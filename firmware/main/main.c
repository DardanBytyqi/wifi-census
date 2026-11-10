// Passive 802.11 sniffer

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "dot11.h"

static const uint8_t CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
#define NUM_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))

#define HOP_DWELL_MS 300
#define STAT_PERIOD_MS 5000

static const char *TAG = "sniffer";

// header + SSID IE
#define SNIFF_COPY_LEN 80

typedef struct {
    uint16_t len;
    int8_t rssi;
    uint8_t channel;
    uint8_t data[SNIFF_COPY_LEN];
} raw_frame_t;

static QueueHandle_t s_queue;

typedef enum {
    MODE_HOP,
    MODE_FIXED,
} sniff_mode_t;

// single writer per variable, volatile is enough
static volatile uint8_t s_current_channel;
static volatile sniff_mode_t s_mode = MODE_HOP;
static volatile uint8_t s_fixed_channel = 1;

static volatile uint32_t s_rx_frames;
static volatile uint32_t s_dropped;
static volatile uint32_t s_lines;

// runs in the Wi-Fi driver task: copy and queue only
static void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
        return;
    }
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len > SNIFF_COPY_LEN) {
        len = SNIFF_COPY_LEN;
    }

    raw_frame_t frame;
    frame.len = len;
    frame.rssi = pkt->rx_ctrl.rssi;
    frame.channel = s_current_channel;
    memcpy(frame.data, pkt->payload, len);

    s_rx_frames++;
    if (xQueueSend(s_queue, &frame, 0) != pdTRUE) {
        s_dropped++;
    }
}

static bool channel_supported(int ch) {
    for (size_t i = 0; i < NUM_CHANNELS; i++) {
        if (CHANNELS[i] == ch) {
            return true;
        }
    }
    return false;
}

// one printf so it can't interleave with parser_task output
static void print_hello(void) {
    char buf[32 + NUM_CHANNELS * 4];
    int n = snprintf(buf, sizeof(buf), "HELLO\t%s\t", CONFIG_IDF_TARGET);
    for (size_t i = 0; i < NUM_CHANNELS && n < (int)sizeof(buf); i++) {
        n += snprintf(buf + n, sizeof(buf) - n, i ? ",%d" : "%d", CHANNELS[i]);
    }
    printf("%s\n", buf);
}

static void tune(uint8_t ch) {
    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set_channel %d: %s", ch, esp_err_to_name(err));
        return;
    }
    s_current_channel = ch;
}

static void channel_task(void *arg) {
    size_t idx = 0;
    uint8_t parked_on = 0;

    while (1) {
        if (s_mode == MODE_HOP) {
            tune(CHANNELS[idx]);
            idx = (idx + 1) % NUM_CHANNELS;
            parked_on = 0;
            vTaskDelay(pdMS_TO_TICKS(HOP_DWELL_MS));
        } else {
            uint8_t target = s_fixed_channel;
            if (target != parked_on) {
                tune(target);
                parked_on = target;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

static void handle_command(const char *line) {
    int ch;
    if (strcmp(line, "HOP") == 0) {
        s_mode = MODE_HOP;
        printf("MODE\tHOP\n");
    } else if (strcmp(line, "INFO") == 0) {
        print_hello();
    } else if (sscanf(line, "CH %d", &ch) == 1) {
        if (!channel_supported(ch)) {
            printf("ERR\tchannel %d not supported on %s\n", ch, CONFIG_IDF_TARGET);
            return;
        }
        s_fixed_channel = (uint8_t)ch;
        s_mode = MODE_FIXED;
        printf("MODE\tFIXED\t%d\n", ch);
    } else if (line[0] != '\0') {
        printf("ERR\tunknown command\n");
    }
}

static void command_task(void *arg) {
    char line[32];
    size_t n = 0;
    uint8_t c;
    while (1) {
        if (uart_read_bytes(CONFIG_ESP_CONSOLE_UART_NUM, &c, 1, portMAX_DELAY) != 1) {
            continue;
        }
        if (c == '\n' || c == '\r') {
            line[n] = '\0';
            handle_command(line);
            n = 0;
        } else if (n < sizeof(line) - 1) {
            line[n++] = (char)c;
        }
    }
}

static void stat_task(void *arg) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(STAT_PERIOD_MS));
        printf("STAT\t%lu\t%lu\t%lu\n",
               (unsigned long)s_rx_frames, (unsigned long)s_dropped, (unsigned long)s_lines);
    }
}

static void mac_to_str(const uint8_t *mac, char *out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void parser_task(void *arg) {
    raw_frame_t frame;
    dot11_event_t ev;
    char bssid_str[18];
    char client_str[18];

    while (1) {
        if (xQueueReceive(s_queue, &frame, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (dot11_parse(frame.data, frame.len, &ev) != 0) {
            continue;
        }

        mac_to_str(ev.bssid, bssid_str);

        if (ev.kind == DOT11_FRAME_AP) {
            printf("AP\t%s\t%s\t%d\t%d\n", bssid_str, ev.ssid, frame.channel, frame.rssi);
        } else if (ev.kind == DOT11_FRAME_CLIENT) {
            mac_to_str(ev.client, client_str);
            printf("CLI\t%s\t%s\t%d\t%d\t%s\n", bssid_str, client_str, frame.channel, frame.rssi, ev.detail);
        }
        s_lines++;
    }
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM, 256, 4096, 0, NULL, 0));
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
    setvbuf(stdout, NULL, _IOLBF, 0);

    s_queue = xQueueCreate(64, sizeof(raw_frame_t));
    xTaskCreate(parser_task, "dot11_parser", 4096, NULL, 5, NULL);

    s_current_channel = CHANNELS[0];

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(s_current_channel, WIFI_SECOND_CHAN_NONE));

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    xTaskCreate(channel_task, "channel_task", 3072, NULL, 5, NULL);
    xTaskCreate(command_task, "command_task", 3072, NULL, 5, NULL);
    xTaskCreate(stat_task, "stat_task", 4096, NULL, 1, NULL);

    print_hello();
    ESP_LOGI(TAG, "hopping %d channels, dwell %d ms", (int)NUM_CHANNELS, HOP_DWELL_MS);
}
