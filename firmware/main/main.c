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
#include "soc/soc_caps.h"

#include "dot11.h"

// 5GHz only on dual-band chips (ESP32-C5)
static const uint8_t CHANNELS[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
#if SOC_WIFI_SUPPORT_5G
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
#endif
};
#define NUM_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))

// beacon interval is ~102 ms: idle channels get one, active ones two
#define HOP_DWELL_MS 250
#define HOP_DWELL_IDLE_MS 110
#define HOP_FULL_EVERY 4
#define STAT_PERIOD_MS 5000

static const char *TAG = "sniffer";

// enough to reach the HT Operation IE on 5GHz beacons
#define SNIFF_COPY_LEN 256

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
    // strip the 4-byte FCS
    uint16_t len = pkt->rx_ctrl.sig_len;
    len = (len > 4) ? len - 4 : 0;
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
    uint32_t pass = 0;
    uint8_t parked_on = 0;
    static bool active[NUM_CHANNELS]; // frames seen on the last visit

    while (1) {
        if (s_mode == MODE_HOP) {
            tune(CHANNELS[idx]);
            parked_on = 0;
            bool full = active[idx] || (pass % HOP_FULL_EVERY) == 0;
            uint32_t before = s_rx_frames;
            vTaskDelay(pdMS_TO_TICKS(full ? HOP_DWELL_MS : HOP_DWELL_IDLE_MS));
            active[idx] = s_rx_frames != before;
            idx++;
            if (idx == NUM_CHANNELS) {
                idx = 0;
                pass++;
            }
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

// at most one data line per (bssid, client) every CLI_DEDUP_MS, carrying the frame count
#define CLI_DEDUP_MS 1000
#define CLI_CACHE_SIZE 128

typedef struct {
    uint8_t key[12]; // bssid, client
    TickType_t last_print;
    uint32_t pending; // frames suppressed since last_print
} cli_entry_t;

static cli_entry_t s_cli_cache[CLI_CACHE_SIZE];

// 0 = suppress, otherwise the frame count to print
static uint32_t cli_should_print(const dot11_event_t *ev) {
    uint8_t key[12];
    memcpy(key, ev->bssid, 6);
    memcpy(key + 6, ev->client, 6);
    uint32_t h = 2166136261u; // FNV-1a
    for (int i = 0; i < 12; i++) {
        h = (h ^ key[i]) * 16777619u;
    }
    cli_entry_t *e = &s_cli_cache[h % CLI_CACHE_SIZE];
    TickType_t now = xTaskGetTickCount();
    bool is_data = strcmp(ev->detail, "data") == 0;

    if (memcmp(e->key, key, 12) == 0 && is_data &&
        (now - e->last_print) < pdMS_TO_TICKS(CLI_DEDUP_MS)) {
        e->pending++;
        return 0;
    }
    uint32_t count = (memcmp(e->key, key, 12) == 0) ? e->pending + 1 : 1;
    memcpy(e->key, key, 12);
    e->last_print = now;
    e->pending = 0;
    return count;
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
            // an advertised channel in the other band is bogus
            if ((ev.ap_channel > 14) != (frame.channel > 14)) {
                ev.ap_channel = 0;
            }
            printf("AP\t%s\t%s\t%d\t%d\t%d\n", bssid_str, ev.ssid, frame.channel, frame.rssi, ev.ap_channel);
        } else if (ev.kind == DOT11_FRAME_CLIENT) {
            uint32_t count = cli_should_print(&ev);
            if (count == 0) {
                continue;
            }
            mac_to_str(ev.client, client_str);
            printf("CLI\t%s\t%s\t%d\t%d\t%s\t%lu\n", bssid_str, client_str, frame.channel, frame.rssi,
                   ev.detail, (unsigned long)count);
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
#if SOC_WIFI_SUPPORT_5G
    ESP_ERROR_CHECK(esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO));
#endif
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
    ESP_LOGI(TAG, "hopping %d channels, dwell %d/%d ms", (int)NUM_CHANNELS, HOP_DWELL_MS, HOP_DWELL_IDLE_MS);
}
