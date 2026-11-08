// single ESP32, one radio, hops channels and tags every frame with whatever
// channel it was on, dumps it as a tab-separated line over USB-serial.
//
// serial commands (from the backend, same line):
//   HOP\n      resume hopping
//   CH <n>\n   stick to channel n (1-13)

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t CHANNELS[] = {1, 6, 11};
#define NUM_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))
#define HOP_DWELL_MS 300

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "dot11.h"

static const char *TAG = "sniffer";

// header + full SSID IE, don't need the rest of the payload
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

// written by command_task, read by channel_task + the rx callback.
// volatile is enough here, no lock needed - worst case a frame gets
// tagged with the channel right before/after a switch, harmless.
static volatile uint8_t s_current_channel;
static volatile sniff_mode_t s_mode = MODE_HOP;
static volatile uint8_t s_fixed_channel = 1;

// runs in the wifi driver's task - no parsing, no printf, just queue it
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

    // full queue = parser's behind, drop instead of blocking the driver
    xQueueSend(s_queue, &frame, 0);
}

// cycles CHANNELS when hopping, or just parks on s_fixed_channel
static void channel_task(void *arg) {
    size_t idx = 0;
    uint8_t parked_on = 0;

    while (1) {
        if (s_mode == MODE_HOP) {
            s_current_channel = CHANNELS[idx];
            esp_wifi_set_channel(s_current_channel, WIFI_SECOND_CHAN_NONE);
            idx = (idx + 1) % NUM_CHANNELS;
            parked_on = 0;
            vTaskDelay(pdMS_TO_TICKS(HOP_DWELL_MS));
        } else {
            uint8_t target = s_fixed_channel;
            if (target != parked_on) {
                esp_wifi_set_channel(target, WIFI_SECOND_CHAN_NONE);
                s_current_channel = target;
                parked_on = target;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

// reads one command per line from stdin, ignores anything it doesn't recognize
static void command_task(void *arg) {
    char line[32];
    while (1) {
        if (fgets(line, sizeof(line), stdin) == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }

        int ch;
        if (strcmp(line, "HOP") == 0) {
            s_mode = MODE_HOP;
            printf("MODE\tHOP\n");
        } else if (sscanf(line, "CH %d", &ch) == 1 && ch >= 1 && ch <= 13) {
            s_fixed_channel = (uint8_t)ch;
            s_mode = MODE_FIXED;
            printf("MODE\tFIXED\t%d\n", ch);
        }
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
    }
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_queue = xQueueCreate(64, sizeof(raw_frame_t));
    xTaskCreate(parser_task, "dot11_parser", 4096, NULL, 5, NULL);

    s_current_channel = CHANNELS[0];

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(s_current_channel, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb));

    xTaskCreate(channel_task, "channel_task", 2048, NULL, 5, NULL);
    xTaskCreate(command_task, "command_task", 4096, NULL, 5, NULL);

    ESP_LOGI(TAG, "hopping channels, dwell %d ms", HOP_DWELL_MS);
}
