#pragma once

#include <stddef.h>
#include <stdint.h>

// 802.11 MAC header, mgmt and data frames
typedef struct __attribute__((packed)) {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} dot11_hdr_t;

typedef enum {
    DOT11_FRAME_NONE,
    DOT11_FRAME_AP,     // beacon / probe response
    DOT11_FRAME_CLIENT, // client MAC tied to a BSSID
} dot11_frame_kind_t;

typedef struct {
    dot11_frame_kind_t kind;
    uint8_t bssid[6];
    uint8_t client[6];  // set only for DOT11_FRAME_CLIENT
    char ssid[33];      // set only for DOT11_FRAME_AP, empty if hidden
    uint8_t ap_channel; // DOT11_FRAME_AP only: advertised channel, 0 = unknown
    const char *detail; // "beacon", "assoc", "auth", "data", ...
} dot11_event_t;

// 0 = AP or client event in *out, non-zero = ignored
int dot11_parse(const uint8_t *frame, size_t len, dot11_event_t *out);
