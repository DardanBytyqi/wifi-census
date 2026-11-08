#pragma once

#include <stddef.h>
#include <stdint.h>

// 802.11 MAC header, mgmt + data frames
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
    uint8_t client[6]; // set only for DOT11_FRAME_CLIENT
    char ssid[33];     // set only for DOT11_FRAME_AP, empty if hidden
    const char *detail; // "beacon", "assoc", "data", ...
} dot11_event_t;

// returns 0 and fills *out on AP/client event, non-zero if not interesting
int dot11_parse(const uint8_t *frame, size_t len, dot11_event_t *out);
