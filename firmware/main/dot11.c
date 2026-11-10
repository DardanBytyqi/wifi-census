#include "dot11.h"

#include <stdbool.h>
#include <string.h>

#define FC_TYPE(fc) (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc) (((fc) >> 8) & 0x1)
#define FC_FROM_DS(fc) (((fc) >> 9) & 0x1)

#define TYPE_MGMT 0
#define TYPE_DATA 2

#define SUBTYPE_ASSOC_REQ 0
#define SUBTYPE_ASSOC_RESP 1
#define SUBTYPE_REASSOC_REQ 2
#define SUBTYPE_REASSOC_RESP 3
#define SUBTYPE_PROBE_REQ 4
#define SUBTYPE_PROBE_RESP 5
#define SUBTYPE_BEACON 8
#define SUBTYPE_AUTH 11

// timestamp beacon interval capability info
#define FIXED_FIELDS_LEN 12

#define IE_SSID 0
#define IE_DS_PARAMS 3   // 2.4GHz: 1 byte, current channel
#define IE_HT_OPERATION 61 // first byte = primary channel, also present on 5GHz

static int is_multicast(const uint8_t *mac) {
    return mac[0] & 0x01;
}

static void copy_ssid(const uint8_t *src, uint8_t len, char *out, size_t out_cap) {
    if (len >= out_cap) {
        len = out_cap - 1;
    }
    // hidden networks send either length 0 or zero-filled bytes
    bool all_zero = true;
    for (uint8_t i = 0; i < len; i++) {
        if (src[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        out[0] = '\0';
        return;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    // tabs/newlines would break the line protocol
    for (uint8_t i = 0; i < len; i++) {
        if ((uint8_t)out[i] < 0x20 || out[i] == 0x7f) {
            out[i] = '?';
        }
    }
}

static void parse_ies(const uint8_t *body, size_t body_len, dot11_event_t *out) {
    if (body_len <= FIXED_FIELDS_LEN) {
        return;
    }
    const uint8_t *p = body + FIXED_FIELDS_LEN;
    const uint8_t *end = body + body_len;
    uint8_t ht_channel = 0;

    while (end - p >= 2) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        const uint8_t *val = p + 2;
        if (val + len > end) {
            if (tag == IE_SSID && p == body + FIXED_FIELDS_LEN) {
                copy_ssid(val, (uint8_t)(end - val), out->ssid, sizeof(out->ssid));
            }
            break;
        }
        switch (tag) {
        case IE_SSID:
            // the SSID is always the first IE
            if (p == body + FIXED_FIELDS_LEN) {
                copy_ssid(val, len, out->ssid, sizeof(out->ssid));
            }
            break;
        case IE_DS_PARAMS:
            if (len >= 1) {
                out->ap_channel = val[0];
            }
            break;
        case IE_HT_OPERATION:
            if (len >= 1) {
                ht_channel = val[0];
            }
            break;
        }
        p = val + len;
    }
    if (out->ap_channel == 0) {
        out->ap_channel = ht_channel;
    }
}

// auth/assoc go both ways: addr3 is the BSSID, the client is the other address
static int client_from_mgmt(const dot11_hdr_t *hdr, dot11_event_t *out, const char *detail) {
    const uint8_t *bssid = hdr->addr3;
    const uint8_t *client;
    if (memcmp(hdr->addr2, bssid, 6) == 0) {
        client = hdr->addr1; // AP -> client
    } else {
        client = hdr->addr2; // client -> AP
    }
    if (is_multicast(client) || is_multicast(bssid)) {
        return -1;
    }
    out->kind = DOT11_FRAME_CLIENT;
    memcpy(out->bssid, bssid, 6);
    memcpy(out->client, client, 6);
    out->detail = detail;
    return 0;
}

int dot11_parse(const uint8_t *frame, size_t len, dot11_event_t *out) {
    if (len < sizeof(dot11_hdr_t)) {
        return -1;
    }
    const dot11_hdr_t *hdr = (const dot11_hdr_t *)frame;
    uint16_t fc = hdr->frame_control;
    uint8_t type = FC_TYPE(fc);
    uint8_t subtype = FC_SUBTYPE(fc);

    memset(out, 0, sizeof(*out));

    if (type == TYPE_MGMT) {
        const uint8_t *body = frame + sizeof(dot11_hdr_t);
        size_t body_len = len - sizeof(dot11_hdr_t);

        switch (subtype) {
        case SUBTYPE_BEACON:
        case SUBTYPE_PROBE_RESP:
            if (is_multicast(hdr->addr3)) {
                return -1;
            }
            out->kind = DOT11_FRAME_AP;
            memcpy(out->bssid, hdr->addr3, 6);
            parse_ies(body, body_len, out);
            out->detail = (subtype == SUBTYPE_BEACON) ? "beacon" : "probe_resp";
            return 0;

        case SUBTYPE_ASSOC_REQ:
        case SUBTYPE_REASSOC_REQ:
        case SUBTYPE_ASSOC_RESP:
        case SUBTYPE_REASSOC_RESP:
            return client_from_mgmt(hdr, out, "assoc");

        case SUBTYPE_AUTH:
            return client_from_mgmt(hdr, out, "auth");

        default:
            return -1;
        }
    }

    if (type == TYPE_DATA) {
        uint8_t to_ds = FC_TO_DS(fc);
        uint8_t from_ds = FC_FROM_DS(fc);

        if (to_ds && !from_ds) {
            // station to AP: addr1 = BSSID, addr2 = station
            if (is_multicast(hdr->addr2)) {
                return -1;
            }
            out->kind = DOT11_FRAME_CLIENT;
            memcpy(out->bssid, hdr->addr1, 6);
            memcpy(out->client, hdr->addr2, 6);
            out->detail = "data";
            return 0;
        }
        if (!to_ds && from_ds) {
            // AP to station: addr1 = station, addr2 = BSSID
            if (is_multicast(hdr->addr1)) {
                return -1;
            }
            out->kind = DOT11_FRAME_CLIENT;
            memcpy(out->bssid, hdr->addr2, 6);
            memcpy(out->client, hdr->addr1, 6);
            out->detail = "data";
            return 0;
        }
        // IBSS or 4-address WDS
        return -1;
    }

    return -1;
}
