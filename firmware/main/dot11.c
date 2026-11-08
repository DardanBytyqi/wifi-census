#include "dot11.h"

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

// timestamp(8) + beacon interval(2) + capability info(2), before the IEs
#define FIXED_FIELDS_LEN 12

// I/G bit of the first octet: set = multicast/broadcast, not a real client
static int is_multicast(const uint8_t *mac) {
    return mac[0] & 0x01;
}

static void extract_ssid(const uint8_t *body, size_t body_len, char *out, size_t out_cap) {
    out[0] = '\0';
    if (body_len <= FIXED_FIELDS_LEN) {
        return;
    }
    const uint8_t *ie = body + FIXED_FIELDS_LEN;
    size_t ie_len = body_len - FIXED_FIELDS_LEN;
    if (ie_len < 2 || ie[0] != 0x00) { // tag 0 = SSID
        return;
    }
    uint8_t ssid_len = ie[1];
    if (ssid_len > ie_len - 2) {
        ssid_len = ie_len - 2;
    }
    if (ssid_len >= out_cap) {
        ssid_len = out_cap - 1;
    }
    memcpy(out, ie + 2, ssid_len);
    out[ssid_len] = '\0';
    // hidden networks send junk/empty SSIDs, strip non-printable chars
    for (uint8_t i = 0; i < ssid_len; i++) {
        if (out[i] < 0x20 || out[i] > 0x7e) {
            out[i] = '?';
        }
    }
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
            out->kind = DOT11_FRAME_AP;
            memcpy(out->bssid, hdr->addr2, 6);
            extract_ssid(body, body_len, out->ssid, sizeof(out->ssid));
            out->detail = (subtype == SUBTYPE_BEACON) ? "beacon" : "probe_resp";
            return 0;

        case SUBTYPE_ASSOC_REQ:
        case SUBTYPE_REASSOC_REQ:
        case SUBTYPE_AUTH:
            // client to AP: addr1 = AP (BSSID), addr2 = client
            if (is_multicast(hdr->addr2)) {
                return -1;
            }
            out->kind = DOT11_FRAME_CLIENT;
            memcpy(out->bssid, hdr->addr1, 6);
            memcpy(out->client, hdr->addr2, 6);
            out->detail = "assoc";
            return 0;

        case SUBTYPE_ASSOC_RESP:
        case SUBTYPE_REASSOC_RESP:
            // AP to client: addr1 = client, addr2 = AP (BSSID)
            if (is_multicast(hdr->addr1)) {
                return -1;
            }
            out->kind = DOT11_FRAME_CLIENT;
            memcpy(out->bssid, hdr->addr2, 6);
            memcpy(out->client, hdr->addr1, 6);
            out->detail = "assoc";
            return 0;

        default:
            return -1;
        }
    }

    if (type == TYPE_DATA) {
        uint8_t to_ds = FC_TO_DS(fc);
        uint8_t from_ds = FC_FROM_DS(fc);

        if (to_ds && !from_ds) {
            // station to AP
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
            // AP to station, skip broadcast/multicast payloads (ARP, mDNS...)
            if (is_multicast(hdr->addr1)) {
                return -1;
            }
            out->kind = DOT11_FRAME_CLIENT;
            memcpy(out->bssid, hdr->addr2, 6);
            memcpy(out->client, hdr->addr1, 6);
            out->detail = "data";
            return 0;
        }
        // ad-hoc or 4-address WDS, not handled
        return -1;
    }

    return -1;
}
