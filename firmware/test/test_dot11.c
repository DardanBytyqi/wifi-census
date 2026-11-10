// host-side parser tests, see README.md to run
#include "dot11.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t AP[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
static const uint8_t CL[6] = {0xda, 0x01, 0x02, 0x03, 0x04, 0x05};
static const uint8_t BC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// 24-byte header, returns its length
static size_t hdr(uint8_t *f, uint8_t fc0, uint8_t fc1, const uint8_t *a1, const uint8_t *a2, const uint8_t *a3) {
    memset(f, 0, 24);
    f[0] = fc0;
    f[1] = fc1;
    memcpy(f + 4, a1, 6);
    memcpy(f + 10, a2, 6);
    memcpy(f + 16, a3, 6);
    return 24;
}

// beacon header and fixed fields, IEs go after
static size_t beacon(uint8_t *f) {
    size_t n = hdr(f, 0x80, 0, BC, AP, AP);
    memset(f + n, 0, 12);
    return n + 12;
}

static size_t ie(uint8_t *f, size_t n, uint8_t tag, const void *val, uint8_t len) {
    f[n] = tag;
    f[n + 1] = len;
    memcpy(f + n + 2, val, len);
    return n + 2 + len;
}

int main(void) {
    uint8_t f[256];
    dot11_event_t e;
    size_t n;

    // 2.4GHz beacon: SSID, rates, DS params says channel 3
    n = beacon(f);
    n = ie(f, n, 0, "home", 4);
    n = ie(f, n, 1, "\x82\x84", 2);
    n = ie(f, n, 3, "\x03", 1);
    assert(dot11_parse(f, n, &e) == 0 && e.kind == DOT11_FRAME_AP);
    assert(strcmp(e.ssid, "home") == 0 && e.ap_channel == 3 && memcmp(e.bssid, AP, 6) == 0);

    // same frame cut before the DS IE: SSID kept, channel unknown
    assert(dot11_parse(f, n - 3, &e) == 0 && e.ap_channel == 0 && strcmp(e.ssid, "home") == 0);

    // 5GHz beacon: no DS IE, channel from HT Operation
    n = beacon(f);
    n = ie(f, n, 0, "", 0);
    n = ie(f, n, 61, "\x24\x00", 2);
    assert(dot11_parse(f, n, &e) == 0 && e.ap_channel == 36 && e.ssid[0] == '\0');

    // hidden SSID sent as zero bytes -> empty
    n = beacon(f);
    n = ie(f, n, 0, "\0\0\0\0", 4);
    assert(dot11_parse(f, n, &e) == 0 && e.ssid[0] == '\0');

    // control chars replaced, UTF-8 kept
    n = beacon(f);
    n = ie(f, n, 0, "a\tb", 3);
    assert(dot11_parse(f, n, &e) == 0 && strcmp(e.ssid, "a?b") == 0);
    n = beacon(f);
    n = ie(f, n, 0, "caf\xc3\xa9", 5);
    assert(dot11_parse(f, n, &e) == 0 && strcmp(e.ssid, "caf\xc3\xa9") == 0);

    // a later tag-0 IE must not overwrite the SSID
    n = beacon(f);
    n = ie(f, n, 0, "ok", 2);
    n = ie(f, n, 0, "\x01\x02", 2);
    assert(dot11_parse(f, n, &e) == 0 && strcmp(e.ssid, "ok") == 0);

    // auth in both directions: bssid = AP, client = CL
    n = hdr(f, 0xb0, 0, AP, CL, AP) + 6;
    assert(dot11_parse(f, n, &e) == 0 && e.kind == DOT11_FRAME_CLIENT && strcmp(e.detail, "auth") == 0);
    assert(memcmp(e.bssid, AP, 6) == 0 && memcmp(e.client, CL, 6) == 0);
    n = hdr(f, 0xb0, 0, CL, AP, AP) + 6;
    assert(dot11_parse(f, n, &e) == 0 && memcmp(e.bssid, AP, 6) == 0 && memcmp(e.client, CL, 6) == 0);

    // assoc request
    n = hdr(f, 0x00, 0, AP, CL, AP) + 4;
    assert(dot11_parse(f, n, &e) == 0 && strcmp(e.detail, "assoc") == 0 && memcmp(e.client, CL, 6) == 0);

    // data to-DS and from-DS
    n = hdr(f, 0x88, 0x01, AP, CL, BC);
    assert(dot11_parse(f, n, &e) == 0 && memcmp(e.bssid, AP, 6) == 0 && memcmp(e.client, CL, 6) == 0);
    n = hdr(f, 0x08, 0x02, CL, AP, AP);
    assert(dot11_parse(f, n, &e) == 0 && memcmp(e.bssid, AP, 6) == 0 && memcmp(e.client, CL, 6) == 0);

    // ignored: broadcast from AP, WDS (4-address), too short
    n = hdr(f, 0x08, 0x02, BC, AP, AP);
    assert(dot11_parse(f, n, &e) != 0);
    n = hdr(f, 0x08, 0x03, CL, AP, AP);
    assert(dot11_parse(f, n, &e) != 0);
    assert(dot11_parse(f, 10, &e) != 0);

    puts("dot11 tests OK");
    return 0;
}
