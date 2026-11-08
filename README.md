# wifi-census

Passive wifi sniffer. Shows nearby access points and which client MACs
are connected to each one (including randomized MACs).

## Setup

ESP32 has one radio, so it hops channels (1, 6, 11 by default, 300ms
each) and tags every frame it captures with the channel it was on. It
sends that over USB-serial to a Go backend, which keeps track of
everything and shows it on a web dashboard.

ESP32, over USB, to a Go backend, to the dashboard.

Raw packet capture has to be C/ESP-IDF, no Go toolchain does that on a
microcontroller. Everything after capture (storage, dashboard) is Go.

## Run it

Firmware:

```
idf.py set-target esp32 && idf.py build flash monitor
```

You should see `AP` and `CLI` lines scrolling. Ctrl+] to quit the
monitor before starting the backend (only one thing can own the serial
port).

Backend:

```
cd backend
go run .
```

Set your serial port first in `nodes` inside `backend/main.go`. Then
open `http://localhost:8080`. There's a toggle top-right for
hopping / fixed channel.

## Known limits

- classic ESP32 only sees 2.4GHz. 5GHz devices just never show up, no
  matter the channel settings - that's the chip, not the firmware
- only handles normal data frames, not WDS
- everything is in memory, restart wipes it
- no vendor/OUI lookup

## Note

Only point this at your own stuff. Beacons are public broadcast so
that's fine, but client MAC associations are metadata about other
people's devices.
