package main

import (
	"bufio"
	"log"
	"strconv"
	"strings"

	"go.bug.st/serial"
)

// one sniffer board plugged in over USB
type NodeConfig struct {
	Name string
	Port string
	Baud int
}

// reads lines from one node forever, feeds the store. run as a goroutine.
func readNode(cfg NodeConfig, store *Store, ctrl *Controller) {
	mode := &serial.Mode{BaudRate: cfg.Baud}
	port, err := serial.Open(cfg.Port, mode)
	if err != nil {
		log.Printf("node %s: open %s: %v", cfg.Name, cfg.Port, err)
		return
	}
	defer port.Close()

	ctrl.register(cfg.Name, port)
	defer ctrl.unregister(cfg.Name)

	scanner := bufio.NewScanner(port)
	for scanner.Scan() {
		ev, ok := parseLine(cfg.Name, scanner.Text())
		if !ok {
			continue
		}
		store.Apply(ev)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("node %s: read %s: %v", cfg.Name, cfg.Port, err)
	}
}

// wire format:
//	AP\t<bssid>\t<ssid>\t<channel>\t<rssi>
//	CLI\t<bssid>\t<client_mac>\t<channel>\t<rssi>\t<detail>
func parseLine(node, line string) (Event, bool) {
	f := strings.Split(line, "\t")
	switch f[0] {
	case "AP":
		if len(f) != 5 {
			return Event{}, false
		}
		ch, _ := strconv.Atoi(f[3])
		rssi, _ := strconv.Atoi(f[4])
		return Event{Node: node, Type: "AP", BSSID: f[1], SSID: f[2], Channel: ch, RSSI: rssi}, true
	case "CLI":
		if len(f) != 6 {
			return Event{}, false
		}
		ch, _ := strconv.Atoi(f[3])
		rssi, _ := strconv.Atoi(f[4])
		return Event{Node: node, Type: "CLI", BSSID: f[1], Client: f[2], Channel: ch, RSSI: rssi, Detail: f[5]}, true
	default:
		return Event{}, false
	}
}
