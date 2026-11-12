package main

import (
	"bufio"
	"log"
	"strconv"
	"strings"
	"time"

	"go.bug.st/serial"
)

// NodeConfig describes one sniffer board on a serial port.
type NodeConfig struct {
	Name string
	Port string
	Baud int
}

// runNode keeps a node connected, reopening the port after a reset or unplug.
func runNode(cfg NodeConfig, store *Store, ctrl *Controller) {
	for {
		readNode(cfg, store, ctrl)
		time.Sleep(2 * time.Second)
	}
}

func readNode(cfg NodeConfig, store *Store, ctrl *Controller) {
	// DTR/RTS low: on the auto-reset circuit they drive EN and GPIO0
	mode := &serial.Mode{
		BaudRate:          cfg.Baud,
		InitialStatusBits: &serial.ModemOutputBits{DTR: false, RTS: false},
	}
	port, err := serial.Open(cfg.Port, mode)
	if err != nil {
		log.Printf("node %s: open %s: %v", cfg.Name, cfg.Port, err)
		return
	}
	defer port.Close()
	log.Printf("node %s: connected on %s @ %d", cfg.Name, cfg.Port, cfg.Baud)

	ctrl.register(cfg.Name, port)
	defer ctrl.unregister(cfg.Name)
	defer store.SetNodeOnline(cfg.Name, false)

	// reset the board to a known state
	port.Write([]byte("INFO\nHOP\n"))

	scanner := bufio.NewScanner(port)
	for scanner.Scan() {
		handleLine(cfg.Name, scanner.Text(), store)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("node %s: read %s: %v", cfg.Name, cfg.Port, err)
	}
}

func handleLine(node, line string, store *Store) {
	f := strings.Split(strings.TrimRight(line, "\r"), "\t")
	switch f[0] {
	case "HELLO":
		if len(f) != 3 {
			return
		}
		var chans []int
		for _, s := range strings.Split(f[2], ",") {
			if ch, err := strconv.Atoi(s); err == nil {
				chans = append(chans, ch)
			}
		}
		log.Printf("node %s: chip %s, %d channels %v", node, f[1], len(chans), chans)
		store.SetNodeInfo(node, f[1], chans)
	case "STAT":
		if len(f) != 4 {
			return
		}
		rx, _ := strconv.ParseUint(f[1], 10, 32)
		drop, _ := strconv.ParseUint(f[2], 10, 32)
		lines, _ := strconv.ParseUint(f[3], 10, 32)
		store.SetNodeStats(node, uint32(rx), uint32(drop), uint32(lines))
	case "MODE", "ERR":
		log.Printf("node %s: %s", node, strings.Join(f, " "))
		if f[0] == "MODE" {
			store.SetNodeMode(node, strings.Join(f[1:], " "))
		}
	default:
		if ev, ok := parseLine(node, line); ok {
			store.Apply(ev)
		}
	}
}

// parseLine decodes AP/CLI lines; the last field of each is optional (older firmware).
func parseLine(node, line string) (Event, bool) {
	f := strings.Split(strings.TrimRight(line, "\r"), "\t")
	switch f[0] {
	case "AP":
		if len(f) != 5 && len(f) != 6 {
			return Event{}, false
		}
		ch, _ := strconv.Atoi(f[3])
		rssi, _ := strconv.Atoi(f[4])
		ev := Event{Node: node, Type: "AP", BSSID: f[1], SSID: f[2], Channel: ch, RSSI: rssi}
		if len(f) == 6 {
			ev.APChannel, _ = strconv.Atoi(f[5])
		}
		return ev, true
	case "CLI":
		if len(f) != 6 && len(f) != 7 {
			return Event{}, false
		}
		ch, _ := strconv.Atoi(f[3])
		rssi, _ := strconv.Atoi(f[4])
		ev := Event{Node: node, Type: "CLI", BSSID: f[1], Client: f[2], Channel: ch, RSSI: rssi, Detail: f[5], Frames: 1}
		if len(f) == 7 {
			if n, err := strconv.Atoi(f[6]); err == nil && n > 0 {
				ev.Frames = n
			}
		}
		return ev, true
	default:
		return Event{}, false
	}
}
