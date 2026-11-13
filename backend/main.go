package main

import (
	"flag"
	"log"
	"net/http"
	"runtime"
	"time"
)

func defaultPort() string {
	if runtime.GOOS == "darwin" {
		return "/dev/tty.usbserial-10"
	}
	// CH34x/native-USB boards show up as ttyACM*, CP210x/FTDI as ttyUSB*
	return "/dev/ttyACM0"
}

func main() {
	port := flag.String("port", defaultPort(), "serial port of the ESP32 (ls /dev/ttyACM* /dev/ttyUSB* /dev/tty.usb*)")
	baud := flag.Int("baud", 921600, "serial baud rate, must match CONFIG_ESP_CONSOLE_UART_BAUDRATE")
	// localhost by default: the page exposes device MACs and sniffer control
	addr := flag.String("addr", "127.0.0.1:8080", "dashboard listen address")
	ttl := flag.Duration("ttl", 30*time.Minute, "forget clients/APs not seen for this long (0 = never)")
	ouiPath := flag.String("oui", defaultOUIPath(), "IEEE MA-L registry for vendor lookup (https://standards-oui.ieee.org/oui/oui.csv)")
	flag.Parse()

	nodes := []NodeConfig{
		{Name: "esp32", Port: *port, Baud: *baud},
	}

	oui, err := LoadOUI(*ouiPath)
	if err != nil {
		log.Printf("vendor lookup disabled: %v", err)
	} else {
		log.Printf("vendor lookup: %d OUIs from %s", len(oui), *ouiPath)
	}

	store := NewStore(oui)
	ctrl := NewController()
	for _, n := range nodes {
		go runNode(n, store, ctrl)
	}

	if *ttl > 0 {
		go func() {
			for range time.Tick(time.Minute) {
				if aps, clients := store.Prune(*ttl); aps+clients > 0 {
					log.Printf("pruned %d APs, %d clients not seen for %s", aps, clients, *ttl)
				}
			}
		}()
	}

	log.Printf("dashboard on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, newServer(store, ctrl)))
}
