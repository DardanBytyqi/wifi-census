package main

import (
	"flag"
	"log"
	"net/http"
	"runtime"
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
	flag.Parse()

	nodes := []NodeConfig{
		{Name: "esp32", Port: *port, Baud: *baud},
	}

	store := NewStore()
	ctrl := NewController()
	for _, n := range nodes {
		go runNode(n, store, ctrl)
	}

	log.Printf("dashboard on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, newServer(store, ctrl)))
}
