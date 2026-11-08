package main

import (
	"log"
	"net/http"
)

// one entry per ESP32. check your port with ls /dev/tty.usb* (macOS) or
// /dev/ttyUSB* (Linux). more boards later = more entries, each pinned to
// its own channel instead of hopping.
var nodes = []NodeConfig{
	{Name: "esp32", Port: "/dev/tty.usbserial-10", Baud: 115200},
}

func main() {
	store := NewStore()
	ctrl := NewController()
	for _, n := range nodes {
		go readNode(n, store, ctrl)
	}

	addr := ":8080"
	log.Printf("dashboard on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, newServer(store, ctrl)))
}
