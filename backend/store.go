package main

import (
	"fmt"
	"sync"
	"time"
)

// one parsed line from the serial feed
type Event struct {
	Node    string
	Type    string // "AP" or "CLI"
	BSSID   string
	SSID    string
	Client  string
	Channel int
	RSSI    int
	Detail  string
}

type ClientInfo struct {
	MAC        string    `json:"mac"`
	RSSI       int       `json:"rssi"`
	Source     string    `json:"source"`
	Randomized bool      `json:"randomized"`
	LastSeen   time.Time `json:"last_seen"`
}

type APInfo struct {
	BSSID    string                 `json:"bssid"`
	SSID     string                 `json:"ssid"`
	Channel  int                    `json:"channel"`
	RSSI     int                    `json:"rssi"`
	LastSeen time.Time              `json:"last_seen"`
	Clients  map[string]*ClientInfo `json:"clients"`
}

// current AP/clients picture, written from multiple goroutines
type Store struct {
	mu  sync.RWMutex
	aps map[string]*APInfo
}

func NewStore() *Store {
	return &Store{aps: make(map[string]*APInfo)}
}

func (s *Store) Apply(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ap, ok := s.aps[ev.BSSID]
	if !ok {
		ap = &APInfo{BSSID: ev.BSSID, Clients: make(map[string]*ClientInfo)}
		s.aps[ev.BSSID] = ap
	}
	ap.Channel = ev.Channel
	ap.LastSeen = time.Now()

	switch ev.Type {
	case "AP":
		ap.SSID = ev.SSID
		ap.RSSI = ev.RSSI
	case "CLI":
		c, ok := ap.Clients[ev.Client]
		if !ok {
			c = &ClientInfo{MAC: ev.Client, Randomized: isRandomizedMAC(ev.Client)}
			ap.Clients[ev.Client] = c
		}
		c.RSSI = ev.RSSI
		c.Source = ev.Detail
		c.LastSeen = time.Now()
	}
}

// copy for JSON encoding, doesn't hold the lock while marshaling
func (s *Store) Snapshot() []*APInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*APInfo, 0, len(s.aps))
	for _, ap := range s.aps {
		clients := make(map[string]*ClientInfo, len(ap.Clients))
		for mac, c := range ap.Clients {
			cp := *c
			clients[mac] = &cp
		}
		apCopy := *ap
		apCopy.Clients = clients
		out = append(out, &apCopy)
	}
	return out
}

// locally-administered bit set = randomized MAC, not the burned-in one
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b int
	if _, err := fmt.Sscanf(mac[:2], "%02x", &b); err != nil {
		return false
	}
	return b&0x02 != 0
}
