package main

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Event is one AP or CLI line from a node.
type Event struct {
	Node      string
	Type      string // "AP" or "CLI"
	BSSID     string
	SSID      string
	Client    string
	Channel   int // channel the radio was tuned to
	APChannel int // AP only: channel advertised in the beacon, 0 = unknown
	RSSI      int
	Detail    string // CLI only: "auth", "assoc" or "data"
	Frames    int    // CLI only: frames folded into this line
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

type NodeInfo struct {
	Name     string    `json:"name"`
	Online   bool      `json:"online"`
	Chip     string    `json:"chip"`
	Channels []int     `json:"channels"`
	Mode     string    `json:"mode"`
	RxFrames uint32    `json:"rx_frames"`
	Dropped  uint32    `json:"dropped"`
	Lines    uint32    `json:"lines"`
	Updated  time.Time `json:"updated"`
}

// Store holds the current state. Written by serial readers, read by HTTP.
type Store struct {
	mu    sync.RWMutex
	aps   map[string]*APInfo
	nodes map[string]*NodeInfo
}

func NewStore() *Store {
	return &Store{aps: make(map[string]*APInfo), nodes: make(map[string]*NodeInfo)}
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

func (s *Store) node(name string) *NodeInfo {
	n, ok := s.nodes[name]
	if !ok {
		n = &NodeInfo{Name: name}
		s.nodes[name] = n
	}
	n.Updated = time.Now()
	return n
}

func (s *Store) SetNodeInfo(name, chip string, channels []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.node(name)
	n.Online = true
	n.Chip = chip
	n.Channels = channels
	if n.Mode == "" {
		n.Mode = "HOP"
	}
}

func (s *Store) SetNodeStats(name string, rx, dropped, lines uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.node(name)
	n.Online = true
	n.RxFrames, n.Dropped, n.Lines = rx, dropped, lines
}

func (s *Store) SetNodeMode(name, mode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.node(name).Mode = mode
}

func (s *Store) SetNodeOnline(name string, online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.node(name).Online = online
}

func (s *Store) Nodes() []NodeInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NodeInfo, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		cp.Channels = append([]int(nil), n.Channels...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ChannelSupported reports whether an online node can tune to ch.
func (s *Store) ChannelSupported(ch int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, n := range s.nodes {
		if !n.Online {
			continue
		}
		for _, c := range n.Channels {
			if c == ch {
				return true
			}
		}
	}
	return false
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
