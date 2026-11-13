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
	MAC        string `json:"mac"`
	Vendor     string `json:"vendor"`
	RSSI       int    `json:"rssi"`
	Randomized bool   `json:"randomized"`
	Frames     int    `json:"frames"`
	// auth/assoc without data = join attempt with no visible traffic
	Kinds     []string  `json:"kinds"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type APInfo struct {
	BSSID   string `json:"bssid"`
	Vendor  string `json:"vendor"`
	SSID    string `json:"ssid"`
	Channel int    `json:"channel"`
	Band    string `json:"band"`
	RSSI    int    `json:"rssi"`
	// false if only seen as the BSSID of client traffic
	Beaconed bool                   `json:"beaconed"`
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
	oui   OUIDB
	now   func() time.Time // injectable for tests
}

func NewStore(oui OUIDB) *Store {
	return &Store{
		aps:   make(map[string]*APInfo),
		nodes: make(map[string]*NodeInfo),
		oui:   oui,
		now:   time.Now,
	}
}

func bandOf(ch int) string {
	switch {
	case ch >= 1 && ch <= 14:
		return "2.4GHz"
	case ch >= 32 && ch <= 177:
		return "5GHz"
	default:
		return ""
	}
}

func (s *Store) Apply(ev Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	ap, ok := s.aps[ev.BSSID]
	if !ok {
		ap = &APInfo{BSSID: ev.BSSID, Vendor: s.oui.Lookup(ev.BSSID), Clients: make(map[string]*ClientInfo)}
		s.aps[ev.BSSID] = ap
	}
	ap.LastSeen = now

	switch ev.Type {
	case "AP":
		// some APs alternate real and blank SSIDs
		if ev.SSID != "" {
			ap.SSID = ev.SSID
		}
		ap.RSSI = ev.RSSI
		ap.Beaconed = true
		// 2.4GHz channels overlap: trust the beacon over the radio channel
		if ev.APChannel > 0 {
			ap.Channel = ev.APChannel
		} else if ap.Channel == 0 {
			ap.Channel = ev.Channel
		}
	case "CLI":

		if !ap.Beaconed && ap.Channel == 0 {
			ap.Channel = ev.Channel
		}
		c, ok := ap.Clients[ev.Client]
		if !ok {
			c = &ClientInfo{
				MAC:        ev.Client,
				Vendor:     s.oui.Lookup(ev.Client),
				Randomized: isRandomizedMAC(ev.Client),
				FirstSeen:  now,
			}
			ap.Clients[ev.Client] = c
		}
		c.RSSI = ev.RSSI
		c.LastSeen = now
		frames := ev.Frames
		if frames < 1 {
			frames = 1
		}
		c.Frames += frames
		if ev.Detail != "" && !contains(c.Kinds, ev.Detail) {
			c.Kinds = append(c.Kinds, ev.Detail)
		}
	}
	ap.Band = bandOf(ap.Channel)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Prune drops clients, then empty APs, not seen within ttl.
func (s *Store) Prune(ttl time.Duration) (aps, clients int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-ttl)
	for bssid, ap := range s.aps {
		for mac, c := range ap.Clients {
			if c.LastSeen.Before(cutoff) {
				delete(ap.Clients, mac)
				clients++
			}
		}
		if len(ap.Clients) == 0 && ap.LastSeen.Before(cutoff) {
			delete(s.aps, bssid)
			aps++
		}
	}
	return aps, clients
}

// Snapshot returns a deep copy sorted by client count.
func (s *Store) Snapshot() []*APInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*APInfo, 0, len(s.aps))
	for _, ap := range s.aps {
		clients := make(map[string]*ClientInfo, len(ap.Clients))
		for mac, c := range ap.Clients {
			cp := *c
			cp.Kinds = append([]string(nil), c.Kinds...)
			clients[mac] = &cp
		}
		apCopy := *ap
		apCopy.Clients = clients
		out = append(out, &apCopy)
	}
	// ties: beaconed first, then RSSI, then BSSID for a stable order
	sort.Slice(out, func(i, j int) bool {
		ci, cj := len(out[i].Clients), len(out[j].Clients)
		if ci != cj {
			return ci > cj
		}
		if out[i].Beaconed != out[j].Beaconed {
			return out[i].Beaconed
		}
		if out[i].RSSI != out[j].RSSI {
			return out[i].RSSI > out[j].RSSI
		}
		return out[i].BSSID < out[j].BSSID
	})
	return out
}

func (s *Store) node(name string) *NodeInfo {
	n, ok := s.nodes[name]
	if !ok {
		n = &NodeInfo{Name: name}
		s.nodes[name] = n
	}
	n.Updated = s.now()
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

// isRandomizedMAC checks the locally-administered bit.
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
