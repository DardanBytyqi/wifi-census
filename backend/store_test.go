package main

import (
	"reflect"
	"testing"
	"time"
)

// store with a controllable clock
func testStore() (*Store, *time.Time) {
	s := NewStore()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestParseLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want Event
	}{
		{"AP\taa:bb:cc:dd:ee:ff\thome\t6\t-50\t3", true,
			Event{Node: "n", Type: "AP", BSSID: "aa:bb:cc:dd:ee:ff", SSID: "home", Channel: 6, RSSI: -50, APChannel: 3}},
		{"AP\taa:bb:cc:dd:ee:ff\thome\t6\t-50", true, // old firmware, no ap_ch
			Event{Node: "n", Type: "AP", BSSID: "aa:bb:cc:dd:ee:ff", SSID: "home", Channel: 6, RSSI: -50}},
		{"CLI\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\t36\t-60\tdata\t42", true,
			Event{Node: "n", Type: "CLI", BSSID: "aa:bb:cc:dd:ee:ff", Client: "11:22:33:44:55:66", Channel: 36, RSSI: -60, Detail: "data", Frames: 42}},
		{"CLI\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\t36\t-60\tauth\r", true, // old firmware, no count
			Event{Node: "n", Type: "CLI", BSSID: "aa:bb:cc:dd:ee:ff", Client: "11:22:33:44:55:66", Channel: 36, RSSI: -60, Detail: "auth", Frames: 1}},
		{"CLI\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\t36", false, Event{}},
		{"I (123) wifi: boot log", false, Event{}},
		{"", false, Event{}},
	}
	for _, c := range cases {
		got, ok := parseLine("n", c.line)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseLine(%q) = %+v, %v; want %+v, %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

func TestAPChannelAndSSID(t *testing.T) {
	s, _ := testStore()
	// heard on ch 1 but the beacon says 3: trust the beacon
	s.Apply(Event{Type: "AP", BSSID: "b1", SSID: "home", Channel: 1, APChannel: 3, RSSI: -50})
	// client traffic must not move the AP's channel
	s.Apply(Event{Type: "CLI", BSSID: "b1", Client: "c1", Channel: 5, Detail: "data"})
	// a blank SSID (hotspots do this) must not erase the known one
	s.Apply(Event{Type: "AP", BSSID: "b1", SSID: "", Channel: 1, APChannel: 3, RSSI: -55})

	ap := s.Snapshot()[0]
	if ap.Channel != 3 || ap.Band != "2.4GHz" || ap.SSID != "home" || ap.RSSI != -55 {
		t.Errorf("got ch=%d band=%s ssid=%q rssi=%d", ap.Channel, ap.Band, ap.SSID, ap.RSSI)
	}

	// 5GHz
	s.Apply(Event{Type: "AP", BSSID: "b5", SSID: "home5", Channel: 36, APChannel: 36})
	for _, ap := range s.Snapshot() {
		if ap.BSSID == "b5" && ap.Band != "5GHz" {
			t.Errorf("b5 band = %q", ap.Band)
		}
	}
}

func TestClientFramesAndKinds(t *testing.T) {
	s, _ := testStore()
	s.Apply(Event{Type: "CLI", BSSID: "b1", Client: "c1", Detail: "auth"}) // Frames 0 counts as 1
	s.Apply(Event{Type: "CLI", BSSID: "b1", Client: "c1", Detail: "assoc", Frames: 1})
	s.Apply(Event{Type: "CLI", BSSID: "b1", Client: "c1", Detail: "data", Frames: 40})
	s.Apply(Event{Type: "CLI", BSSID: "b1", Client: "c1", Detail: "data", Frames: 10})

	c := s.Snapshot()[0].Clients["c1"]
	if c.Frames != 52 {
		t.Errorf("frames = %d, want 52", c.Frames)
	}
	if want := []string{"auth", "assoc", "data"}; !reflect.DeepEqual(c.Kinds, want) {
		t.Errorf("kinds = %v, want %v", c.Kinds, want)
	}
}

func TestSnapshotOrder(t *testing.T) {
	s, _ := testStore()
	s.Apply(Event{Type: "AP", BSSID: "loud-empty", RSSI: -30})
	s.Apply(Event{Type: "AP", BSSID: "one", RSSI: -80})
	s.Apply(Event{Type: "CLI", BSSID: "one", Client: "c1"})
	s.Apply(Event{Type: "AP", BSSID: "two", RSSI: -90})
	s.Apply(Event{Type: "CLI", BSSID: "two", Client: "c1"})
	s.Apply(Event{Type: "CLI", BSSID: "two", Client: "c2"})
	s.Apply(Event{Type: "CLI", BSSID: "ghost", Client: "c3"}) // never beaconed

	var got []string
	for _, ap := range s.Snapshot() {
		got = append(got, ap.BSSID)
	}
	want := []string{"two", "one", "ghost", "loud-empty"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestPrune(t *testing.T) {
	s, now := testStore()
	s.Apply(Event{Type: "AP", BSSID: "old-ap"})
	s.Apply(Event{Type: "AP", BSSID: "busy"})
	s.Apply(Event{Type: "CLI", BSSID: "busy", Client: "old-client"})

	*now = now.Add(20 * time.Minute)
	s.Apply(Event{Type: "CLI", BSSID: "busy", Client: "fresh"})

	*now = now.Add(15 * time.Minute) // old stuff is 35m old, fresh is 15m
	aps, clients := s.Prune(30 * time.Minute)
	if aps != 1 || clients != 1 {
		t.Errorf("pruned %d APs, %d clients; want 1, 1", aps, clients)
	}
	snap := s.Snapshot()
	if len(snap) != 1 || snap[0].BSSID != "busy" {
		t.Fatalf("left %d APs", len(snap))
	}
	if _, ok := snap[0].Clients["fresh"]; !ok || len(snap[0].Clients) != 1 {
		t.Errorf("clients left: %v", snap[0].Clients)
	}
}

func TestChannelSupportedOnlineOnly(t *testing.T) {
	s, _ := testStore()
	s.SetNodeInfo("n", "esp32c5", []int{1, 36})
	if !s.ChannelSupported(36) || s.ChannelSupported(40) {
		t.Error("online node channels wrong")
	}
	s.SetNodeOnline("n", false)
	if s.ChannelSupported(36) {
		t.Error("offline node must not count")
	}
}
