package main

import "testing"

func TestOUILookup(t *testing.T) {
	db, err := LoadOUI("oui.csv")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"2c:7b:a0:c9:eb:cc": "Intel Corporate",
		"C8:EA:F8:EE:CA:5D": "zte corporation", // case-insensitive
		"d6:b3:6b:9d:bc:78": "",                // randomized: no vendor
		"00:00":             "",                // too short
	}
	for mac, want := range cases {
		if got := db.Lookup(mac); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", mac, got, want)
		}
	}
	var nilDB OUIDB
	if nilDB.Lookup("2c:7b:a0:c9:eb:cc") != "" {
		t.Error("nil db must return empty")
	}
}
