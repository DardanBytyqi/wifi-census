package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OUIDB maps a MAC prefix to its vendor (IEEE MA-L registry).
type OUIDB map[string]string

func LoadOUI(path string) (OUIDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	db := make(OUIDB, 40000)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if len(rec) < 3 || len(rec[1]) != 6 {
			continue // header
		}
		db[strings.ToUpper(rec[1])] = strings.TrimSpace(rec[2])
	}
	return db, nil
}

// Lookup returns the vendor for a MAC, or "" if unknown or randomized.
func (db OUIDB) Lookup(mac string) string {
	if db == nil || len(mac) < 8 || isRandomizedMAC(mac) {
		return ""
	}
	key := strings.ToUpper(mac[0:2] + mac[3:5] + mac[6:8])
	return db[key]
}

// defaultOUIPath checks the working dir, the repo root and the binary's dir.
func defaultOUIPath() string {
	candidates := []string{"oui.csv", filepath.Join("backend", "oui.csv")}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "oui.csv"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "oui.csv"
}
