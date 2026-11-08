package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// POST /api/mode body: {"mode":"hop"} or {"mode":"fixed","channel":11}
type modeRequest struct {
	Mode    string `json:"mode"`
	Channel int    `json:"channel"`
}

func newServer(store *Store, ctrl *Controller) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Snapshot())
	})

	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req modeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}

		var cmd string
		switch req.Mode {
		case "hop":
			cmd = "HOP\n"
		case "fixed":
			if req.Channel < 1 || req.Channel > 13 {
				http.Error(w, "channel must be 1-13", http.StatusBadRequest)
				return
			}
			cmd = fmt.Sprintf("CH %d\n", req.Channel)
		default:
			http.Error(w, `mode must be "hop" or "fixed"`, http.StatusBadRequest)
			return
		}

		if err := ctrl.Broadcast(cmd); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("/", http.FileServer(http.Dir("static")))
	return mux
}
