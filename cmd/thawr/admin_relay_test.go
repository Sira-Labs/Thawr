package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// fakeRelayAPI serves two relays, records token requests and deletes.
func fakeRelayAPI(t *testing.T) (sock string, tokenBody func() string, deleted func() []string) {
	t.Helper()
	var body string
	var gone []string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/relays", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "rl_b1", "name": "berlin-1", "url": "https://relay-berlin.example.com:443", "tls_fingerprint": "sha256:bb", "online": false,
				"registered_at": "2026-11-01T10:00:00Z", "sessions": 0, "frames": 0, "bytes": 0, "drops": 0},
			{"id": "rl_r1", "name": "riyadh-1", "url": "https://relay-riyadh.example.com:443", "tls_fingerprint": "sha256:aa", "version": "0.2.0",
				"online": true, "since": "2026-11-18T08:00:00Z", "registered_at": "2026-11-02T10:00:00Z", "last_seen_at": "2026-11-18T08:00:00Z",
				"sessions": 4, "frames": 1200, "bytes": 987654, "drops": 3},
		})
	})
	mux.HandleFunc("POST /api/v1/relays/tokens", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		if strings.Contains(body, `"expires":"25h"`) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "expiry exceeds the maximum of 24h0m0s"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "rt_12345678", "name": "riyadh-2", "expires_at": "2026-11-18T09:00:00Z", "secret": "thawr_relay_TESTONLY"})
	})
	mux.HandleFunc("DELETE /api/v1/relays/{id}", func(w http.ResponseWriter, r *http.Request) {
		gone = append(gone, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	return fakeDaemonSocket(t, mux), func() string { return body }, func() []string { return gone }
}

func TestAdminRelay(t *testing.T) {
	sock, tokenBody, deleted := fakeRelayAPI(t)

	out, code, err := runCLI(t, "admin", "relay", "list", "--socket", sock)
	if code != 0 {
		t.Fatalf("list: exit %d: %v", code, err)
	}
	for _, want := range []string{
		"NAME      URL                                   STATE                              SESSIONS  VERSION",
		"berlin-1  https://relay-berlin.example.com:443  offline                            0         -",
		"riyadh-1  https://relay-riyadh.example.com:443  online since 2026-11-18T08:00:00Z  4         0.2.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	out, code, _ = runCLI(t, "admin", "relay", "list", "--json", "--socket", sock)
	var relays []relayJSON
	if err := json.Unmarshal([]byte(out), &relays); code != 0 || err != nil || len(relays) != 2 || relays[1].Bytes != 987654 {
		t.Errorf("list --json: %d %v %s", code, err, out)
	}

	out, code, err = runCLI(t, "admin", "relay", "show", "riyadh-1", "--socket", sock)
	if code != 0 {
		t.Fatalf("show: exit %d: %v", code, err)
	}
	for _, want := range []string{"Name:             riyadh-1", "Id:               rl_r1", "TLS fingerprint:  sha256:aa",
		"State:            online since 2026-11-18T08:00:00Z", "Last seen:        2026-11-18T08:00:00Z", "Bytes:            987654", "Drops:            3"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if out, code, _ = runCLI(t, "admin", "relay", "show", "berlin-1", "--socket", sock); code != 0 || !strings.Contains(out, "Last seen:        -") || !strings.Contains(out, "Version:          -") {
		t.Errorf("show of a relay never seen: %d\n%s", code, out)
	}
	if _, code, err = runCLI(t, "admin", "relay", "show", "nowhere", "--socket", sock); code == 0 || err == nil || !strings.Contains(err.Error(), `relay "nowhere": not found`) {
		t.Errorf("show of an unknown relay: code=%d err=%v", code, err)
	}

	out, code, err = runCLI(t, "admin", "relay", "token", "--name", "riyadh-2", "--ttl", "30m", "--socket", sock)
	if code != 0 {
		t.Fatalf("token: exit %d: %v", code, err)
	}
	if tokenBody() != `{"expires":"30m","name":"riyadh-2"}` {
		t.Errorf("token request: %s", tokenBody())
	}
	for _, want := range []string{"Token id:     rt_12345678  (expires 2026-11-18T09:00:00Z, single use)", "Relay name:   riyadh-2", "Relay token:  thawr_relay_TESTONLY"} {
		if !strings.Contains(out, want) {
			t.Errorf("token output lacks %q:\n%s", want, out)
		}
	}
	if _, code, _ = runCLI(t, "admin", "relay", "token", "--socket", sock); code != 0 || tokenBody() != `{"expires":"1h","name":""}` {
		t.Errorf("token defaults: code=%d body=%s", code, tokenBody())
	}
	if _, code, err = runCLI(t, "admin", "relay", "token", "--ttl", "25h", "--socket", sock); code == 0 || err == nil || !strings.Contains(err.Error(), "exceeds the maximum") {
		t.Errorf("server error not surfaced: code=%d err=%v", code, err)
	}

	// delete takes the name and sends the id.
	out, code, err = runCLI(t, "admin", "relay", "delete", "riyadh-1", "--socket", sock)
	if code != 0 || !strings.Contains(out, "relay riyadh-1 deleted") || len(deleted()) != 1 || deleted()[0] != "rl_r1" {
		t.Errorf("delete: code=%d err=%v out=%q deleted=%v", code, err, out, deleted())
	}
	if _, code, _ = runCLI(t, "admin", "relay", "delete", "nowhere", "--socket", sock); code == 0 || len(deleted()) != 1 {
		t.Errorf("delete of an unknown relay: code=%d deleted=%v", code, deleted())
	}
	if _, code, _ = runCLI(t, "admin", "relay", "delete", "--socket", sock); code == 0 {
		t.Error("delete without a name succeeded")
	}
}
