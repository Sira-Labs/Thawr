package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// fakeAdminAPI serves two peers and one detail on an admin socket.
func fakeAdminAPI(t *testing.T) string {
	t.Helper()
	peers := []map[string]any{
		{"id": "p1", "name": "alice-box", "kind": "human", "mode": "agent", "owner": "alice", "tags": []string{}, "public_key": "A=", "ipv4": "100.64.0.2",
			"online": true, "created_at": "2026-09-01T10:00:00Z", "last_seen_at": "2026-09-04T09:59:30Z", "version": "0.1.0", "os": "linux/amd64",
			"path_summary": map[string]int{"direct": 2, "relay": 1, "other": 0}, "signed": true},
		{"id": "p2", "name": "markus-box", "kind": "server", "mode": "agent", "owner": "markus", "tags": []string{"tag:prod"}, "public_key": "M=", "ipv4": "100.64.0.3",
			"online": false, "created_at": "2026-09-01T10:00:00Z", "version": "", "os": "", "path_summary": map[string]int{}},
	}
	detail := map[string]any{}
	for k, v := range peers[1] {
		detail[k] = v
	}
	detail["paths"] = []map[string]string{{"peer": "alice-box", "state": "direct", "endpoint": "203.0.113.9:4000", "updated_at": "2026-09-04T09:59:00Z"}}
	detail["endpoints"] = []map[string]string{{"addr": "192.168.1.9:41820", "kind": "local"}, {"addr": "203.0.113.9:41820", "kind": "reflexive"}}
	detail["symmetric"] = true
	detail["filter"] = []map[string]any{{"src": "100.64.0.2", "proto": "tcp", "port_lo": 22, "port_hi": 22}, {"src": "100.64.0.2", "proto": "udp", "port_lo": 8000, "port_hi": 8100}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/peers", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(peers) })
	mux.HandleFunc("GET /api/v1/peers/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") != "markus-box" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "peer not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(detail)
	})
	return fakeDaemonSocket(t, mux)
}

func TestAdminPeerList(t *testing.T) {
	sock := fakeAdminAPI(t)
	out, code, err := runCLI(t, "admin", "peer", "list", "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d: %v", code, err)
	}
	for _, want := range []string{"NAME", "MODE", "LAST SEEN", "PATHS", "VERSION", "OS", "SIGNED", "alice-box", "agent", "2 direct, 1 relay", "0.1.0", "linux/amd64", "yes", "markus-box", "offline", "never"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	out, _, _ = runCLI(t, "admin", "peer", "list", "--online", "--socket", sock)
	if !strings.Contains(out, "alice-box") || strings.Contains(out, "markus-box") {
		t.Errorf("--online: %s", out)
	}
	out, _, _ = runCLI(t, "admin", "peer", "list", "--online", "--json", "--socket", sock)
	var peers []peerJSON
	if err := json.Unmarshal([]byte(out), &peers); err != nil || len(peers) != 1 || peers[0].Name != "alice-box" {
		t.Errorf("--json: %v %s", err, out)
	}
}

func TestAdminPeerShowFilter(t *testing.T) {
	sock := fakeAdminAPI(t)
	out, code, err := runCLI(t, "admin", "peer", "show", "markus-box", "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d: %v", code, err)
	}
	for _, want := range []string{"name:      markus-box", "tags:      tag:prod", "nat:       symmetric", "192.168.1.9:41820 (local)", "203.0.113.9:41820 (reflexive)",
		"alice-box: direct 203.0.113.9:4000", "Filter (2 rules", "100.64.0.2 -> tcp 22", "100.64.0.2 -> udp 8000-8100"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	out, _, _ = runCLI(t, "admin", "peer", "show", "markus-box", "--json", "--socket", sock)
	var d peerDetailJSON
	if err := json.Unmarshal([]byte(out), &d); err != nil || len(d.Filter) != 2 || d.Filter[1].PortHi != 8100 || !d.Symmetric {
		t.Errorf("--json: %v %s", err, out)
	}
	if _, code, _ := runCLI(t, "admin", "peer", "show", "ghost", "--socket", sock); code == 0 {
		t.Error("unknown peer exited 0")
	}
	if _, code, _ := runCLI(t, "admin", "peer", "show", "--socket", sock); code != exitConfigError {
		t.Errorf("missing name: exit %d", code)
	}
}
