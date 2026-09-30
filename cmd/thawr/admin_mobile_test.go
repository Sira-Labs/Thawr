package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testConf = "[Interface]\nPrivateKey = cGVlcGVlcGVlcGVlcGVlcGVlcGVlcGVlcGVlcGVlcGVlcGU=\nAddress = 100.64.0.21/32\n\n[Peer]\nPublicKey = HUB=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 100.64.0.0/10\nPersistentKeepalive = 25\n"

// fakeMobileAPI answers POST /peers/mobile with a canned config.
func fakeMobileAPI(t *testing.T) (sock string, bodies *[]map[string]any) {
	t.Helper()
	var seen []map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/peers/mobile", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen = append(seen, body)
		if body["owner"] == "ghost" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown owner"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"peer":    map[string]any{"name": body["name"], "ipv4": "100.64.0.21", "owner": body["owner"], "mode": "static", "kind": "human", "tags": []string{}},
			"config":  testConf,
			"qr_svg":  "<svg/>",
			"warning": "The server decrypts this phone's traffic (threat model T4).",
		})
	})
	return fakeDaemonSocket(t, mux), &seen
}

func TestAdminAddMobile(t *testing.T) {
	sock, bodies := fakeMobileAPI(t)
	out, code, err := runCLI(t, "admin", "peer", "add-mobile", "--owner", "alice", "--name", "alice-phone", "--tags", "tag:phones", "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d: %v\n%s", code, err, out)
	}
	if len(*bodies) != 1 || (*bodies)[0]["name"] != "alice-phone" || (*bodies)[0]["kind"] != "human" {
		t.Errorf("request: %+v", *bodies)
	}
	for _, want := range []string{"alice-phone (100.64.0.21) created for alice", "threat model T4", "PrivateKey = ", "█"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "PrivateKey") != 1 {
		t.Errorf("config printed %d times", strings.Count(out, "PrivateKey"))
	}
	// The QR fits an 80x40 terminal.
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("line wider than 80 columns (%d): %q", n, line)
		}
	}

	out, _, _ = runCLI(t, "admin", "peer", "add-mobile", "--owner", "alice", "--name", "p2", "--no-qr", "--socket", sock)
	if strings.Contains(out, "█") || !strings.Contains(out, "PrivateKey = ") {
		t.Errorf("--no-qr: %s", out)
	}

	conf := filepath.Join(t.TempDir(), "phone.conf")
	out, code, _ = runCLI(t, "admin", "peer", "add-mobile", "--owner", "alice", "--name", "p3", "--no-qr", "--out", conf, "--socket", sock)
	if code != 0 || strings.Contains(out, "PrivateKey") || !strings.Contains(out, "written to") {
		t.Errorf("--out: exit %d\n%s", code, out)
	}
	data, err := os.ReadFile(conf)
	if err != nil || string(data) != testConf {
		t.Errorf("conf file: %v %q", err, data)
	}
	if fi, _ := os.Stat(conf); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("conf mode %o, want 600", fi.Mode().Perm())
	}

	out, code, _ = runCLI(t, "admin", "peer", "add-mobile", "--owner", "alice", "--name", "p4", "--json", "--socket", sock)
	var m mobileJSON
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil || m.Config != testConf || m.QRSVG != "" || m.Peer.Mode != "static" {
		t.Errorf("--json: exit %d %s", code, out)
	}

	if _, code, _ := runCLI(t, "admin", "peer", "add-mobile", "--name", "x", "--socket", sock); code != exitConfigError {
		t.Errorf("missing owner: exit %d", code)
	}
	if _, code, _ := runCLI(t, "admin", "peer", "add-mobile", "--owner", "ghost", "--name", "x", "--socket", sock); code == 0 {
		t.Error("unknown owner exited 0")
	}
}

func TestPrintMobileDNSWarning(t *testing.T) {
	var b strings.Builder
	m := mobileJSON{Peer: peerJSON{Name: "p", IPv4: "100.64.0.3", Owner: "alice"}, Config: "[Interface]\n", Warning: "T4", DNSWarning: "only .thawr names"}
	if err := printMobile(&b, m, "", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Warning: T4\nWarning: only .thawr names\n\n[Interface]") {
		t.Errorf("output:\n%s", b.String())
	}
}
