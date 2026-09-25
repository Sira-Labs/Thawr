package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/wg"
)

// trustDaemon answers /trust/{name} for "nas" and "all" and 404 otherwise.
func trustDaemon(t *testing.T, pinned, offered string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /trust/{name}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "nas", "all":
			_ = json.NewEncoder(w).Encode(client.TrustResult{Trusted: []client.HeldStatus{{Name: "nas", PinnedKey: pinned, OfferedKey: offered}}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "client: nothing to trust: " + r.PathValue("name") + " is not held"})
		}
	})
	return fakeDaemonSocket(t, mux)
}

func TestClientTrust(t *testing.T) {
	oldKey, _ := wg.GenerateKey()
	newKey, _ := wg.GenerateKey()
	pinned, offered := oldKey.PublicKey().String(), newKey.PublicKey().String()
	sock := trustDaemon(t, pinned, offered)
	want := "trusted nas (" + wg.Fingerprint(oldKey.PublicKey()) + " → " + wg.Fingerprint(newKey.PublicKey()) + ")\n"

	out, code, err := runCLI(t, "client", "trust", "nas", "--socket", sock)
	if err != nil || code != 0 || out != want {
		t.Errorf("trust nas: %q code=%d err=%v", out, code, err)
	}
	if out, code, _ := runCLI(t, "client", "trust", "--all", "--socket", sock); code != 0 || out != want {
		t.Errorf("trust --all: %q code=%d", out, code)
	}
	if out, code, err := runCLI(t, "client", "trust", "box", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "box is not held") || out != "" {
		t.Errorf("not held: %q code=%d err=%v", out, code, err)
	}
	if _, code, _ := runCLI(t, "client", "trust", "--socket", sock); code != exitConfigError {
		t.Errorf("no args: code=%d", code)
	}
	if _, code, _ := runCLI(t, "client", "trust", "nas", "--all", "--socket", sock); code != exitConfigError {
		t.Errorf("name and --all: code=%d", code)
	}
	if _, code, _ := runCLI(t, "client", "trust", "nas", "--socket", filepath.Join(t.TempDir(), "missing.sock")); code != exitNotRunning {
		t.Errorf("not running: code=%d", code)
	}
	if out, _, _ := runCLI(t, "client", "--help"); !strings.Contains(out, "trust") {
		t.Error("client help does not list trust")
	}
}
