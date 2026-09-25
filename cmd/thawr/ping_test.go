package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/sira-labs/thawr/internal/client"
)

// probingDaemon answers /status with b idle until /ping/b was called,
// then with a direct path.
func probingDaemon(t *testing.T) (sock string, pinged func() int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		st := statusFixture()
		st.Peers = st.Peers[3:4] // bob-laptop, idle
		mu.Lock()
		if calls > 0 {
			st.Peers[0].Path, st.Peers[0].PathEndpoint = "direct", "192.0.2.5:41820"
		}
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("POST /ping/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") != "bob-laptop" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unknown peer"})
			return
		}
		mu.Lock()
		calls++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(client.PathResult{Peer: "bob-laptop", State: "direct", Endpoint: "192.0.2.5:41820"})
	})
	return fakeDaemonSocket(t, mux), func() int { mu.Lock(); defer mu.Unlock(); return calls }
}

func runCLI(t *testing.T, args ...string) (out string, code int, err error) {
	t.Helper()
	var o, e bytes.Buffer
	root := newRootCmd(&o, &e)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	var ee *exitError
	switch {
	case errors.As(err, &ee):
		code = ee.code
	case err != nil:
		code = 1
	}
	return o.String(), code, err
}

func TestClientPingTriggersProbe(t *testing.T) {
	sock, pinged := probingDaemon(t)
	out, code, err := runCLI(t, "client", "ping", "bob-laptop", "--count", "0", "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d: %v\n%s", code, err, out)
	}
	if pinged() != 1 {
		t.Errorf("daemon pinged %d times, want 1", pinged())
	}
	if want := "path: idle → direct 192.0.2.5:41820\n"; out != want {
		t.Errorf("output %q, want %q", out, want)
	}

	out, code, _ = runCLI(t, "client", "ping", "bob-laptop", "--count", "0", "--json", "--socket", sock)
	var res client.PathResult
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.State != "direct" || res.Endpoint != "192.0.2.5:41820" || res.Peer != "bob-laptop" {
		t.Errorf("json: exit %d %q", code, out)
	}
}

func TestClientPingViaHub(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		st := statusFixture()
		st.Peers = st.Peers[2:3] // alice-phone, via hub
		_ = json.NewEncoder(w).Encode(st)
	})
	mux.HandleFunc("POST /ping/{name}", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(client.PathResult{Peer: "alice-phone", State: client.PathHub})
	})
	sock := fakeDaemonSocket(t, mux)
	out, code, err := runCLI(t, "client", "ping", "alice-phone", "--count", "0", "--socket", sock)
	if code != 0 || out != "path: via hub → via hub\n" {
		t.Errorf("exit %d err %v out %q", code, err, out)
	}
}

func TestClientPingExitCodes(t *testing.T) {
	sock, _ := probingDaemon(t)
	if _, code, err := runCLI(t, "client", "ping", "ghost", "--count", "0", "--socket", sock); code != exitConfigError || !strings.Contains(err.Error(), "unknown peer") {
		t.Errorf("unknown peer: exit %d err %v", code, err)
	}
	if _, code, _ := runCLI(t, "client", "ping", "--socket", sock); code != exitConfigError {
		t.Errorf("missing argument: exit %d", code)
	}
	if _, code, _ := runCLI(t, "client", "ping", "bob-laptop", "--count", "0", "--socket", sock+".missing"); code != exitNotRunning {
		t.Errorf("no daemon: exit %d", code)
	}
	idle := statusFixture()
	if _, code, _ := runCLI(t, "client", "ping", "bob-laptop", "--count", "0", "--socket", fakeDaemon(t, idle)); code != exitConfigError {
		// fakeDaemon has no /ping route: a 404 is an unknown peer.
		t.Errorf("no ping route: exit %d", code)
	}
}
