package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/wg"
	"github.com/sira-labs/thawr/internal/wg/wgtest"
)

// createTokenLocal creates a user (once) and a token over the admin socket.
func createTokenLocal(t *testing.T, socket string) string {
	t.Helper()
	code, body := postLocal(t, socket, http.MethodPost, "/api/v1/users", map[string]string{"name": "alice", "role": "member", "password": "alicepassword"})
	if code != http.StatusCreated && code != http.StatusConflict {
		t.Fatalf("create user: %d %s", code, body)
	}
	code, body = postLocal(t, socket, http.MethodPost, "/api/v1/tokens", map[string]any{"owner": "alice", "kind": "human"})
	if code != http.StatusCreated {
		t.Fatalf("create token: %d %s", code, body)
	}
	var created struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	return created.Secret
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 5s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestHubDevicePeersFollowRegistry: enrolling and deleting peers changes
// the hub WireGuard interface within the coalescing delay.
func TestHubDevicePeersFollowRegistry(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PublicAddr = "127.0.0.1"
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)

	waitUntil(t, "initial hub config", func() bool { _, ok := h.fake.Last(); return ok })
	last, _ := h.fake.Last()
	if len(last.Peers) != 0 {
		t.Fatalf("hub started with %d peers", len(last.Peers))
	}

	secret := createTokenLocal(t, cfg.AdminSocket)
	st, err := client.Enroll(context.Background(), client.Options{
		Server: "https://" + h.srv.HTTPSAddr(), Token: secret, Fingerprint: h.srv.tlsFingerprint, StateDir: t.TempDir(), Hostname: "laptop", Version: "0.1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "hub gains the peer", func() bool {
		last, _ := h.fake.Last()
		return len(last.Peers) == 1 && last.Peers[0].AllowedIPs[0].String() == st.IPv4+"/32"
	})
	if code, _ := postLocal(t, cfg.AdminSocket, http.MethodDelete, "/api/v1/peers/laptop", nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	waitUntil(t, "hub drops the peer", func() bool { last, _ := h.fake.Last(); return len(last.Peers) == 0 })
}

// TestSyncOverTLS runs a client daemon (fake device) against the real
// server: it receives the hub, sees a second peer appear and disappear,
// and the server reports it online.
func TestSyncOverTLS(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	cfg.PublicAddr = "127.0.0.1"
	h := newHarness(t, cfg)
	h.srv.deps.HubOptions = control.HubOptions{Coalesce: 10 * time.Millisecond, KeepaliveInterval: 200 * time.Millisecond, OfflineAfter: 200 * time.Millisecond}
	h.start(t)
	defer h.stop(t)

	dirA, dirB := t.TempDir(), t.TempDir()
	server := "https://" + h.srv.HTTPSAddr()
	for _, d := range []struct{ dir, host string }{{dirA, "a"}, {dirB, "b"}} {
		if _, err := client.Enroll(context.Background(), client.Options{Server: server, Token: createTokenLocal(t, cfg.AdminSocket), Fingerprint: h.srv.tlsFingerprint, StateDir: d.dir, Hostname: d.host, Version: "0.1.0"}); err != nil {
			t.Fatal(err)
		}
	}
	fake := wgtest.New("thawr1")
	d, err := client.NewDaemon(client.DaemonOptions{
		StateDir: dirA, Socket: filepath.Join(shortTempDir(t), "c.sock"), Interface: "thawr1",
		OpenDevice: func(context.Context, wg.Options) (wg.Device, error) { return fake, nil },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "0.1.0", MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	var stopOnce sync.Once
	stopDaemon := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("daemon: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("daemon did not stop")
			}
		})
	}
	defer stopDaemon()

	var got client.NetMap
	waitUntil(t, "netmap with peer b", func() bool {
		select {
		case nm := <-d.Applied():
			got = nm
			return len(nm.Peers) == 1 && nm.Hub.PublicKey == h.srv.hubKey.PublicKey().String()
		default:
			return false
		}
	})
	if got.Peers[0].Name != "b" {
		t.Errorf("peer: %+v", got.Peers[0])
	}
	waitUntil(t, "server marks a online", func() bool { return h.srv.Hub().Online(got.SelfID) })
	code, body := postLocal(t, cfg.AdminSocket, http.MethodGet, "/api/v1/peers", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"name":"a","kind":"human","mode":"agent","owner":"alice","tags":[],"public_key"`) || !strings.Contains(string(body), `"online":true`) {
		t.Errorf("peer list: %d %s", code, body)
	}
	code, body = postLocal(t, cfg.AdminSocket, http.MethodGet, "/api/v1/status", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"online_peers":1`) {
		t.Errorf("status: %d %s", code, body)
	}

	if code, _ := postLocal(t, cfg.AdminSocket, http.MethodDelete, "/api/v1/peers/b", nil); code != http.StatusNoContent {
		t.Fatal("delete b")
	}
	waitUntil(t, "netmap without b", func() bool {
		select {
		case nm := <-d.Applied():
			return len(nm.Peers) == 0
		default:
			return false
		}
	})
	last, _ := fake.Last()
	if len(last.Peers) != 1 {
		t.Errorf("device should only have the hub left, has %d peers", len(last.Peers))
	}

	stopDaemon()
	waitUntil(t, "server marks a offline", func() bool { h.srv.Hub().Sweep(); return !h.srv.Hub().Online(got.SelfID) })
}
