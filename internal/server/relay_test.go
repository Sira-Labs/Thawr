package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/relay"
	"github.com/sira-labs/thawr/internal/wg"
)

// TestRelayOverTLS: two enrolled peers reach the relay through the real
// listener with their node secrets and exchange a frame; deleting one
// closes its session; the status endpoint counts.
func TestRelayOverTLS(t *testing.T) {
	cfg, _ := testConfig(t)
	allowSelfPolicy(t, cfg)
	h := newHarness(t, cfg)
	h.srv.deps.HubOptions = control.HubOptions{Coalesce: 10 * time.Millisecond}
	h.start(t)
	defer h.stop(t)

	ctx := context.Background()
	server := "https://" + h.srv.HTTPSAddr()
	tlsCfg, err := client.PinnedTLSConfig(h.srv.tlsFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	type peer struct {
		st   client.State
		key  wg.Key
		conn interface {
			Read([]byte) (int, error)
			Write([]byte) (int, error)
			SetReadDeadline(time.Time) error
			Close() error
		}
	}
	var peers []peer
	for _, host := range []string{"a", "b"} {
		dir := t.TempDir()
		st, err := client.Enroll(ctx, client.Options{Server: server, Token: createTokenLocal(t, cfg.AdminSocket), Fingerprint: h.srv.tlsFingerprint, StateDir: dir, Hostname: host, Version: "0.1.0"})
		if err != nil {
			t.Fatal(err)
		}
		key, _ := client.LoadKey(dir)
		conn, err := relay.Dial(ctx, server, tlsCfg, st.NodeSecret)
		if err != nil {
			t.Fatalf("relay dial for %s: %v", host, err)
		}
		defer conn.Close()
		peers = append(peers, peer{st: st, key: key.PublicKey(), conn: conn})
	}
	if _, err := relay.Dial(ctx, server, tlsCfg, "thawr_wrong"); err == nil {
		t.Fatal("relay accepted a bogus node secret")
	}
	waitUntil(t, "two relay sessions", func() bool { st, _ := h.srv.Status(ctx); return st.Relay.Sessions == 2 })

	payload := []byte{4, 0, 0, 0, 7, 7}
	if err := relay.WriteFrame(peers[0].conn, relay.Frame{Type: relay.TypeSend, Key: relay.Key(peers[1].key), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = peers[1].conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := relay.ReadFrame(peers[1].conn, make([]byte, relay.HeaderLen+relay.MaxPayload))
	if err != nil || got.Type != relay.TypeRecv || got.Key != relay.Key(peers[0].key) || string(got.Payload) != string(payload) {
		t.Fatalf("b received %+v err=%v", got, err)
	}
	// The counters are bumped by the forwarding goroutine after the
	// frame is queued, so they can trail the delivery by a moment.
	waitUntil(t, "status counters", func() bool {
		st, _ := h.srv.Status(ctx)
		return st.Relay.Frames == 1 && st.Relay.Bytes == uint64(len(payload))
	})

	// Deleting b closes its relay session and a's frames to it are gone.
	if code, _ := postLocal(t, cfg.AdminSocket, http.MethodDelete, "/api/v1/peers/b", nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	_ = peers[1].conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := relay.ReadFrame(peers[1].conn, make([]byte, relay.HeaderLen+relay.MaxPayload)); err == nil {
		t.Fatal("deleted peer's session still open")
	}
	waitUntil(t, "session pruned", func() bool { st, _ := h.srv.Status(ctx); return st.Relay.Sessions == 1 })
	if err := relay.WriteFrame(peers[0].conn, relay.Frame{Type: relay.TypeSend, Key: relay.Key(peers[1].key), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	_ = peers[0].conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, err := relay.ReadFrame(peers[0].conn, make([]byte, relay.HeaderLen+relay.MaxPayload)); err != nil || got.Type != relay.TypePeerGone {
		t.Fatalf("expected PEER_GONE, got %+v err=%v", got, err)
	}
}
