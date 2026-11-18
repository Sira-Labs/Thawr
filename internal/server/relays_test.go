package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// TestRelayRegistryWired: the running server serves the relay admin
// API on its socket and applies relay.ticket_ttl.
func TestRelayRegistryWired(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Relay.TicketTTL = "10m"
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()

	code, body := adminGet(t, cfg.AdminSocket, "/api/v1/relays")
	if code != http.StatusOK || strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("relay list on a fresh server: %d %s", code, body)
	}

	const url, fp = "https://relay.example.com:443", "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tok, err := h.srv.relays.CreateToken(ctx, control.LocalAdmin, "riyadh-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := h.srv.relays.Register(ctx, control.RelayRegistration{Token: tok.Secret, URL: url, Fingerprint: fp})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.relays.Attach(ctx, reg.Relay.ID, control.RelayHello{URL: url, Fingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	code, body = adminGet(t, cfg.AdminSocket, "/api/v1/relays")
	var list []struct {
		Name   string `json:"name"`
		Online bool   `json:"online"`
	}
	if err := json.Unmarshal(body, &list); err != nil || code != http.StatusOK || len(list) != 1 || list[0].Name != "riyadh-1" || !list[0].Online {
		t.Fatalf("relay list: %d %s %v", code, body, err)
	}

	// The configured lifetime reaches the tickets.
	if err := h.srv.st.Peers().Create(ctx, store.Peer{ID: "p1", Name: "box", Kind: store.KindServer, Mode: store.ModeAgent,
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", IPv4: "100.64.0.77", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	grants, err := h.srv.relays.Tickets(ctx, "p1")
	if err != nil || len(grants) != 1 {
		t.Fatalf("tickets: %v %v", grants, err)
	}
	if ttl := grants[0].Expires.Sub(before); ttl < 9*time.Minute || ttl > 11*time.Minute {
		t.Errorf("ticket lifetime %s, want the configured 10m", ttl)
	}
}
