package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/control"
)

// TestPolicyChangesNetmaps: without a policy nobody sees anybody; a
// reload over the admin socket makes the allowed pair visible with the
// receiver-side rules in the netmap; an invalid file keeps the running
// policy; an empty one hides everyone but the hub.
func TestPolicyChangesNetmaps(t *testing.T) {
	cfg, _ := testConfig(t)
	h := newHarness(t, cfg)
	h.srv.deps.HubOptions = control.HubOptions{Coalesce: 10 * time.Millisecond}
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()
	socket := cfg.AdminSocket
	server := "https://" + h.srv.HTTPSAddr()

	tokA := createTokenLocal(t, socket) // creates alice
	if code, body := postLocal(t, socket, http.MethodPost, "/api/v1/users", map[string]string{"name": "bob", "role": "member", "password": "bobpassword"}); code != http.StatusCreated {
		t.Fatalf("create bob: %d %s", code, body)
	}
	_, body := postLocal(t, socket, http.MethodPost, "/api/v1/tokens", map[string]any{"owner": "bob", "kind": "server"})
	var tokB struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &tokB); err != nil {
		t.Fatal(err)
	}
	a, err := client.Enroll(ctx, client.Options{Server: server, Token: tokA, Fingerprint: h.srv.tlsFingerprint, StateDir: t.TempDir(), Hostname: "alice-laptop", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Enroll(ctx, client.Options{Server: server, Token: tokB.Secret, Fingerprint: h.srv.tlsFingerprint, StateDir: t.TempDir(), Hostname: "bob-box", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	peersOf := func(id string) (int, []control.FilterRule) {
		nm, err := h.srv.netmaps.Build(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return len(nm.Peers), nm.Filter
	}
	if n, _ := peersOf(a.PeerID); n != 0 {
		t.Fatalf("no policy but alice sees %d peers", n)
	}

	write := func(doc string) {
		if err := os.WriteFile(cfg.PolicyFile, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:22']\n    proto: tcp\n")
	gen := h.srv.Hub().Generation()
	code, body := postLocal(t, socket, http.MethodPost, "/api/v1/policy/reload", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"visible_pairs":1`) {
		t.Fatalf("reload: %d %s", code, body)
	}
	waitUntil(t, "alice sees bob", func() bool { n, _ := peersOf(a.PeerID); return n == 1 })
	nb, filter := peersOf(b.PeerID)
	if nb != 1 || len(filter) != 1 || filter[0].SrcIPv4.String() != a.IPv4 || filter[0].Proto != "tcp" || filter[0].PortLo != 22 {
		t.Fatalf("bob's netmap: peers %d filter %+v", nb, filter)
	}
	if _, fa := peersOf(a.PeerID); len(fa) != 0 {
		t.Errorf("alice's filter should be empty: %+v", fa)
	}
	if h.srv.Hub().Generation() <= gen {
		t.Error("reload did not bump the netmap generation")
	}

	// Invalid file: 400 with the error, running policy untouched.
	write("version: 1\nacls:\n  - action: accept\n    src: [ghost]\n    dst: ['*:*']\n")
	code, body = postLocal(t, socket, http.MethodPost, "/api/v1/policy/reload", nil)
	if code != http.StatusBadRequest || !strings.Contains(string(body), "unknown user") {
		t.Fatalf("invalid reload: %d %s", code, body)
	}
	if n, _ := peersOf(a.PeerID); n != 1 {
		t.Fatal("invalid reload changed the policy")
	}
	code, body = postLocal(t, socket, http.MethodGet, "/api/v1/policy", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "bob:22") {
		t.Errorf("show: %d %s", code, body)
	}

	// Empty policy: default deny again.
	write("version: 1\n")
	if code, _ := postLocal(t, socket, http.MethodPost, "/api/v1/policy/reload", nil); code != http.StatusOK {
		t.Fatalf("empty reload: %d", code)
	}
	waitUntil(t, "alice sees nobody", func() bool { n, _ := peersOf(a.PeerID); return n == 0 })
	if nm, _ := h.srv.netmaps.Build(ctx, a.PeerID); nm.Hub.PublicKey == "" {
		t.Error("hub missing under the empty policy")
	}

	// Tag ownership: bob (member) may not mint tag:prod without a rule.
	write("version: 1\ntagOwners:\n  tag:prod: [alice]\n")
	if code, _ := postLocal(t, socket, http.MethodPost, "/api/v1/policy/reload", nil); code != http.StatusOK {
		t.Fatalf("tagOwners reload: %d", code)
	}
	if !h.srv.policySvc.TagAllowed("alice", "tag:prod") || h.srv.policySvc.TagAllowed("bob", "tag:prod") {
		t.Error("tagOwners not in effect")
	}
	// The hub device got a forward-hook filter with every peer visible.
	set, ok := h.fake.LastFilter()
	if !ok || set.Hook != 1 || len(set.Visible) != 2 {
		t.Errorf("hub filter: %+v ok=%v", set, ok)
	}
}
