package server

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestResolveOverlayIPv6(t *testing.T) {
	ctx := context.Background()
	rnd := func() *bytes.Reader { return bytes.NewReader([]byte{0x3a, 0x9c, 0x1e, 0x44, 0xb0}) }

	t.Run("generated once, then kept", func(t *testing.T) {
		st := openStore(t)
		p, gen, err := resolveOverlayIPv6(ctx, "", st.Meta(), rnd())
		if err != nil || !gen || p.String() != "fd3a:9c1e:44b0::/64" {
			t.Fatalf("first start = %s %v %v", p, gen, err)
		}
		p2, gen, err := resolveOverlayIPv6(ctx, "", st.Meta(), bytes.NewReader(nil))
		if err != nil || gen || p2 != p {
			t.Fatalf("second start = %s %v %v; want the recorded %s without randomness", p2, gen, err, p)
		}
		p3, _, err := resolveOverlayIPv6(ctx, "fd3a:9c1e:44b0:0::/64", st.Meta(), nil)
		if err != nil || p3 != p {
			t.Errorf("the same prefix configured later = %s %v", p3, err)
		}
	})
	t.Run("configured is recorded", func(t *testing.T) {
		st := openStore(t)
		p, gen, err := resolveOverlayIPv6(ctx, "fd12:3456:789a::/64", st.Meta(), nil)
		if err != nil || gen || p.String() != "fd12:3456:789a::/64" {
			t.Fatalf("configured = %s %v %v", p, gen, err)
		}
		if v, _ := st.Meta().Get(ctx, store.MetaOverlayIPv6); v != "fd12:3456:789a::/64" {
			t.Errorf("meta = %q", v)
		}
		if _, _, err := resolveOverlayIPv6(ctx, "fd99::/64", st.Meta(), nil); !errors.Is(err, ErrOverlayIPv6Changed) {
			t.Errorf("changed prefix: %v, want ErrOverlayIPv6Changed", err)
		}
	})
	t.Run("no randomness", func(t *testing.T) {
		st := openStore(t)
		if _, _, err := resolveOverlayIPv6(ctx, "", st.Meta(), bytes.NewReader(nil)); err == nil {
			t.Error("generated a prefix without randomness")
		}
		if _, err := st.Meta().Get(ctx, store.MetaOverlayIPv6); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a failed generation recorded something: %v", err)
		}
	})
}

func TestBackfillIPv6(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	for i, v4 := range []string{"100.64.0.2", "100.64.0.3"} {
		id := string(rune('a' + i))
		if err := st.Peers().Create(ctx, store.Peer{ID: id, Name: id, Kind: store.KindHuman, Mode: store.ModeAgent,
			PublicKey: "k" + id, IPv4: v4, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	p, _, err := resolveOverlayIPv6(ctx, "fd3a:9c1e:44b0::/64", st.Meta(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := backfillIPv6(ctx, st.Peers(), p); err != nil || n != 2 {
		t.Fatalf("backfill = %d, %v", n, err)
	}
	if n, err := backfillIPv6(ctx, st.Peers(), p); err != nil || n != 0 {
		t.Errorf("second backfill = %d, %v; want nothing left", n, err)
	}
	b, _ := st.Peers().GetByID(ctx, "b")
	if b.IPv6 != "fd3a:9c1e:44b0::6440:3" {
		t.Errorf("peer b ipv6 = %q", b.IPv6)
	}
}

// TestHubIPv6 checks the hub's side of spec 015: both addresses on the
// interface, a /128 next to the /32 only for capable peers, and IPv6
// in the forward filter only toward capable peers.
func TestHubIPv6(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Overlay.IPv6 = "fd3a:9c1e:44b0::/64"
	if err := os.WriteFile(cfg.PolicyFile, []byte("version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	ctx := context.Background()

	prefix := netip.MustParsePrefix(cfg.Overlay.IPv6)
	hub6 := control.IPv6For(prefix, cfg.HubAddr().Addr())
	type peerSpec struct {
		name    string
		mode    string
		v4      string
		capable bool
	}
	specs := []peerSpec{
		{"phone", store.ModeStatic, "100.64.0.5", true},
		{"laptop", store.ModeAgent, "100.64.0.6", false},
		{"nas", store.ModeAgent, "100.64.0.7", true},
	}
	v6 := map[string]netip.Addr{}
	for _, sp := range specs {
		key, err := wg.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		v6[sp.name] = control.IPv6For(prefix, netip.MustParseAddr(sp.v4))
		if err := h.srv.st.Peers().Create(ctx, store.Peer{ID: sp.name, Name: sp.name, Kind: store.KindHuman, Mode: sp.mode,
			PublicKey: key.PublicKey().String(), IPv4: sp.v4, IPv6: v6[sp.name].String(), IPv6Capable: sp.capable, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	h.srv.reloadPolicy()
	if err := h.srv.configureHub(ctx); err != nil {
		t.Fatal(err)
	}

	last, ok := h.fake.Last()
	if !ok {
		t.Fatal("hub device never configured")
	}
	if want := []netip.Prefix{cfg.HubAddr(), netip.PrefixFrom(hub6, 64)}; !slices.Equal(last.Addresses, want) {
		t.Errorf("hub addresses %v, want %v", last.Addresses, want)
	}
	allowed := map[string][]netip.Prefix{}
	for _, p := range last.Peers {
		for _, sp := range specs {
			if p.AllowedIPs[0] == netip.MustParsePrefix(sp.v4+"/32") {
				allowed[sp.name] = p.AllowedIPs
			}
		}
	}
	for _, sp := range specs {
		want := []netip.Prefix{netip.MustParsePrefix(sp.v4 + "/32")}
		if sp.capable {
			want = append(want, netip.PrefixFrom(v6[sp.name], 128))
		}
		if !slices.Equal(allowed[sp.name], want) {
			t.Errorf("%s AllowedIPs %v, want %v", sp.name, allowed[sp.name], want)
		}
	}

	set, ok := h.fake.LastFilter()
	if !ok {
		t.Fatal("no hub filter")
	}
	if set.Local6 != hub6 {
		t.Errorf("filter Local6 %s, want %s", set.Local6, hub6)
	}
	if !slices.Contains(set.Visible, v6["phone"]) || !slices.Contains(set.Visible, v6["nas"]) || slices.Contains(set.Visible, v6["laptop"]) {
		t.Errorf("visible %v: want the capable peers' IPv6 addresses only", set.Visible)
	}
	var toPhone6 bool
	for _, r := range set.Rules {
		if r.Src.Addr().Is6() != r.Dst.Is6() || r.Src.Bits() != r.Src.Addr().BitLen() {
			t.Errorf("rule mixes families or widens its source: %+v", r)
		}
		if r.Dst == v6["laptop"] {
			t.Errorf("IPv6 rule toward an incapable peer: %+v", r)
		}
		toPhone6 = toPhone6 || (r.Dst == v6["phone"] && r.Src == netip.PrefixFrom(v6["nas"], 128))
	}
	if !toPhone6 {
		t.Errorf("no IPv6 rule from nas to the phone: %+v", set.Rules)
	}
}
