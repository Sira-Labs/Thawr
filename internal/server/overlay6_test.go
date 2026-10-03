package server

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
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
