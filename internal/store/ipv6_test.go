package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPeerIPv6(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	mk := func(id, ipv4, ipv6 string) {
		t.Helper()
		p := Peer{ID: id, Name: "n-" + id, Kind: KindHuman, Mode: ModeAgent, PublicKey: "k-" + id,
			IPv4: ipv4, IPv6: ipv6, CreatedAt: time.Now().UTC()}
		if err := s.Peers().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "100.64.0.2", "")
	mk("b", "100.64.0.3", "fd00::6440:3")
	mk("c", "100.64.0.4", "")

	n, err := s.Peers().BackfillIPv6(ctx, func(v4 string) string {
		if v4 == "100.64.0.4" {
			return "" // a derivation that cannot map leaves the peer alone
		}
		return "fd00::" + v4
	})
	if err != nil || n != 1 {
		t.Fatalf("BackfillIPv6 = %d, %v; want 1", n, err)
	}
	for id, want := range map[string]string{"a": "fd00::100.64.0.2", "b": "fd00::6440:3", "c": ""} {
		p, err := s.Peers().GetByID(ctx, id)
		if err != nil || p.IPv6 != want {
			t.Errorf("peer %s ipv6 = %q %v, want %q", id, p.IPv6, err, want)
		}
	}
	if n, err := s.Peers().BackfillIPv6(ctx, func(string) string { return "fd00::6440:3" }); err == nil || !errors.Is(err, ErrConflict) || n != 0 {
		t.Errorf("backfill onto a taken address = %d, %v; want ErrConflict", n, err)
	}

	changed, err := s.Peers().SetIPv6Capable(ctx, "a", true)
	if err != nil || !changed {
		t.Fatalf("SetIPv6Capable = %v, %v", changed, err)
	}
	if changed, err := s.Peers().SetIPv6Capable(ctx, "a", true); err != nil || changed {
		t.Errorf("repeat SetIPv6Capable = %v, %v; want unchanged", changed, err)
	}
	if p, _ := s.Peers().GetByID(ctx, "a"); !p.IPv6Capable {
		t.Error("ipv6_capable not stored")
	}
	if _, err := s.Peers().SetIPv6Capable(ctx, "nobody", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown peer: %v", err)
	}
	if err := s.Peers().Create(ctx, Peer{ID: "d", Name: "n-d", Kind: KindHuman, Mode: ModeAgent, PublicKey: "k-d",
		IPv4: "100.64.0.5", IPv6: "fd00::6440:3", CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate ipv6: %v", err)
	}
}
