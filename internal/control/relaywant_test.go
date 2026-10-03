package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

func TestHubRelayWanted(t *testing.T) {
	clk := newClock()
	h := newHub(t, openStore(t), clk)
	chB, unsubB := h.Subscribe("b")
	defer unsubB()
	chC, unsubC := h.Subscribe("c")
	defer unsubC()
	gen := h.Generation()

	h.WantRelay("b", "a")
	waitWake(t, chB)
	select {
	case <-chC:
		t.Error("a peer that was not asked woke up")
	default:
	}
	if h.Generation() != gen {
		t.Errorf("a relay request bumped the generation to %d", h.Generation())
	}
	if !h.RelayWanted("b", "a") || h.RelayWanted("a", "b") || h.RelayWanted("b", "x") {
		t.Error("RelayWanted does not match the request")
	}

	// A repeat inside relayWantRepeat refreshes without waking again.
	clk.Advance(time.Second)
	h.WantRelay("b", "a")
	select {
	case <-chB:
		t.Error("repeated request woke the peer again")
	case <-time.After(30 * time.Millisecond):
	}
	clk.Advance(relayWantRepeat)
	h.WantRelay("b", "a")
	waitWake(t, chB)

	// The request expires after relayWantTTL.
	clk.Advance(relayWantTTL - time.Second)
	if !h.RelayWanted("b", "a") {
		t.Error("request expired early")
	}
	clk.Advance(time.Second)
	if h.RelayWanted("b", "a") {
		t.Error("request outlived relayWantTTL")
	}

	// Forgetting either side drops the request.
	h.WantRelay("b", "a")
	h.Forget("a")
	if h.RelayWanted("b", "a") {
		t.Error("request survived forgetting its sender")
	}
	h.WantRelay("b", "a")
	h.Forget("b")
	if h.RelayWanted("b", "a") {
		t.Error("request survived forgetting its target")
	}
}

type fakeRelayWants map[[2]string]bool

func (f fakeRelayWants) RelayWanted(to, from string) bool { return f[[2]string{to, from}] }

func TestNetMapRelayWanted(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	a1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a2")
	if err != nil {
		t.Fatal(err)
	}
	hub := HubConfig{PublicKey: "HUBKEY", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	b := NewNetMapBuilder(env.st, OwnerVisibility{}, nil, nil, hub, func() int64 { return 1 }).
		WithRelayWants(fakeRelayWants{{a1.Peer.ID, a2.Peer.ID}: true})

	nm, err := b.Build(ctx, a1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || !nm.Peers[0].RelayWanted {
		t.Errorf("a1's map does not ask it to reach a2: %+v", nm.Peers)
	}
	nm, err = b.Build(ctx, a2.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].RelayWanted {
		t.Errorf("a2's map carries a request nobody made: %+v", nm.Peers)
	}
}
