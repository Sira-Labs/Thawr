package control

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

func TestHubWanted(t *testing.T) {
	clk := newClock()
	h := newHub(t, openStore(t), clk)
	chB, unsubB := h.Subscribe("b")
	defer unsubB()
	chC, unsubC := h.Subscribe("c")
	defer unsubC()
	h.Connected("b")
	h.Connected("c")
	waitWake(t, chB) // the coalesced wake-up of the presence change
	waitWake(t, chC)
	gen := h.Generation()

	// A peer without a stream cannot be woken and is not recorded, so
	// reported ids cannot grow the table.
	h.Want("nobody", "a")
	if h.Wanted("nobody", "a") {
		t.Error("request recorded for a peer without a stream")
	}

	h.Want("b", "a")
	waitWake(t, chB)
	select {
	case <-chC:
		t.Error("a peer that was not asked woke up")
	default:
	}
	if h.Generation() != gen {
		t.Errorf("a relay request bumped the generation to %d", h.Generation())
	}
	if !h.Wanted("b", "a") || h.Wanted("a", "b") || h.Wanted("b", "x") {
		t.Error("Wanted does not match the request")
	}
	// A second sender, never looked up again, to be pruned later.
	h.Want("b", "y")
	waitWake(t, chB)

	// A repeat inside wantRepeat refreshes without waking again, and
	// keeps its number: the receiver has acted on it already.
	seq := h.WantSeq("b", "a")
	if seq == 0 || seq == h.WantSeq("b", "y") {
		t.Errorf("request numbers a=%d y=%d, want distinct and non-zero", seq, h.WantSeq("b", "y"))
	}
	clk.Advance(time.Second)
	h.Want("b", "a")
	select {
	case <-chB:
		t.Error("repeated request woke the peer again")
	case <-time.After(30 * time.Millisecond):
	}
	if got := h.WantSeq("b", "a"); got != seq {
		t.Errorf("a repeat without a wake renumbered the request: %d -> %d", seq, got)
	}
	clk.Advance(wantRepeat)
	h.Want("b", "a")
	waitWake(t, chB)
	if got := h.WantSeq("b", "a"); got <= seq {
		t.Errorf("a repeat that woke the peer kept number %d (was %d)", got, seq)
	}
	// A sender repeating every second still wakes the target once per
	// wantRepeat: the gate counts from the last wake.
	for i := 1; i <= 2*int(wantRepeat/time.Second); i++ {
		clk.Advance(time.Second)
		h.Want("b", "a")
		woke := false
		select {
		case <-chB:
			woke = true
		case <-time.After(30 * time.Millisecond):
		}
		if want := i%int(wantRepeat/time.Second) == 0; woke != want {
			t.Errorf("request %d s after a wake: woke=%v, want %v", i, woke, want)
		}
	}

	// The request expires after wantTTL.
	clk.Advance(wantTTL - time.Second)
	if !h.Wanted("b", "a") {
		t.Error("request expired early")
	}
	clk.Advance(time.Second)
	if h.Wanted("b", "a") {
		t.Error("request outlived wantTTL")
	}

	// Expired requests are pruned when the next one arrives: y expired
	// with a and was never looked up.
	h.Want("b", "x")
	if _, kept := h.wants["b"]["y"]; kept || len(h.wants["b"]) != 1 {
		t.Errorf("requests kept for b: %v, want x only", h.wants["b"])
	}

	// Forgetting either side drops the request.
	h.Want("b", "a")
	h.Forget("a")
	if h.Wanted("b", "a") {
		t.Error("request survived forgetting its sender")
	}
	h.Want("b", "a")
	h.Forget("b")
	if h.Wanted("b", "a") {
		t.Error("request survived forgetting its target")
	}
}

type fakeWants map[[2]string]uint64

func (f fakeWants) WantSeq(to, from string) uint64 { return f[[2]string{to, from}] }

// TestHubWantSeqAcrossRestarts: a client keeps the last request number
// it saw across reconnects, so a restarted server must not number a new
// request the way the old one did.
func TestHubWantSeqAcrossRestarts(t *testing.T) {
	st := openStore(t)
	clk := newClock()
	seqAfterRestart := func() uint64 {
		t.Helper()
		h := newHub(t, st, clk)
		_, unsub := h.Subscribe("b")
		defer unsub()
		h.Connected("b")
		h.Want("b", "a")
		return h.WantSeq("b", "a")
	}
	first := seqAfterRestart()
	clk.Advance(time.Second)
	if second := seqAfterRestart(); second == first || second == 0 {
		t.Errorf("request numbers across a restart: %d then %d, want distinct", first, second)
	}
}

func TestNetMapWanted(t *testing.T) {
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
		WithWants(fakeWants{{a1.Peer.ID, a2.Peer.ID}: 7})

	nm, err := b.Build(ctx, a1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || !nm.Peers[0].Wanted || nm.Peers[0].WantSeq != 7 {
		t.Errorf("a1's map does not ask it to reach a2: %+v", nm.Peers)
	}
	nm, err = b.Build(ctx, a2.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 1 || nm.Peers[0].Wanted || nm.Peers[0].WantSeq != 0 {
		t.Errorf("a2's map carries a request nobody made: %+v", nm.Peers)
	}
}
