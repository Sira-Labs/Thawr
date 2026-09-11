package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thedatadudech/thawr/internal/store"
)

func newHub(t *testing.T, st *store.Store, clk *clock) *Hub {
	t.Helper()
	h, err := NewHub(context.Background(), st, clk.Now, quietLogger(), HubOptions{Coalesce: 10 * time.Millisecond, OfflineAfter: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func waitWake(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no wake-up within 2s")
	}
}

func TestHubCoalesceAndSequence(t *testing.T) {
	st := openStore(t)
	clk := newClock()
	h := newHub(t, st, clk)
	if h.Generation() != 0 {
		t.Fatalf("initial generation %d", h.Generation())
	}
	ch, unsub := h.Subscribe("p")
	defer unsub()
	for i := 0; i < 5; i++ {
		h.Changed()
	}
	waitWake(t, ch)
	time.Sleep(30 * time.Millisecond)
	select {
	case <-ch:
		t.Error("burst produced a second wake-up")
	default:
	}
	if h.Generation() != 5 {
		t.Errorf("burst bumped sequence to %d, want 5 (one per change)", h.Generation())
	}
	// A persistent change moves the DB generation ahead of the
	// sequence; the sequence catches up instead of falling behind.
	for i := 0; i < 20; i++ {
		if _, err := st.Meta().IncrementGeneration(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	h.Changed()
	waitWake(t, ch)
	if h.Generation() != 20 {
		t.Errorf("sequence %d, want 20 after catching up", h.Generation())
	}
	unsub()
	h.Changed()
	time.Sleep(30 * time.Millisecond)
	select {
	case <-ch:
		t.Error("unsubscribed channel woke")
	default:
	}
}

func TestHubPresence(t *testing.T) {
	st := openStore(t)
	clk := newClock()
	h := newHub(t, st, clk)
	ch, unsub := h.Subscribe("watcher")
	defer unsub()
	h.Connected("p")
	waitWake(t, ch)
	if !h.Online("p") || h.OnlineCount() != 1 {
		t.Fatal("connected peer not online")
	}
	h.Disconnected("p")
	clk.Advance(30 * time.Second)
	h.Sweep()
	if !h.Online("p") {
		t.Error("peer went offline inside the grace period")
	}
	h.Connected("p") // reconnect within grace
	h.Disconnected("p")
	clk.Advance(91 * time.Second)
	h.Sweep()
	if h.Online("p") {
		t.Error("peer still online after grace period")
	}
	waitWake(t, ch)
	h.Forget("p")
	if h.OnlineCount() != 0 {
		t.Error("forgotten peer counted")
	}
}

func TestRegistryRotateLeaveTouch(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	res, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a2")

	p, err := env.registry.PeerByNodeSecret(ctx, res.NodeSecret)
	if err != nil || p.ID != res.Peer.ID {
		t.Errorf("PeerByNodeSecret: %+v %v", p, err)
	}
	if _, err := env.registry.PeerByNodeSecret(ctx, "wrong"); !errors.Is(err, ErrForbidden) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := env.registry.PeerByNodeSecret(ctx, ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("empty secret: %v", err)
	}

	before, _ := env.registry.Generation(ctx)
	newKey := newPubKey(t)
	gen, err := env.registry.RotateKey(ctx, res.Peer.ID, newKey, nil)
	if err != nil || gen != before+1 {
		t.Fatalf("RotateKey: gen %d (before %d) err %v", gen, before, err)
	}
	got, _ := env.st.Peers().GetByID(ctx, res.Peer.ID)
	if got.PublicKey != newKey {
		t.Error("key not rotated")
	}
	if _, err := env.registry.RotateKey(ctx, res.Peer.ID, other.Peer.PublicKey, nil); !errors.Is(err, ErrValidation) {
		t.Errorf("rotating to a key in use: %v", err)
	}
	if _, err := env.registry.RotateKey(ctx, res.Peer.ID, "junk", nil); !errors.Is(err, ErrValidation) {
		t.Errorf("rotating to junk: %v", err)
	}
	if _, err := env.registry.RotateKey(ctx, "missing", newPubKey(t), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotating missing peer: %v", err)
	}

	if err := env.registry.Touch(ctx, res.Peer.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := env.st.Peers().GetByID(ctx, res.Peer.ID); got.LastSeenAt == nil {
		t.Error("Touch did not set last_seen_at")
	}

	if err := env.registry.Leave(ctx, res.Peer.ID); err != nil {
		t.Fatalf("Leave: %v", err)
	}
	if err := env.registry.Leave(ctx, res.Peer.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Leave twice: %v", err)
	}
	if _, err := env.registry.PeerByNodeSecret(ctx, res.NodeSecret); !errors.Is(err, ErrForbidden) {
		t.Errorf("secret still valid after leave: %v", err)
	}
}

type countNotifier struct{ n int }

func (c *countNotifier) Changed() { c.n++ }

func TestNotifierCalledOnPersistentChanges(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	n := &countNotifier{}
	env.enroller.WithNotifier(n)
	env.registry.WithNotifier(n)
	mustUser(t, env.users, "alice", store.RoleMember)
	res, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.registry.Rename(ctx, env.admin, "a1", "a-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.registry.RotateKey(ctx, res.Peer.ID, newPubKey(t), nil); err != nil {
		t.Fatal(err)
	}
	if err := env.registry.Delete(ctx, env.admin, "a-one"); err != nil {
		t.Fatal(err)
	}
	if n.n != 4 {
		t.Errorf("notifier called %d times, want 4 (enroll, rename, rotate, delete)", n.n)
	}
}
