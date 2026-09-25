package control

import (
	"context"
	"testing"

	"github.com/sira-labs/thawr/internal/store"
)

func TestKeyVisibility(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	mustUser(t, env.users, "bob", store.RoleMember)
	a1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a2")
	if err != nil {
		t.Fatal(err)
	}
	b1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "bob"}), "b1")
	if err != nil {
		t.Fatal(err)
	}
	gen := int64(1)
	vis := NewKeyVisibility(env.st, OwnerVisibility{}, func() int64 { return gen })
	check := func(src, dst string, want bool) {
		t.Helper()
		got, err := vis.Visible(ctx, src, dst)
		if err != nil || got != want {
			t.Errorf("Visible(%s, %s) = %v, %v; want %v", src[:6], dst[:6], got, err, want)
		}
	}
	check(a1.Peer.PublicKey, a2.Peer.PublicKey, true)
	check(a2.Peer.PublicKey, a1.Peer.PublicKey, true)
	check(a1.Peer.PublicKey, b1.Peer.PublicKey, false)
	check(a1.Peer.PublicKey, "unknown", false)
	check("unknown", a1.Peer.PublicKey, false)

	// The cache holds until the generation moves.
	if err := env.st.Peers().Delete(ctx, a2.Peer.ID); err != nil {
		t.Fatal(err)
	}
	check(a1.Peer.PublicKey, a2.Peer.PublicKey, true)
	gen++
	check(a1.Peer.PublicKey, a2.Peer.PublicKey, false)
}
