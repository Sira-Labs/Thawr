package control

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/thedatadudech/thawr/internal/control/policy"
	"github.com/thedatadudech/thawr/internal/store"
)

// TestPolicyVisibilityNetMap: with a compiled policy the netmap carries
// only visible peers and the receiver-side filter rules for them.
func TestPolicyVisibilityNetMap(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	mustUser(t, env.users, "bob", store.RoleMember)
	a1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	if err != nil {
		t.Fatal(err)
	}
	b1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "bob"}), "b1")
	if err != nil {
		t.Fatal(err)
	}
	m1, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "markus"}), "m1")
	if err != nil {
		t.Fatal(err)
	}
	doc := "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:22,80-90']\n    proto: tcp\n"
	pol, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	peers, _ := env.st.Peers().List(ctx)
	users, _ := env.users.List(ctx)
	names := map[string]string{}
	for _, u := range users {
		names[u.ID] = u.Name
	}
	compiled := policy.Compile(pol, PolicyPeers(peers, names, nil))
	vis := PolicyVisibility{Load: func() *policy.Compiled { return compiled }}
	hub := HubConfig{PublicKey: "HUB", Address: netip.MustParseAddr("100.64.0.1"), Overlay: netip.MustParsePrefix("100.64.0.0/10")}
	b := NewNetMapBuilder(env.st, vis, nil, nil, hub, func() int64 { return 1 })

	nmB, err := b.Build(ctx, b1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nmB.Peers) != 1 || nmB.Peers[0].ID != a1.Peer.ID {
		t.Fatalf("bob's netmap peers: %+v", nmB.Peers)
	}
	if len(nmB.Filter) != 2 || nmB.Filter[0].SrcIPv4.String() != a1.Peer.IPv4 || nmB.Filter[0].Proto != "tcp" || nmB.Filter[0].PortLo != 22 || nmB.Filter[1].PortHi != 90 {
		t.Fatalf("bob's filter: %+v", nmB.Filter)
	}
	nmA, err := b.Build(ctx, a1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nmA.Peers) != 1 || nmA.Peers[0].ID != b1.Peer.ID || len(nmA.Filter) != 0 {
		t.Fatalf("alice's netmap: peers %+v filter %+v (bob may not initiate)", nmA.Peers, nmA.Filter)
	}
	nmM, err := b.Build(ctx, m1.Peer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(nmM.Peers) != 0 || nmM.Hub.PublicKey != "HUB" {
		t.Fatalf("markus has no rule but sees %+v", nmM.Peers)
	}
	// No compilation yet: nothing is visible.
	none := PolicyVisibility{Load: func() *policy.Compiled { return nil }}
	if none.Visible(a1.Peer, b1.Peer) || none.FilterFor(b1.Peer) != nil {
		t.Error("nil compilation made peers visible")
	}
}

func TestTokenTagOwnership(t *testing.T) {
	tokens, users, _ := newTokenEnv(t)
	ctx := context.Background()
	mustUser(t, users, "markus", store.RoleAdmin)
	alice := asPrincipal(mustUser(t, users, "alice", store.RoleMember))
	// Without a policy check members cannot tag at all; admins can.
	if _, err := tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "server", Tags: []string{"tag:prod"}}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member tagged without tagOwners: %v", err)
	}
	if _, err := tokens.Create(ctx, LocalAdmin, TokenRequest{OwnerName: "markus", Kind: "server", Tags: []string{"tag:prod"}}); err != nil {
		t.Errorf("admin tag: %v", err)
	}
	tokens.WithTagAllowed(func(user, tag string) bool { return user == "alice" && tag == "tag:ci" })
	if _, err := tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "server", Tags: []string{"tag:ci"}}); err != nil {
		t.Errorf("owned tag refused: %v", err)
	}
	if _, err := tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "server", Tags: []string{"tag:ci", "tag:prod"}}); !errors.Is(err, ErrForbidden) {
		t.Errorf("unowned tag accepted: %v", err)
	}
}
