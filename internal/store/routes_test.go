package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRoutesReplaceApproveCascade(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	if err := s.Users().Create(ctx, User{ID: "u1", Name: "markus", Role: RoleAdmin, PasswordHash: "h", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	p := Peer{ID: "p1", Name: "gw", Kind: KindServer, Mode: ModeAgent, OwnerID: "u1", PublicKey: "K1=", IPv4: "100.64.0.2", NodeSecretHash: "h1", CreatedAt: now}
	if err := s.Peers().Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	added, removed, err := s.Routes().Replace(ctx, "p1", []string{"10.1.0.0/24", "0.0.0.0/0"}, now)
	if err != nil || len(added) != 2 || len(removed) != 0 {
		t.Fatalf("first replace: added %v removed %v err %v", added, removed, err)
	}
	if err := s.Routes().SetApproved(ctx, "p1", "10.1.0.0/24", "markus", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Routes().SetApproved(ctx, "p1", "10.9.0.0/24", "markus", true, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("approve of an unadvertised prefix: %v", err)
	}
	rows, err := s.Routes().ListPeer(ctx, "p1")
	if err != nil || len(rows) != 2 {
		t.Fatalf("list: %v %v", rows, err)
	}
	// Ordered by prefix text: "0.0.0.0/0" sorts before "10.1.0.0/24".
	if rows[0].Prefix != "0.0.0.0/0" || rows[0].Approved || rows[1].Prefix != "10.1.0.0/24" || !rows[1].Approved || rows[1].ApprovedBy != "markus" || !rows[1].ApprovedAt.Equal(now) {
		t.Errorf("rows: %+v", rows)
	}
	// Re-advertising the same set changes nothing and keeps the approval.
	added, removed, err = s.Routes().Replace(ctx, "p1", []string{"0.0.0.0/0", "10.1.0.0/24"}, now.Add(time.Hour))
	if err != nil || len(added) != 0 || len(removed) != 0 {
		t.Fatalf("same set: added %v removed %v err %v", added, removed, err)
	}
	if rows, _ = s.Routes().ListPeer(ctx, "p1"); !rows[1].Approved {
		t.Errorf("approval lost on re-advertise: %+v", rows)
	}
	// Withdrawing and advertising again drops the approval.
	if _, removed, err = s.Routes().Replace(ctx, "p1", []string{"0.0.0.0/0"}, now); err != nil || len(removed) != 1 || removed[0] != "10.1.0.0/24" {
		t.Fatalf("withdraw: removed %v err %v", removed, err)
	}
	if added, _, err = s.Routes().Replace(ctx, "p1", []string{"0.0.0.0/0", "10.1.0.0/24"}, now); err != nil || len(added) != 1 {
		t.Fatalf("re-advertise: added %v err %v", added, err)
	}
	if rows, _ = s.Routes().ListPeer(ctx, "p1"); rows[1].Approved {
		t.Errorf("approval survived a withdraw: %+v", rows)
	}
	if err := s.Routes().SetApproved(ctx, "p1", "0.0.0.0/0", "markus", true, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Routes().SetApproved(ctx, "p1", "0.0.0.0/0", "", false, now); err != nil {
		t.Fatal(err)
	}
	if rows, _ = s.Routes().ListPeer(ctx, "p1"); rows[0].Approved || rows[0].ApprovedBy != "" {
		t.Errorf("revoke: %+v", rows[0])
	}
	all, err := s.Routes().ListAll(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list all: %v %v", all, err)
	}
	// Deleting the peer removes its routes (foreign key cascade).
	if err := s.Peers().Delete(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if all, _ = s.Routes().ListAll(ctx); len(all) != 0 {
		t.Errorf("routes survived the peer: %+v", all)
	}
}
