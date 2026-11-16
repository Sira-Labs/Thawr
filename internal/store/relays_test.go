package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func relayFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.Users().Create(ctx, User{ID: "u1", Name: "markus", Role: RoleAdmin, PasswordHash: "h", CreatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"p1", "p2"} {
		p := Peer{ID: id, Name: "box" + id, Kind: KindServer, Mode: ModeAgent, OwnerID: "u1", PublicKey: "K" + id + "=",
			IPv4: "100.64.0." + string(rune('2'+i)), NodeSecretHash: "h" + id, CreatedAt: now()}
		if err := s.Peers().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []Relay{
		{ID: "r1", Name: "riyadh-1", URL: "https://r1.example.com:443", TLSFingerprint: "sha256:aa", SecretHash: "s1", CreatedAt: now()},
		{ID: "r2", Name: "berlin-1", URL: "https://r2.example.com:443", TLSFingerprint: "sha256:bb", SecretHash: "s2", CreatedAt: now()},
	} {
		if err := s.Relays().Create(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	return s, ctx
}

func TestRelaysCRUD(t *testing.T) {
	s, ctx := relayFixture(t)
	list, err := s.Relays().List(ctx)
	if err != nil || len(list) != 2 || list[0].Name != "berlin-1" || list[1].Name != "riyadh-1" {
		t.Fatalf("list ordered by name: %+v %v", list, err)
	}
	dup := Relay{ID: "r3", Name: "riyadh-1", URL: "https://x:1", TLSFingerprint: "f", SecretHash: "s3", CreatedAt: now()}
	if err := s.Relays().Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	got, err := s.Relays().GetBySecretHash(ctx, "s1")
	if err != nil || got.ID != "r1" || got.LastSeenAt != nil {
		t.Fatalf("by secret hash: %+v %v", got, err)
	}
	if _, err := s.Relays().GetBySecretHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown secret hash: %v", err)
	}
	seen := now().Add(time.Minute)
	if err := s.Relays().Touch(ctx, "r1", seen); err != nil {
		t.Fatal(err)
	}
	if err := s.Relays().SetEndpoint(ctx, "r1", "https://new.example.com:8443", "sha256:cc", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	got, err = s.Relays().GetByName(ctx, "riyadh-1")
	if err != nil || got.URL != "https://new.example.com:8443" || got.TLSFingerprint != "sha256:cc" || got.Version != "0.2.0" ||
		got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
		t.Errorf("after update: %+v %v", got, err)
	}
	if err := s.Relays().Touch(ctx, "gone", seen); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch of a missing relay: %v", err)
	}
	if err := s.Relays().Delete(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Relays().Delete(ctx, "r1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if _, err := s.Relays().GetByID(ctx, "r1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete: %v", err)
	}
}

func TestRelayTokensOneTime(t *testing.T) {
	s, ctx := relayFixture(t)
	tok := RelayToken{ID: "rt_1", SecretHash: "th1", RelayName: "riyadh-2", CreatedBy: "markus", CreatedAt: now(), ExpiresAt: now().Add(time.Hour)}
	if err := s.RelayTokens().Create(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.RelayTokens().Create(ctx, tok); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate token: %v", err)
	}
	got, err := s.RelayTokens().GetByHash(ctx, "th1")
	if err != nil || got.RelayName != "riyadh-2" || got.UsedAt != nil || !got.ExpiresAt.Equal(tok.ExpiresAt) {
		t.Fatalf("get: %+v %v", got, err)
	}
	if err := s.RelayTokens().MarkUsed(ctx, "rt_1", "r1", now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RelayTokens().MarkUsed(ctx, "rt_1", "r2", now()); !errors.Is(err, ErrConflict) {
		t.Errorf("second use: %v", err)
	}
	got, _ = s.RelayTokens().GetByHash(ctx, "th1")
	if got.UsedAt == nil || got.UsedByRelayID != "r1" {
		t.Errorf("after use: %+v", got)
	}
	// The token outlives its relay, without pointing at it.
	if err := s.Relays().Delete(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.RelayTokens().GetByHash(ctx, "th1")
	if err != nil || got.UsedAt == nil || got.UsedByRelayID != "" {
		t.Errorf("after the relay is gone: %+v %v", got, err)
	}
	// An enrollment token's hash is not a relay token.
	if _, err := s.RelayTokens().GetByHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown hash: %v", err)
	}
}

func TestRelayTicketsExpire(t *testing.T) {
	s, ctx := relayFixture(t)
	put := func(hash, peer, relay string, ttl time.Duration) {
		t.Helper()
		if err := s.RelayTickets().Put(ctx, RelayTicket{TicketHash: hash, PeerID: peer, RelayID: relay, CreatedAt: now(), ExpiresAt: now().Add(ttl)}); err != nil {
			t.Fatal(err)
		}
	}
	put("a", "p1", "r1", time.Hour)
	put("b", "p1", "r2", 10*time.Minute)
	put("c", "p2", "r1", time.Hour)
	if err := s.RelayTickets().Put(ctx, RelayTicket{TicketHash: "a", PeerID: "p2", RelayID: "r2", CreatedAt: now(), ExpiresAt: now()}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate hash: %v", err)
	}
	if err := s.RelayTickets().Put(ctx, RelayTicket{TicketHash: "z", PeerID: "nobody", RelayID: "r1", CreatedAt: now(), ExpiresAt: now()}); err == nil {
		t.Error("a ticket for a peer that does not exist was stored")
	}
	got, err := s.RelayTickets().GetByHash(ctx, "b")
	if err != nil || got.PeerID != "p1" || got.RelayID != "r2" || !got.ExpiresAt.Equal(now().Add(10*time.Minute)) {
		t.Fatalf("get: %+v %v", got, err)
	}
	// Exactly at its expiry a ticket is gone; one second earlier it is not.
	if n, err := s.RelayTickets().DeleteExpired(ctx, now().Add(10*time.Minute-time.Second)); err != nil || n != 0 {
		t.Errorf("before expiry: %d %v", n, err)
	}
	if n, err := s.RelayTickets().DeleteExpired(ctx, now().Add(10*time.Minute)); err != nil || n != 1 {
		t.Errorf("at expiry: %d %v", n, err)
	}
	if _, err := s.RelayTickets().GetByHash(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired ticket still there: %v", err)
	}
}

func TestDeletePeerDeletesTickets(t *testing.T) {
	s, ctx := relayFixture(t)
	for hash, pr := range map[string][2]string{"a": {"p1", "r1"}, "b": {"p1", "r2"}, "c": {"p2", "r1"}, "d": {"p2", "r2"}} {
		if err := s.RelayTickets().Put(ctx, RelayTicket{TicketHash: hash, PeerID: pr[0], RelayID: pr[1], CreatedAt: now(), ExpiresAt: now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(hash string) bool {
		_, err := s.RelayTickets().GetByHash(ctx, hash)
		return errors.Is(err, ErrNotFound)
	}
	// Deleting the peer row takes its tickets along.
	if err := s.Peers().Delete(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if !gone("a") || !gone("b") || gone("c") || gone("d") {
		t.Errorf("after peer delete: a=%v b=%v c=%v d=%v", gone("a"), gone("b"), gone("c"), gone("d"))
	}
	// So does deleting the relay.
	if err := s.Relays().Delete(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	if !gone("c") || gone("d") {
		t.Errorf("after relay delete: c=%v d=%v", gone("c"), gone("d"))
	}
	// A key rotation removes the rest for that peer only.
	if n, err := s.RelayTickets().DeletePeer(ctx, "p2"); err != nil || n != 1 || !gone("d") {
		t.Errorf("delete by peer: %d %v gone=%v", n, err, gone("d"))
	}
}

// TestMigration0008 applies the relay tables to a database that stopped
// at schema version 7 and holds a peer.
func TestMigration0008(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	if err := s.Users().Create(ctx, User{ID: "u1", Name: "markus", Role: RoleAdmin, PasswordHash: "h", CreatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Peers().Create(ctx, Peer{ID: "p1", Name: "box", Kind: KindServer, Mode: ModeAgent, OwnerID: "u1", PublicKey: "K=", IPv4: "100.64.0.2", NodeSecretHash: "h1", CreatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{`DROP TABLE relay_tickets`, `DROP TABLE relay_tokens`, `DROP TABLE relays`} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Meta().Set(ctx, SchemaVersionKey, "7"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s.Close() }()
	if v, err := s.SchemaVersion(ctx); err != nil || v != 8 {
		t.Fatalf("schema version: %d %v", v, err)
	}
	if p, err := s.Peers().GetByID(ctx, "p1"); err != nil || p.Name != "box" {
		t.Errorf("peer after migration: %+v %v", p, err)
	}
	if err := s.Relays().Create(ctx, Relay{ID: "r1", Name: "riyadh-1", URL: "https://r:443", TLSFingerprint: "f", SecretHash: "s", CreatedAt: now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.RelayTickets().Put(ctx, RelayTicket{TicketHash: "a", PeerID: "p1", RelayID: "r1", CreatedAt: now(), ExpiresAt: now().Add(time.Hour)}); err != nil {
		t.Errorf("ticket on the migrated schema: %v", err)
	}
}
