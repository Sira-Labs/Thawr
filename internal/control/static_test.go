package control

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

func TestCreateStatic(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	n := &countNotifier{}
	env.registry.WithNotifier(n)
	mustUser(t, env.users, "alice", store.RoleMember)
	if _, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "alice-box"); err != nil {
		t.Fatal(err)
	}
	res, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "alice", Name: "alice-phone", Tags: []string{"tag:phones"}})
	if err != nil {
		t.Fatalf("CreateStatic: %v", err)
	}
	p := res.Peer
	if p.Mode != store.ModeStatic || p.Kind != store.KindHuman || p.IPv4 != "100.64.0.3" || p.NodeSecretHash != "" || len(p.Tags) != 1 || p.OS != "wireguard-app" {
		t.Errorf("peer: %+v", p)
	}
	if p.PublicKey != res.PrivateKey.PublicKey().String() || res.PrivateKey == (wg.Key{}) {
		t.Error("public key does not match the returned private key")
	}
	if res.Generation != 2 || n.n != 1 {
		t.Errorf("generation %d notified %d, want 2 and 1", res.Generation, n.n)
	}
	stored, err := env.st.Peers().GetByName(ctx, "alice-phone")
	if err != nil || stored.ID != p.ID || stored.OwnerID == "" {
		t.Errorf("stored: %+v %v", stored, err)
	}
	// Names and addresses stay unique; a re-add after delete gets a new key.
	if _, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "alice", Name: "alice-phone"}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	if err := env.registry.Delete(ctx, env.admin, "alice-phone"); err != nil {
		t.Fatal(err)
	}
	again, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "alice", Name: "alice-phone"})
	if err != nil || again.PrivateKey == res.PrivateKey || again.Peer.ID == p.ID {
		t.Errorf("re-add: %+v %v", again.Peer, err)
	}
	// Validation.
	for _, bad := range []StaticRequest{
		{OwnerName: "alice"},
		{OwnerName: "alice", Name: "Bad Name"},
		{OwnerName: "ghost", Name: "x"},
		{OwnerName: "alice", Name: "x", Kind: "robot"},
		{OwnerName: "alice", Name: "x", Tags: []string{"prod"}},
	} {
		if _, err := env.registry.CreateStatic(ctx, env.admin, bad); !errors.Is(err, ErrValidation) {
			t.Errorf("%+v: %v, want validation error", bad, err)
		}
	}
}

func TestMobileTagOwners(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))
	env.registry.WithTagAllowed(func(user, tag string) bool { return user == "alice" && tag == "tag:phones" })
	if _, err := env.registry.CreateStatic(ctx, alice, StaticRequest{OwnerName: "markus", Name: "p1"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member for another owner: %v", err)
	}
	if _, err := env.registry.CreateStatic(ctx, alice, StaticRequest{OwnerName: "alice", Name: "p2", Tags: []string{"tag:prod"}}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member with ungranted tag: %v", err)
	}
	if _, err := env.registry.CreateStatic(ctx, alice, StaticRequest{OwnerName: "alice", Name: "p3", Tags: []string{"tag:phones"}}); err != nil {
		t.Errorf("member with granted tag: %v", err)
	}
	if _, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "alice", Name: "p4", Tags: []string{"tag:prod"}}); err != nil {
		t.Errorf("admin with any tag: %v", err)
	}
}

// TestMobileKeyNotPersisted: the private key is in the result only, not
// in the database file and not in the log.
func TestMobileKeyNotPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	clk := newClock()
	users, err := NewUsers(st, clk.Now, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	admin := asPrincipal(mustUser(t, users, "markus", store.RoleAdmin))
	var logs bytes.Buffer
	reg := NewRegistry(st, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))).WithOverlay(netip.MustParsePrefix("100.64.0.0/10"))
	res, err := reg.CreateStatic(context.Background(), admin, StaticRequest{OwnerName: "markus", Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	priv := res.PrivateKey.String()
	if strings.Contains(logs.String(), priv) || !strings.Contains(logs.String(), "static peer created") {
		t.Errorf("log leaks the key or lacks the event:\n%s", logs.String())
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(priv)) || bytes.Contains(raw, res.PrivateKey[:]) {
		t.Error("database contains the private key")
	}
	if !bytes.Contains(raw, []byte(res.Peer.PublicKey)) {
		t.Error("database lacks the public key")
	}
}
