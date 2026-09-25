package control

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

type enrollEnv struct {
	st       *store.Store
	clk      *clock
	users    *Users
	tokens   *Tokens
	enroller *Enroller
	registry *Registry
	admin    Principal
}

func newEnrollEnv(t *testing.T, overlay string) *enrollEnv {
	t.Helper()
	st := openStore(t)
	clk := newClock()
	users, err := NewUsers(st, clk.Now, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	env := &enrollEnv{
		st:       st,
		clk:      clk,
		users:    users,
		tokens:   NewTokens(st, clk.Now, quietLogger()),
		enroller: NewEnroller(st, clk.Now, quietLogger(), netip.MustParsePrefix(overlay), ""),
		registry: NewRegistry(st, quietLogger()).WithOverlay(netip.MustParsePrefix(overlay)),
	}
	env.admin = asPrincipal(mustUser(t, users, "markus", store.RoleAdmin))
	return env
}

func (e *enrollEnv) token(t *testing.T, req TokenRequest) string {
	t.Helper()
	if req.OwnerName == "" {
		req.OwnerName = "markus"
	}
	if req.Kind == "" {
		req.Kind = "human"
	}
	c, err := e.tokens.Create(context.Background(), e.admin, req)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return c.Secret
}

func newPubKey(t *testing.T) string {
	t.Helper()
	k, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func (e *enrollEnv) enroll(t *testing.T, secret, hostname string) (EnrollResult, error) {
	t.Helper()
	return e.enroller.Enroll(context.Background(), EnrollRequest{
		Token: secret, PublicKey: newPubKey(t), Hostname: hostname, OS: "linux", Arch: "amd64", ClientVersion: "0.1.0",
	})
}

func TestEnrollAllocatesAndRecords(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	secret := env.token(t, TokenRequest{Tags: []string{"tag:dev"}})
	res, err := env.enroll(t, secret, "Alice's MacBook")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Peer.Name != "alice-s-macbook" || res.Peer.IPv4 != "100.64.0.2" || res.Peer.Mode != store.ModeAgent {
		t.Errorf("peer: %+v", res.Peer)
	}
	if res.NodeSecret == "" || res.Peer.NodeSecretHash != hashSecret(res.NodeSecret) || strings.Contains(res.Peer.NodeSecretHash, res.NodeSecret) {
		t.Error("node secret not hashed correctly")
	}
	if res.Generation != 1 {
		t.Errorf("generation %d, want 1", res.Generation)
	}
	stored, err := env.st.Peers().GetByNodeSecretHash(context.Background(), hashSecret(res.NodeSecret))
	if err != nil || stored.ID != res.Peer.ID {
		t.Errorf("lookup by node secret: %+v %v", stored, err)
	}
	if stored.ClientVersion != "0.1.0" || stored.OS != "linux/amd64" {
		t.Errorf("client info not persisted: %+v", stored)
	}
	res2, err := env.enroll(t, env.token(t, TokenRequest{}), "second")
	if err != nil || res2.Peer.IPv4 != "100.64.0.3" || res2.Generation != 2 {
		t.Errorf("second enroll: %+v %v", res2.Peer, err)
	}
}

func TestEnrollTokenErrors(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	used := env.token(t, TokenRequest{})
	if _, err := env.enroll(t, used, "h"); err != nil {
		t.Fatal(err)
	}
	expired := env.token(t, TokenRequest{TTL: time.Minute})
	env.clk.Advance(2 * time.Minute)
	cases := map[string]string{
		"used":      used,
		"expired":   expired,
		"unknown":   TokenPrefix + strings.Repeat("A", 43),
		"malformed": "not-a-token",
		"empty":     "",
	}
	for name, secret := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := env.enroll(t, secret, "h")
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("got %v, want ErrInvalidToken", err)
			}
			if err.Error() != ErrInvalidToken.Error() {
				t.Errorf("message must not reveal the reason: %q", err.Error())
			}
		})
	}
	if n, _ := env.st.Peers().Count(context.Background()); n != 1 {
		t.Errorf("rejected enrollments created peers: %d", n)
	}
}

func TestTokenSingleUse(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	secret := env.token(t, TokenRequest{})
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.enroll(t, secret, "racer")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrInvalidToken) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Errorf("token used %d times, want 1", wins)
	}
}

func TestNameDerivation(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	first, err := env.enroll(t, env.token(t, TokenRequest{}), "build-box")
	if err != nil || first.Peer.Name != "build-box" {
		t.Fatalf("first: %+v %v", first.Peer, err)
	}
	second, err := env.enroll(t, env.token(t, TokenRequest{}), "build-box")
	if err != nil || second.Peer.Name != "build-box-2" {
		t.Errorf("conflict suffix: %+v %v", second.Peer, err)
	}
	third, err := env.enroll(t, env.token(t, TokenRequest{}), "BUILD-BOX")
	if err != nil || third.Peer.Name != "build-box-3" {
		t.Errorf("case-insensitive conflict: %+v %v", third.Peer, err)
	}
	named, err := env.enroll(t, env.token(t, TokenRequest{PeerName: "from-token"}), "build-box")
	if err != nil || named.Peer.Name != "from-token" {
		t.Errorf("token name wins over hostname: %+v %v", named.Peer, err)
	}
	res, err := env.enroller.Enroll(context.Background(), EnrollRequest{
		Token: env.token(t, TokenRequest{PeerName: "from-token"}), PublicKey: newPubKey(t), Hostname: "x", Name: "explicit", ClientVersion: "0.1.0"})
	if err != nil || res.Peer.Name != "explicit" {
		t.Errorf("request name wins over token: %+v %v", res.Peer, err)
	}
	if _, err := env.enroller.Enroll(context.Background(), EnrollRequest{
		Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Hostname: "x", Name: "Not Valid", ClientVersion: "0.1.0"}); !errors.Is(err, ErrValidation) {
		t.Errorf("invalid requested name: %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"Alice's MacBook":       "alice-s-macbook",
		"--weird--":             "weird",
		"":                      "peer",
		"ÜBER host":             "ber-host",
		"a.b.c":                 "a-b-c",
		strings.Repeat("x", 80): strings.Repeat("x", 63),
	}
	for in, want := range cases {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnrollKindTagsFromToken(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	alice := mustUser(t, env.users, "alice", store.RoleMember)
	secret := env.token(t, TokenRequest{OwnerName: "alice", Kind: "server", Tags: []string{"tag:prod"}})
	res, err := env.enroll(t, secret, "host")
	if err != nil {
		t.Fatal(err)
	}
	if res.Peer.Kind != "server" || res.Peer.OwnerID != alice.ID || len(res.Peer.Tags) != 1 || res.Peer.Tags[0] != "tag:prod" {
		t.Errorf("peer identity not taken from token: %+v", res.Peer)
	}
}

func TestEnrollValidation(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	secret := env.token(t, TokenRequest{})
	if _, err := env.enroller.Enroll(context.Background(), EnrollRequest{Token: secret, PublicKey: "nope", Hostname: "h"}); !errors.Is(err, ErrValidation) {
		t.Errorf("bad key: %v", err)
	}
	if _, err := env.enroller.Enroll(context.Background(), EnrollRequest{Token: secret, PublicKey: newPubKey(t), Hostname: strings.Repeat("h", 64)}); !errors.Is(err, ErrValidation) {
		t.Errorf("long hostname: %v", err)
	}
}

func TestEnrollRateLimit(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	for i := 0; i < enrollMax; i++ {
		_, err := env.enroller.Enroll(ctx, EnrollRequest{Token: "bad", PublicKey: newPubKey(t), RemoteIP: "203.0.113.5"})
		if !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	_, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), RemoteIP: "203.0.113.5"})
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("11th attempt: got %v, want ErrRateLimited", err)
	}
	if _, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), RemoteIP: "203.0.113.6"}); err != nil {
		t.Errorf("other IP affected: %v", err)
	}
	env.clk.Advance(enrollWindow + time.Second)
	if _, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), RemoteIP: "203.0.113.5"}); err != nil {
		t.Errorf("after window: %v", err)
	}
}

func TestMinClientVersion(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.enroller.minVersion = "0.2"
	ctx := context.Background()
	cases := map[string]bool{"0.1.9": false, "0.2.0": true, "v0.3.1": true, "1.0.0": true, "dev": true, "91dcef8-dirty": true, "0.2": true}
	for version, ok := range cases {
		_, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Hostname: "h", ClientVersion: version})
		if ok && err != nil {
			t.Errorf("%s: unexpected %v", version, err)
		}
		if !ok && !errors.Is(err, ErrVersion) {
			t.Errorf("%s: got %v, want ErrVersion", version, err)
		}
	}
}

func TestAllocatorExhaustedInEnroll(t *testing.T) {
	env := newEnrollEnv(t, "10.0.0.0/30") // .1 hub, .2 the only peer, .3 broadcast
	if _, err := env.enroll(t, env.token(t, TokenRequest{}), "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.enroll(t, env.token(t, TokenRequest{}), "two"); !errors.Is(err, ErrExhausted) {
		t.Errorf("got %v, want ErrExhausted", err)
	}
}

func TestRegistry(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))
	if _, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "alice-box"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.enroll(t, env.token(t, TokenRequest{}), "admin-box"); err != nil {
		t.Fatal(err)
	}
	all, err := env.registry.List(ctx, env.admin)
	if err != nil || len(all) != 2 {
		t.Errorf("admin list: %d %v", len(all), err)
	}
	own, err := env.registry.List(ctx, alice)
	if err != nil || len(own) != 1 || own[0].Name != "alice-box" {
		t.Errorf("member list: %v %v", own, err)
	}
	if _, err := env.registry.Get(ctx, alice, "admin-box"); !errors.Is(err, ErrNotFound) {
		t.Errorf("member sees foreign peer: %v", err)
	}
	if err := env.registry.Rename(ctx, alice, "alice-box", "x"); !errors.Is(err, ErrForbidden) {
		t.Errorf("member rename: %v", err)
	}
	if err := env.registry.Rename(ctx, env.admin, "alice-box", "admin-box"); !errors.Is(err, ErrValidation) {
		t.Errorf("rename to taken: %v", err)
	}
	if err := env.registry.Rename(ctx, env.admin, "alice-box", "alice-laptop"); err != nil {
		t.Errorf("rename: %v", err)
	}
	before, _ := env.registry.Generation(ctx)
	if err := env.registry.Delete(ctx, env.admin, "alice-laptop"); err != nil {
		t.Errorf("delete: %v", err)
	}
	after, _ := env.registry.Generation(ctx)
	if after != before+1 {
		t.Errorf("delete did not bump generation: %d -> %d", before, after)
	}
	if err := env.registry.Delete(ctx, env.admin, "alice-laptop"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
	if err := env.registry.Delete(ctx, alice, "admin-box"); !errors.Is(err, ErrForbidden) {
		t.Errorf("member delete: %v", err)
	}
}

func TestCheckVersionPrefixes(t *testing.T) {
	for _, tc := range []struct {
		client, minimum string
		ok              bool
	}{
		{"v0.2.0", "0.2", true}, {"0.2.0", "0.2", true}, {"v0.1.9", "0.2", false}, {"0.1.9-3-gabc", "0.2", false},
		{"dev", "0.2", true}, {"v1.0.0", "0.9", true}, {"v0.9.9", "1.0", false}, {"0.3.0", "", true},
	} {
		err := checkVersion(tc.client, tc.minimum)
		if tc.ok != (err == nil) {
			t.Errorf("checkVersion(%q, %q) = %v, want ok=%v", tc.client, tc.minimum, err, tc.ok)
		}
	}
	for _, tc := range []struct {
		server, client string
		newer          bool
	}{
		{"v0.2.0", "0.1.0", true}, {"v0.2.0", "v0.2.5", false}, {"1.0.0", "0.9.9", true}, {"v0.1.0-rc1", "v0.1.0", false},
		{"dev", "0.1.0", false}, {"v0.2.0", "dev", false}, {"", "0.1.0", false},
	} {
		if got := NewerMajorMinor(tc.server, tc.client); got != tc.newer {
			t.Errorf("NewerMajorMinor(%q, %q) = %v, want %v", tc.server, tc.client, got, tc.newer)
		}
	}
}
