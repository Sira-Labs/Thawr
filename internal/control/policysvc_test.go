package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sira-labs/thawr/internal/store"
)

type policyNotifier struct{ n int }

func (c *policyNotifier) Changed() { c.n++ }

func TestPolicyServiceReload(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	ctx := context.Background()
	mustUser(t, env.users, "alice", store.RoleMember)
	mustUser(t, env.users, "bob", store.RoleMember)
	a, _ := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice"}), "a1")
	b, _ := env.enroll(t, env.token(t, TokenRequest{OwnerName: "bob"}), "b1")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	notify := &policyNotifier{}
	svc := NewPolicyService(env.st, quietLogger(), path, notify)

	// Missing file: empty policy, nothing visible.
	if err := svc.LoadInitial(ctx); err != nil {
		t.Fatal(err)
	}
	if svc.Compiled(ctx).Visible(a.Peer.ID, b.Peer.ID) {
		t.Fatal("empty policy made peers visible")
	}
	gen0, _ := env.st.Meta().Generation(ctx)

	// Invalid file: rejected with the rule index, old policy kept.
	write(t, path, "version: 1\nacls:\n  - action: accept\n    src: [nobody]\n    dst: ['*:*']\n")
	rep, err := svc.Reload(ctx, LocalAdmin)
	if !errors.Is(err, ErrPolicyInvalid) || len(rep.Errors) != 1 || rep.Errors[0] != `acls[0].src[0]: unknown user "nobody"` {
		t.Fatalf("invalid reload: %v %+v", err, rep)
	}
	if gen, _ := env.st.Meta().Generation(ctx); gen != gen0 || notify.n != 0 || len(svc.Current().ACLs) != 0 {
		t.Fatalf("invalid reload changed state: gen %d->%d notify %d rules %d", gen0, gen, notify.n, len(svc.Current().ACLs))
	}

	// Valid file: installed, generation bumped, hub notified, compiled.
	write(t, path, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:22']\n  - action: accept\n    src: ['*']\n    dst: ['tag:prod:*']\n")
	rep, err = svc.Reload(ctx, LocalAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Rules != 2 || rep.Summary.VisiblePairs != 1 || len(rep.Warnings) != 1 || rep.Hash == "" {
		t.Fatalf("report: %+v", rep)
	}
	if gen, _ := env.st.Meta().Generation(ctx); gen != gen0+1 || notify.n != 1 {
		t.Fatalf("generation %d (was %d), notified %d", gen, gen0, notify.n)
	}
	c := svc.Compiled(ctx)
	if !c.Visible(a.Peer.ID, b.Peer.ID) || len(c.Allowed(a.Peer.ID, b.Peer.ID)) != 1 {
		t.Fatal("reloaded policy not in effect")
	}
	if svc.Compiled(ctx) != c {
		t.Error("compilation not cached")
	}
	// A registry change invalidates the cache.
	if _, err := env.enroll(t, env.token(t, TokenRequest{OwnerName: "alice", Tags: []string{"tag:prod"}}), "prod-1"); err != nil {
		t.Fatal(err)
	}
	if c2 := svc.Compiled(ctx); c2 == c || c2.Summary().Peers != 3 {
		t.Errorf("cache not refreshed after enrolment: %+v", c2.Summary())
	}
	if !svc.TagAllowed("nobody", "tag:prod") == false {
		t.Error("TagAllowed for unknown user")
	}
	show := svc.Show(ctx)
	if show.Hash != rep.Hash || show.Source == "" || show.Summary.Peers != 3 {
		t.Errorf("show: %+v", show)
	}

	// Check does not install.
	bad := svc.Check(ctx, []byte("version: 1\nacls:\n  - action: deny\n"))
	if len(bad.Errors) == 0 {
		t.Error("check accepted a deny rule")
	}
	good := svc.Check(ctx, []byte("version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['self:*']\n"))
	if len(good.Errors) != 0 || good.Summary.Rules != 1 || len(svc.Current().ACLs) != 2 {
		t.Errorf("check: %+v current rules %d", good, len(svc.Current().ACLs))
	}
}

func TestPolicyServiceInitialInvalid(t *testing.T) {
	env := newEnrollEnv(t, "100.64.0.0/10")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	write(t, path, "version: 1\nacls:\n  - action: accept\n    src: [ghost]\n    dst: ['*:*']\n")
	svc := NewPolicyService(env.st, quietLogger(), path, nil)
	if err := svc.LoadInitial(context.Background()); err == nil {
		t.Fatal("invalid initial policy accepted")
	}
}

func write(t *testing.T, path, doc string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}
