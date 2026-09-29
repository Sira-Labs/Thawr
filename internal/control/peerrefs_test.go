package control

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

// policyRefs stands in for the running policy: it selects the listed
// names with peer:<name>.
func policyRefs(names ...string) PeerRefs {
	return func(name string) []string {
		for _, n := range names {
			if n == name {
				return []string{"acls[0].dst[0]"}
			}
		}
		return nil
	}
}

func TestRenameRefusesPolicySelectedName(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.registry.WithPeerRefs(policyRefs("db"))
	if _, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Name: "db", ClientVersion: "0.1.0"}); err != nil {
		t.Fatalf("enroll db: %v", err)
	}

	err := env.registry.Rename(ctx, env.admin, "db", "db-old", false)
	if !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "peer:db") || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("Rename without force = %v, want a validation error naming peer:db and --force", err)
	}
	if _, err := env.st.Peers().GetByName(ctx, "db"); err != nil {
		t.Fatalf("refused rename changed the peer: %v", err)
	}
	if err := env.registry.Rename(ctx, env.admin, "db", "db-old", true); err != nil {
		t.Fatalf("Rename with force: %v", err)
	}
	// A name the policy does not select renames without force.
	if err := env.registry.Rename(ctx, env.admin, "db-old", "archive", false); err != nil {
		t.Fatalf("Rename of an unselected name: %v", err)
	}
}

func TestMemberCannotIssueTokenForPolicySelectedName(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.tokens.WithPeerRefs(policyRefs("db"))
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))

	_, err := env.tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "human", PeerName: "db"})
	if !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "peer:db") {
		t.Fatalf("member token for db = %v, want ErrForbidden naming peer:db", err)
	}
	if _, err := env.tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "human", PeerName: "alice-box"}); err != nil {
		t.Fatalf("member token for an unselected name: %v", err)
	}
	if _, err := env.tokens.Create(ctx, env.admin, TokenRequest{OwnerName: "alice", Kind: "human", PeerName: "db"}); err != nil {
		t.Fatalf("admin token for db: %v", err)
	}
}

func TestEnrollDoesNotTakePolicySelectedName(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.enroller.WithPeerRefs(policyRefs("db", "db-2"))

	cases := []struct {
		name string
		req  func() EnrollRequest
		want string
	}{
		{"requested name", func() EnrollRequest {
			return EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Name: "db", ClientVersion: "0.1.0"}
		}, "db-3"},
		{"hostname", func() EnrollRequest {
			return EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Hostname: "DB", ClientVersion: "0.1.0"}
		}, "db-4"},
		{"token issued for the name", func() EnrollRequest {
			return EnrollRequest{Token: env.token(t, TokenRequest{PeerName: "db"}), PublicKey: newPubKey(t), ClientVersion: "0.1.0"}
		}, "db"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := env.enroller.Enroll(ctx, tc.req())
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			if res.Peer.Name != tc.want {
				t.Errorf("name = %q, want %q", res.Peer.Name, tc.want)
			}
		})
	}
}

func TestHubNameIsReserved(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")

	res, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Hostname: "hub", ClientVersion: "0.1.0"})
	if err != nil || res.Peer.Name != "hub-2" {
		t.Fatalf("enrol a host called hub: name %q, err %v; want hub-2", res.Peer.Name, err)
	}
	if _, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Name: "hub", ClientVersion: "0.1.0"}); !errors.Is(err, ErrValidation) {
		t.Errorf("enrol --name hub = %v, want ErrValidation", err)
	}
	if _, err := env.tokens.Create(ctx, env.admin, TokenRequest{OwnerName: "markus", Kind: "human", PeerName: "hub"}); !errors.Is(err, ErrValidation) {
		t.Errorf("token for hub = %v, want ErrValidation", err)
	}
	if err := env.registry.Rename(ctx, env.admin, "hub-2", "hub", true); !errors.Is(err, ErrValidation) {
		t.Errorf("rename to hub = %v, want ErrValidation", err)
	}
	if _, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "markus", Name: "hub"}); !errors.Is(err, ErrValidation) {
		t.Errorf("static peer hub = %v, want ErrValidation", err)
	}
}

// A member's token for a name the policy did not select yet cannot take
// the name once a reload selects it: enrolment checks the policy then
// in force and who issued the token.
func TestEnrollChecksPolicyAtRedeem(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))
	selected := false
	refs := func(name string) []string {
		if selected && name == "db" {
			return []string{"acls[0].dst[0]"}
		}
		return nil
	}
	env.tokens.WithPeerRefs(refs)
	env.enroller.WithPeerRefs(refs)

	member, err := env.tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "human", PeerName: "db"})
	if err != nil {
		t.Fatalf("member token before the policy selects db: %v", err)
	}
	admin := env.token(t, TokenRequest{PeerName: "db"})
	selected = true // the policy is reloaded with peer:db

	res, err := env.enroller.Enroll(ctx, EnrollRequest{Token: member.Secret, PublicKey: newPubKey(t), ClientVersion: "0.1.0"})
	if err != nil || res.Peer.Name == "db" {
		t.Fatalf("member token took db after the reload: name %q, err %v", res.Peer.Name, err)
	}
	res, err = env.enroller.Enroll(ctx, EnrollRequest{Token: admin, PublicKey: newPubKey(t), ClientVersion: "0.1.0"})
	if err != nil || res.Peer.Name != "db" {
		t.Errorf("admin token for db: name %q, err %v; want db", res.Peer.Name, err)
	}
}

func TestMemberCannotAddStaticPeerWithPolicySelectedName(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.registry.WithPeerRefs(policyRefs("db"))
	alice := asPrincipal(mustUser(t, env.users, "alice", store.RoleMember))

	if _, err := env.registry.CreateStatic(ctx, alice, StaticRequest{OwnerName: "alice", Name: "db"}); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "peer:db") {
		t.Errorf("member static peer db = %v, want ErrForbidden naming peer:db", err)
	}
	if _, err := env.registry.CreateStatic(ctx, alice, StaticRequest{OwnerName: "alice", Name: "alice-phone"}); err != nil {
		t.Errorf("member static peer with an unselected name: %v", err)
	}
	if _, err := env.registry.CreateStatic(ctx, env.admin, StaticRequest{OwnerName: "alice", Name: "db"}); err != nil {
		t.Errorf("admin static peer db: %v", err)
	}
}

func TestRenameToSameNameIsNoOp(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	env.registry.WithPeerRefs(policyRefs("db"))
	if _, err := env.enroller.Enroll(ctx, EnrollRequest{Token: env.token(t, TokenRequest{PeerName: "db"}), PublicKey: newPubKey(t), ClientVersion: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	before, err := env.st.Meta().Generation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.registry.Rename(ctx, env.admin, "db", "db", false); err != nil {
		t.Fatalf("rename to the same name: %v", err)
	}
	if after, _ := env.st.Meta().Generation(ctx); after != before {
		t.Errorf("generation %d -> %d on a no-op rename", before, after)
	}
}

// TestEnrollWhileCompiling: enrolment asks the running policy for its
// peer names inside a store transaction, which holds the store's only
// connection, while netmap builds compile the policy against the
// registry. Neither may wait on the other.
func TestEnrollWhileCompiling(t *testing.T) {
	ctx := context.Background()
	env := newEnrollEnv(t, "100.64.0.0/10")
	ps := NewPolicyService(env.st, quietLogger(), "", nil)
	env.enroller.WithPeerRefs(ps.PeerRefs)
	env.registry.WithPeerRefs(ps.PeerRefs)

	stop := make(chan struct{})
	compiling := make(chan struct{})
	go func() {
		defer close(compiling)
		for {
			select {
			case <-stop:
				return
			default:
				ps.Compiled(ctx)
			}
		}
	}()
	const rounds = 40
	reqs := make([]EnrollRequest, rounds)
	for i := range reqs {
		reqs[i] = EnrollRequest{Token: env.token(t, TokenRequest{}), PublicKey: newPubKey(t), Name: "box", ClientVersion: "0.1.0"}
	}
	done := make(chan error, 1)
	go func() {
		for i, req := range reqs {
			if _, err := env.enroller.Enroll(ctx, req); err != nil {
				done <- fmt.Errorf("enroll %d: %w", i, err)
				return
			}
			if err := env.registry.Rename(ctx, env.admin, "box", fmt.Sprintf("box-r%d", i), false); err != nil {
				done <- fmt.Errorf("rename %d: %w", i, err)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		close(stop)
		<-compiling
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("enrolment and policy compilation deadlocked")
	}
}
