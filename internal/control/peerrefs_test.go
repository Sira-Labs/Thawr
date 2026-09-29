package control

import (
	"context"
	"errors"
	"strings"
	"testing"

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
