package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

func newTokenEnv(t *testing.T) (*Tokens, *Users, *clock) {
	t.Helper()
	st := openStore(t)
	clk := newClock()
	users, err := NewUsers(st, clk.Now, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	return NewTokens(st, clk.Now, quietLogger()), users, clk
}

func TestTokenCreateAndHash(t *testing.T) {
	tokens, users, clk := newTokenEnv(t)
	ctx := context.Background()
	admin := mustUser(t, users, "markus", store.RoleAdmin)
	created, err := tokens.Create(ctx, asPrincipal(admin), TokenRequest{OwnerName: "markus", Kind: "human", Tags: []string{"tag:dev", "tag:dev"}, PeerName: "laptop"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(created.Secret, TokenPrefix) || len(created.Secret) != len(TokenPrefix)+43 {
		t.Errorf("secret format: %q", created.Secret)
	}
	if !strings.HasPrefix(created.Token.ID, "tk_") || len(created.Token.ID) != 3+tokenIDLen {
		t.Errorf("id format: %q", created.Token.ID)
	}
	if created.Token.SecretHash != hashSecret(created.Secret) || strings.Contains(created.Token.SecretHash, created.Secret) {
		t.Error("stored hash is not SHA-256 of the secret")
	}
	if got, want := created.Token.ExpiresAt, clk.Now().Add(DefaultTokenTTL); !got.Equal(want) {
		t.Errorf("default expiry %v, want %v", got, want)
	}
	if len(created.Token.Tags) != 1 || created.Token.PeerName != "laptop" || created.Token.OwnerID != admin.ID {
		t.Errorf("token fields: %+v", created.Token)
	}
	list, err := tokens.List(ctx, asPrincipal(admin))
	if err != nil || len(list) != 1 {
		t.Errorf("List: %v %v", list, err)
	}
	if err := tokens.Revoke(ctx, asPrincipal(admin), created.Token.ID); err != nil {
		t.Errorf("Revoke: %v", err)
	}
	if err := tokens.Revoke(ctx, asPrincipal(admin), created.Token.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke twice: %v", err)
	}
}

func TestTokenExpiryBounds(t *testing.T) {
	tokens, users, clk := newTokenEnv(t)
	ctx := context.Background()
	admin := asPrincipal(mustUser(t, users, "markus", store.RoleAdmin))
	if _, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "server", TTL: MaxTokenTTL + time.Second}); !errors.Is(err, ErrValidation) {
		t.Errorf("over max: %v", err)
	}
	if _, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "server", TTL: -time.Second}); !errors.Is(err, ErrValidation) {
		t.Errorf("negative: %v", err)
	}
	c, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "server", TTL: MaxTokenTTL})
	if err != nil || !c.Token.ExpiresAt.Equal(clk.Now().Add(MaxTokenTTL)) {
		t.Errorf("max ttl: %v %v", c.Token.ExpiresAt, err)
	}
}

func TestMemberTokenOwnerRestriction(t *testing.T) {
	tokens, users, _ := newTokenEnv(t)
	ctx := context.Background()
	mustUser(t, users, "markus", store.RoleAdmin)
	alice := asPrincipal(mustUser(t, users, "alice", store.RoleMember))
	if _, err := tokens.Create(ctx, alice, TokenRequest{OwnerName: "markus", Kind: "human"}); !errors.Is(err, ErrForbidden) {
		t.Errorf("member for other owner: %v", err)
	}
	own, err := tokens.Create(ctx, alice, TokenRequest{OwnerName: "alice", Kind: "human"})
	if err != nil {
		t.Fatalf("member for self: %v", err)
	}
	adminTok, err := tokens.Create(ctx, LocalAdmin, TokenRequest{OwnerName: "markus", Kind: "agent"})
	if err != nil {
		t.Fatalf("local admin: %v", err)
	}
	list, err := tokens.List(ctx, alice)
	if err != nil || len(list) != 1 || list[0].ID != own.Token.ID {
		t.Errorf("member sees only own tokens: %v %v", list, err)
	}
	if err := tokens.Revoke(ctx, alice, adminTok.Token.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("member revoking foreign token: %v", err)
	}
	if _, err := tokens.Create(ctx, LocalAdmin, TokenRequest{OwnerName: "ghost", Kind: "human"}); !errors.Is(err, ErrValidation) {
		t.Errorf("unknown owner: %v", err)
	}
}

func TestTokenTagAndKindValidation(t *testing.T) {
	tokens, users, _ := newTokenEnv(t)
	ctx := context.Background()
	admin := asPrincipal(mustUser(t, users, "markus", store.RoleAdmin))
	for _, bad := range [][]string{{"dev"}, {"tag:"}, {"tag:Prod"}, {"tag:a b"}} {
		if _, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "human", Tags: bad}); !errors.Is(err, ErrValidation) {
			t.Errorf("tags %v: %v", bad, err)
		}
	}
	if _, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "robot"}); !errors.Is(err, ErrValidation) {
		t.Errorf("bad kind: %v", err)
	}
	if _, err := tokens.Create(ctx, admin, TokenRequest{OwnerName: "markus", Kind: "human", PeerName: "Bad Name"}); !errors.Is(err, ErrValidation) {
		t.Errorf("bad peer name: %v", err)
	}
}
