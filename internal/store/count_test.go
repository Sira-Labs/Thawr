package store

import (
	"context"
	"testing"
	"time"
)

func TestCounts(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	for i, k := range []string{KindHuman, KindHuman, KindAgent} {
		p := Peer{ID: "p" + string(rune('a'+i)), Name: "n" + string(rune('a'+i)), Kind: k, Mode: ModeAgent,
			PublicKey: "k" + string(rune('a'+i)), IPv4: "100.64.0." + string(rune('2'+i)), CreatedAt: time.Now().UTC()}
		if err := s.Peers().Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Peers().CountByKind(ctx)
	if err != nil || got[KindHuman] != 2 || got[KindAgent] != 1 || got[KindServer] != 0 {
		t.Errorf("CountByKind = %v, %v", got, err)
	}

	if n, err := s.Audit().Count(ctx); err != nil || n != 0 {
		t.Errorf("empty audit count = %d, %v", n, err)
	}
	if err := s.Audit().Append(ctx, AuditEntry{At: time.Now().UTC(), Actor: "local", ActorRole: RoleAdmin, Action: "x"}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Audit().Count(ctx); err != nil || n != 1 {
		t.Errorf("audit count = %d, %v", n, err)
	}
}
