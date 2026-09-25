package control

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

// clock is an injectable, advanceable time source for tests.
type clock struct{ t time.Time }

func newClock() *clock { return &clock{t: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustUser(t *testing.T, users *Users, name, role string) store.User {
	t.Helper()
	u, err := users.Create(context.Background(), LocalAdmin, name, role, "correct horse battery")
	if err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	return u
}

func asPrincipal(u store.User) Principal {
	return Principal{UserID: u.ID, Name: u.Name, Role: u.Role}
}
