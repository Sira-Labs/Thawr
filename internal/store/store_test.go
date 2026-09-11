package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "thawr.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestMigrateFresh(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != 4 {
		t.Errorf("schema version: got %d, want 4", v)
	}
	for _, table := range []string{"meta", "users", "peers", "enrollment_tokens", "audit_log", "peer_signatures"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s missing (n=%d, err=%v)", table, n, err)
		}
	}
	gen, err := s.Meta().Get(ctx, MetaNetmapGeneration)
	if err != nil || gen != "0" {
		t.Errorf("netmap_generation: got %q, %v; want \"0\"", gen, err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	if err := s.Meta().Set(ctx, "marker", "kept"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	v, err := s2.SchemaVersion(ctx)
	if err != nil || v != 4 {
		t.Errorf("schema version after reopen: %d, %v", v, err)
	}
	if got, err := s2.Meta().Get(ctx, "marker"); err != nil || got != "kept" {
		t.Errorf("data lost across reopen: %q, %v", got, err)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	s, path := openTemp(t)
	ctx := context.Background()
	if err := s.Meta().Set(ctx, SchemaVersionKey, "99"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	_ = s.Close()
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("expected error opening a database with a newer schema")
	}
}

func TestMetaRoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if _, err := s.Meta().Get(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent key: got %v, want ErrNotFound", err)
	}
	if err := s.Meta().Set(ctx, "k", "v1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Meta().Set(ctx, "k", "v2"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	if got, err := s.Meta().Get(ctx, "k"); err != nil || got != "v2" {
		t.Errorf("Get: %q, %v", got, err)
	}
}

func TestPeersCountEmpty(t *testing.T) {
	s, _ := openTemp(t)
	n, err := s.Peers().Count(context.Background())
	if err != nil || n != 0 {
		t.Errorf("Count: %d, %v", n, err)
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty path")
	}
}
