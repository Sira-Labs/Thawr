package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupTo(t *testing.T) {
	ctx := context.Background()
	s, _ := openTemp(t)
	if err := s.Peers().Create(ctx, Peer{ID: "peer", Name: "p", Kind: KindHuman, Mode: ModeAgent, PublicKey: "k", IPv4: "100.64.0.2", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy.db")
	if err := s.BackupTo(ctx, dst); err != nil {
		t.Fatalf("BackupTo: %v", err)
	}
	if err := s.BackupTo(ctx, dst); err == nil {
		t.Fatal("BackupTo over an existing file succeeded")
	}

	cp, err := Open(ctx, dst)
	if err != nil {
		t.Fatalf("open copy: %v", err)
	}
	defer func() { _ = cp.Close() }()
	if _, err := cp.Peers().GetByName(ctx, "p"); err != nil {
		t.Errorf("peer missing in copy: %v", err)
	}
	want, _ := s.SchemaVersion(ctx)
	if got, _ := cp.SchemaVersion(ctx); got != want {
		t.Errorf("schema version in copy = %d, want %d", got, want)
	}
	// The source stays usable after the snapshot.
	if n, err := s.Peers().Count(ctx); err != nil || n != 1 {
		t.Errorf("source after backup: count %d, %v", n, err)
	}
}
