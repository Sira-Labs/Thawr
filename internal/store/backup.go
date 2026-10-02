package store

import (
	"context"
	"fmt"
	"os"
)

// BackupTo writes a consistent copy of the database to path with
// VACUUM INTO, the online snapshot ADR 0002 names. path must not exist.
// The store keeps one connection, so other queries wait for the copy;
// at the database sizes Thawr targets that is well under a second.
func (s *Store) BackupTo(ctx context.Context, path string) error {
	if s.tx != nil {
		return fmt.Errorf("store: backup inside a transaction")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("store: backup target %s exists", path)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return fmt.Errorf("store: backup to %s: %w", path, err)
	}
	return nil
}
