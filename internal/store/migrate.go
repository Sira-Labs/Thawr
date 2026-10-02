package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// SchemaVersionKey is the meta key holding the applied schema version.
const SchemaVersionKey = "schema_version"

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads the embedded NNNN_name.sql files sorted by number.
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		if !ok || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("store: migration %q is not NNNN_name.sql", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q has no numeric prefix: %w", name, err)
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("store: read migration %q: %w", name, err)
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := range out {
		if out[i].version != i+1 {
			return nil, fmt.Errorf("store: migration %q breaks the sequence (expected %04d)", out[i].name, i+1)
		}
	}
	return out, nil
}

// LatestSchemaVersion is the schema version this binary migrates to;
// a database (or a backup) newer than that cannot be opened.
func LatestSchemaVersion() (int, error) {
	m, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	return len(m), nil
}

// migrate applies every migration newer than the recorded schema
// version inside one transaction and records the new version.
func (s *Store) migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	current, err := s.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if current >= len(migrations) {
		if current > len(migrations) {
			return fmt.Errorf("store: database schema version %d is newer than this binary (%d)", current, len(migrations))
		}
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin migration tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range migrations[current:] {
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("store: apply migration %s: %w", m.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		SchemaVersionKey, strconv.Itoa(len(migrations))); err != nil {
		return fmt.Errorf("store: record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit migrations: %w", err)
	}
	return nil
}

// schemaVersion returns 0 for a fresh database (no meta table yet).
func (s *Store) schemaVersion(ctx context.Context) (int, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'`).Scan(&exists)
	if err != nil {
		return 0, fmt.Errorf("store: inspect schema: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}
	var raw string
	err = s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, SchemaVersionKey).Scan(&raw)
	if err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("store: schema version %q is not a number: %w", raw, err)
	}
	return v, nil
}

// SchemaVersion reports the applied schema version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	return s.schemaVersion(ctx)
}
