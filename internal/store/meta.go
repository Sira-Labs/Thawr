package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// Meta reads and writes the key/value metadata table (schema version,
// netmap generation, server key fingerprint).
type Meta struct {
	q querier
}

// Well-known meta keys.
const (
	MetaNetmapGeneration     = "netmap_generation"
	MetaServerKeyFingerprint = "server_key_fingerprint"
	// MetaOverlayIPv6 is the IPv6 overlay prefix in effect (spec 015),
	// kept so a restart or restore never changes peers' addresses.
	MetaOverlayIPv6 = "overlay_ipv6"
)

// Get returns the value for key or ErrNotFound.
func (m *Meta) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := m.q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("meta %q: %w", key, ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("store: meta get %q: %w", key, err)
	}
	return v, nil
}

// Set inserts or replaces key.
func (m *Meta) Set(ctx context.Context, key, value string) error {
	_, err := m.q.ExecContext(ctx,
		`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return fmt.Errorf("store: meta set %q: %w", key, err)
	}
	return nil
}

// IncrementGeneration bumps the netmap generation and returns the new
// value. Callers run it inside the transaction that changed the netmap.
func (m *Meta) IncrementGeneration(ctx context.Context) (int64, error) {
	var gen int64
	err := m.q.QueryRowContext(ctx,
		`UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = ? RETURNING CAST(value AS INTEGER)`,
		MetaNetmapGeneration).Scan(&gen)
	if err != nil {
		return 0, fmt.Errorf("store: increment generation: %w", err)
	}
	return gen, nil
}

// Generation returns the current netmap generation.
func (m *Meta) Generation(ctx context.Context) (int64, error) {
	raw, err := m.Get(ctx, MetaNetmapGeneration)
	if err != nil {
		return 0, err
	}
	gen, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: generation %q: %w", raw, err)
	}
	return gen, nil
}
