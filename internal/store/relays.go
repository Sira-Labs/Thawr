package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Relay is a standalone relay node (spec 016). The relay secret itself
// is never stored; SecretHash is its SHA-256 in hex.
type Relay struct {
	ID             string
	Name           string
	URL            string
	TLSFingerprint string
	SecretHash     string
	Version        string
	CreatedAt      time.Time
	LastSeenAt     *time.Time
}

// RelayToken is a one-time token that registers a relay node. It is a
// kind of its own: an enrollment token never registers a relay.
type RelayToken struct {
	ID         string
	SecretHash string
	// RelayName, when set, is the name the relay registers under.
	RelayName     string
	CreatedBy     string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	UsedAt        *time.Time
	UsedByRelayID string
}

// RelayTicket lets one peer open a session at one relay until it
// expires. TicketHash is the SHA-256 of the ticket in hex.
type RelayTicket struct {
	TicketHash string
	PeerID     string
	RelayID    string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Relays accesses the relays table.
type Relays struct {
	q querier
}

// RelayTokens accesses the relay_tokens table.
type RelayTokens struct {
	q querier
}

// RelayTickets accesses the relay_tickets table.
type RelayTickets struct {
	q querier
}

const relayColumns = `id, name, url, tls_fingerprint, secret_hash, version, created_at, last_seen_at`

func scanRelay(row interface{ Scan(...any) error }) (Relay, error) {
	var (
		r        Relay
		created  string
		lastSeen sql.NullString
	)
	if err := row.Scan(&r.ID, &r.Name, &r.URL, &r.TLSFingerprint, &r.SecretHash, &r.Version, &created, &lastSeen); err != nil {
		return Relay{}, err
	}
	r.CreatedAt = parseTime(created)
	r.LastSeenAt = parseTimePtr(lastSeen)
	return r, nil
}

// Create inserts r; a taken name or secret is ErrConflict.
func (s *Relays) Create(ctx context.Context, r Relay) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO relays (`+relayColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Name, r.URL, r.TLSFingerprint, r.SecretHash, r.Version, formatTime(r.CreatedAt), formatTimePtr(r.LastSeenAt))
	if isUniqueViolation(err) {
		return fmt.Errorf("relay %s: %w", r.Name, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: create relay %s: %w", r.ID, err)
	}
	return nil
}

func (s *Relays) getWhere(ctx context.Context, where, arg, what string) (Relay, error) {
	r, err := scanRelay(s.q.QueryRowContext(ctx, `SELECT `+relayColumns+` FROM relays WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Relay{}, ErrNotFound
	}
	if err != nil {
		return Relay{}, fmt.Errorf("store: get relay by %s: %w", what, err)
	}
	return r, nil
}

// GetByID returns the relay or ErrNotFound.
func (s *Relays) GetByID(ctx context.Context, id string) (Relay, error) {
	return s.getWhere(ctx, `id = ?`, id, "id")
}

// GetByName returns the relay or ErrNotFound.
func (s *Relays) GetByName(ctx context.Context, name string) (Relay, error) {
	return s.getWhere(ctx, `name = ?`, name, "name")
}

// GetBySecretHash returns the relay holding that secret or ErrNotFound.
func (s *Relays) GetBySecretHash(ctx context.Context, hash string) (Relay, error) {
	return s.getWhere(ctx, `secret_hash = ?`, hash, "secret hash")
}

// List returns every relay ordered by name.
func (s *Relays) List(ctx context.Context) ([]Relay, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+relayColumns+` FROM relays ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list relays: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Relay
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan relay: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list relays: %w", err)
	}
	return out, nil
}

// SetEndpoint replaces what devices dial and pin, and the version the
// relay reported.
func (s *Relays) SetEndpoint(ctx context.Context, id, url, fingerprint, version string) error {
	return s.update(ctx, id, `UPDATE relays SET url = ?, tls_fingerprint = ?, version = ? WHERE id = ?`, url, fingerprint, version, id)
}

// Touch records when the relay was last heard from.
func (s *Relays) Touch(ctx context.Context, id string, now time.Time) error {
	return s.update(ctx, id, `UPDATE relays SET last_seen_at = ? WHERE id = ?`, formatTime(now), id)
}

func (s *Relays) update(ctx context.Context, id, query string, args ...any) error {
	res, err := s.q.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: update relay %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("relay %s: %w", id, ErrNotFound)
	}
	return nil
}

// Delete removes the relay, and with it its tickets, or returns
// ErrNotFound.
func (s *Relays) Delete(ctx context.Context, id string) error {
	res, err := s.q.ExecContext(ctx, `DELETE FROM relays WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete relay %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("relay %s: %w", id, ErrNotFound)
	}
	return nil
}

//nolint:gosec // a column list, not a credential
const relayTokenColumns = `id, secret_hash, relay_name, created_by, created_at, expires_at, used_at, used_by_relay_id`

func scanRelayToken(row interface{ Scan(...any) error }) (RelayToken, error) {
	var (
		t                    RelayToken
		created, expires     string
		name, usedAt, usedBy sql.NullString
	)
	if err := row.Scan(&t.ID, &t.SecretHash, &name, &t.CreatedBy, &created, &expires, &usedAt, &usedBy); err != nil {
		return RelayToken{}, err
	}
	t.RelayName = name.String
	t.CreatedAt = parseTime(created)
	t.ExpiresAt = parseTime(expires)
	t.UsedAt = parseTimePtr(usedAt)
	t.UsedByRelayID = usedBy.String
	return t, nil
}

// Create inserts t.
func (s *RelayTokens) Create(ctx context.Context, t RelayToken) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO relay_tokens (`+relayTokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)`,
		t.ID, t.SecretHash, nullString(t.RelayName), t.CreatedBy, formatTime(t.CreatedAt), formatTime(t.ExpiresAt))
	if isUniqueViolation(err) {
		return fmt.Errorf("relay token %s: %w", t.ID, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: create relay token %s: %w", t.ID, err)
	}
	return nil
}

// GetByHash returns the token with that secret hash or ErrNotFound.
func (s *RelayTokens) GetByHash(ctx context.Context, hash string) (RelayToken, error) {
	t, err := scanRelayToken(s.q.QueryRowContext(ctx, `SELECT `+relayTokenColumns+` FROM relay_tokens WHERE secret_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return RelayToken{}, ErrNotFound
	}
	if err != nil {
		return RelayToken{}, fmt.Errorf("store: get relay token by hash: %w", err)
	}
	return t, nil
}

// MarkUsed records that relayID registered with token id. It succeeds
// only while the token is unused, so two registrations cannot both win.
func (s *RelayTokens) MarkUsed(ctx context.Context, id, relayID string, now time.Time) error {
	res, err := s.q.ExecContext(ctx,
		`UPDATE relay_tokens SET used_at = ?, used_by_relay_id = ? WHERE id = ? AND used_at IS NULL`,
		formatTime(now), relayID, id)
	if err != nil {
		return fmt.Errorf("store: mark relay token %s used: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("relay token %s already used: %w", id, ErrConflict)
	}
	return nil
}

// Put stores t.
func (s *RelayTickets) Put(ctx context.Context, t RelayTicket) error {
	_, err := s.q.ExecContext(ctx,
		`INSERT INTO relay_tickets (ticket_hash, peer_id, relay_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		t.TicketHash, t.PeerID, t.RelayID, formatTime(t.CreatedAt), formatTime(t.ExpiresAt))
	if isUniqueViolation(err) {
		return fmt.Errorf("relay ticket: %w", ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: put relay ticket for peer %s at relay %s: %w", t.PeerID, t.RelayID, err)
	}
	return nil
}

// GetByHash returns the ticket with that hash or ErrNotFound. Expiry is
// the caller's to check, against its own clock.
func (s *RelayTickets) GetByHash(ctx context.Context, hash string) (RelayTicket, error) {
	var (
		t                RelayTicket
		created, expires string
	)
	err := s.q.QueryRowContext(ctx,
		`SELECT ticket_hash, peer_id, relay_id, created_at, expires_at FROM relay_tickets WHERE ticket_hash = ?`, hash).
		Scan(&t.TicketHash, &t.PeerID, &t.RelayID, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return RelayTicket{}, ErrNotFound
	}
	if err != nil {
		return RelayTicket{}, fmt.Errorf("store: get relay ticket: %w", err)
	}
	t.CreatedAt = parseTime(created)
	t.ExpiresAt = parseTime(expires)
	return t, nil
}

// DeletePeer removes every ticket of a peer (its key was rotated) and
// reports how many there were.
func (s *RelayTickets) DeletePeer(ctx context.Context, peerID string) (int64, error) {
	return s.deleteWhere(ctx, `peer_id = ?`, peerID)
}

// DeleteExpired removes the tickets that expired at or before now.
func (s *RelayTickets) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return s.deleteWhere(ctx, `expires_at <= ?`, formatTime(now))
}

func (s *RelayTickets) deleteWhere(ctx context.Context, where, arg string) (int64, error) {
	res, err := s.q.ExecContext(ctx, `DELETE FROM relay_tickets WHERE `+where, arg)
	if err != nil {
		return 0, fmt.Errorf("store: delete relay tickets: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete relay tickets: %w", err)
	}
	return n, nil
}
