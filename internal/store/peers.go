package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Peer kinds and modes.
const (
	KindHuman  = "human"
	KindServer = "server"
	KindAgent  = "agent"

	ModeAgent  = "agent"
	ModeStatic = "static"
)

// Peer is one registered identity.
type Peer struct {
	ID        string
	Name      string
	Kind      string
	Mode      string
	OwnerID   string
	Tags      []string
	PublicKey string
	IPv4      string
	// IPv6 is the IPv6 overlay address (spec 015); empty until the
	// server has derived it.
	IPv6 string
	// IPv6Capable is true once the peer's client asked for IPv6.
	IPv6Capable    bool
	NodeSecretHash string
	CreatedAt      time.Time
	LastSeenAt     *time.Time
	// ClientVersion and OS are what the client reported at enrollment
	// (the version is refreshed on every sync).
	ClientVersion string
	OS            string
}

// Peers accesses the peers table.
type Peers struct {
	q querier
}

const peerColumns = `id, name, kind, mode, owner_id, tags, public_key, ipv4, ipv6, ipv6_capable, node_secret_hash, created_at, last_seen_at, client_version, os`

func scanPeer(row interface{ Scan(...any) error }) (Peer, error) {
	var (
		p                       Peer
		tags, created           string
		owner, secret, lastSeen sql.NullString
		ipv6                    sql.NullString
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Mode, &owner, &tags, &p.PublicKey, &p.IPv4, &ipv6, &p.IPv6Capable, &secret, &created, &lastSeen, &p.ClientVersion, &p.OS); err != nil {
		return Peer{}, err
	}
	if err := json.Unmarshal([]byte(tags), &p.Tags); err != nil {
		return Peer{}, fmt.Errorf("peer %s tags: %w", p.ID, err)
	}
	p.OwnerID = owner.String
	p.IPv6 = ipv6.String
	p.NodeSecretHash = secret.String
	p.CreatedAt = parseTime(created)
	p.LastSeenAt = parseTimePtr(lastSeen)
	return p, nil
}

// Create inserts p. ErrConflict on a duplicate name, key or address.
func (s *Peers) Create(ctx context.Context, p Peer) error {
	tags, err := json.Marshal(nonNil(p.Tags))
	if err != nil {
		return fmt.Errorf("store: encode tags: %w", err)
	}
	_, err = s.q.ExecContext(ctx,
		`INSERT INTO peers (`+peerColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.Kind, p.Mode, nullString(p.OwnerID), string(tags), p.PublicKey, p.IPv4,
		nullString(p.IPv6), p.IPv6Capable, nullString(p.NodeSecretHash), formatTime(p.CreatedAt), formatTimePtr(p.LastSeenAt), p.ClientVersion, p.OS)
	if isUniqueViolation(err) {
		return fmt.Errorf("peer %q: %w", p.Name, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: create peer %q: %w", p.Name, err)
	}
	return nil
}

// Count returns the number of registered peers.
func (s *Peers) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count peers: %w", err)
	}
	return n, nil
}

// CountByKind returns the number of peers per kind; kinds without a
// peer are absent.
func (s *Peers) CountByKind(ctx context.Context) (map[string]int, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT kind, COUNT(*) FROM peers GROUP BY kind`)
	if err != nil {
		return nil, fmt.Errorf("store: count peers by kind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var (
			kind string
			n    int
		)
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, fmt.Errorf("store: count peers by kind: %w", err)
		}
		out[kind] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: count peers by kind: %w", err)
	}
	return out, nil
}

// List returns all peers ordered by name.
func (s *Peers) List(ctx context.Context) ([]Peer, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+peerColumns+` FROM peers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list peers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan peer: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list peers: %w", err)
	}
	return out, nil
}

func (s *Peers) getWhere(ctx context.Context, where string, arg any) (Peer, error) {
	p, err := scanPeer(s.q.QueryRowContext(ctx, `SELECT `+peerColumns+` FROM peers WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	if err != nil {
		return Peer{}, fmt.Errorf("store: get peer: %w", err)
	}
	return p, nil
}

// GetByName returns the peer or ErrNotFound.
func (s *Peers) GetByName(ctx context.Context, name string) (Peer, error) {
	return s.getWhere(ctx, `name = ?`, name)
}

// GetByID returns the peer or ErrNotFound.
func (s *Peers) GetByID(ctx context.Context, id string) (Peer, error) {
	return s.getWhere(ctx, `id = ?`, id)
}

// GetByNodeSecretHash returns the agent peer holding the secret or ErrNotFound.
func (s *Peers) GetByNodeSecretHash(ctx context.Context, hash string) (Peer, error) {
	return s.getWhere(ctx, `node_secret_hash = ?`, hash)
}

// Rename changes a peer's name. ErrNotFound or ErrConflict.
func (s *Peers) Rename(ctx context.Context, id, name string) error {
	res, err := s.q.ExecContext(ctx, `UPDATE peers SET name = ? WHERE id = ?`, name, id)
	if isUniqueViolation(err) {
		return fmt.Errorf("peer %q: %w", name, ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: rename peer %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("peer %s: %w", id, ErrNotFound)
	}
	return nil
}

// Delete removes the peer or returns ErrNotFound.
func (s *Peers) Delete(ctx context.Context, id string) error {
	res, err := s.q.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete peer %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("peer %s: %w", id, ErrNotFound)
	}
	return nil
}

// AllocatedIPv4s returns every address in use.
func (s *Peers) AllocatedIPv4s(ctx context.Context) ([]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT ipv4 FROM peers`)
	if err != nil {
		return nil, fmt.Errorf("store: list addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("store: scan address: %w", err)
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// BackfillIPv6 sets the IPv6 address of every peer that has none to
// derive(ipv4) and returns how many it set. A peer whose IPv4 address
// derive cannot map (it returns "") keeps no IPv6 address.
func (s *Peers) BackfillIPv6(ctx context.Context, derive func(ipv4 string) string) (int, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT id, ipv4 FROM peers WHERE ipv6 IS NULL OR ipv6 = ''`)
	if err != nil {
		return 0, fmt.Errorf("store: list peers without ipv6: %w", err)
	}
	type pending struct{ id, ipv4 string }
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.ipv4); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("store: scan peer without ipv6: %w", err)
		}
		todo = append(todo, p)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("store: list peers without ipv6: %w", err)
	}
	n := 0
	for _, p := range todo {
		v6 := derive(p.ipv4)
		if v6 == "" {
			continue
		}
		if _, err := s.q.ExecContext(ctx, `UPDATE peers SET ipv6 = ? WHERE id = ?`, v6, p.id); err != nil {
			if isUniqueViolation(err) {
				return n, fmt.Errorf("peer %s ipv6 %s: %w", p.id, v6, ErrConflict)
			}
			return n, fmt.Errorf("store: set ipv6 of peer %s: %w", p.id, err)
		}
		n++
	}
	return n, nil
}

// SetIPv6Capable records whether the peer's client asked for IPv6. It
// reports whether the stored value changed; ErrNotFound for an unknown
// peer.
func (s *Peers) SetIPv6Capable(ctx context.Context, id string, capable bool) (bool, error) {
	res, err := s.q.ExecContext(ctx, `UPDATE peers SET ipv6_capable = ? WHERE id = ? AND ipv6_capable != ?`, capable, id, capable)
	if err != nil {
		return false, fmt.Errorf("store: set ipv6_capable of peer %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: set ipv6_capable of peer %s: %w", id, err)
	}
	if n > 0 {
		return true, nil
	}
	var exists int
	err = s.q.QueryRowContext(ctx, `SELECT 1 FROM peers WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("peer %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return false, fmt.Errorf("store: find peer %s: %w", id, err)
	}
	return false, nil
}

// NamesWithPrefix returns peer names equal to prefix or starting with
// prefix + "-", used to derive a unique name.
func (s *Peers) NamesWithPrefix(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT name FROM peers WHERE name = ? OR name LIKE ? ESCAPE '\'`,
		prefix, escapeLike(prefix)+"-%")
	if err != nil {
		return nil, fmt.Errorf("store: names with prefix: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store: scan name: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '_' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// SetPublicKey replaces a peer's WireGuard key. ErrConflict if another
// peer holds it, ErrNotFound if the peer is gone.
func (s *Peers) SetPublicKey(ctx context.Context, id, publicKey string) error {
	res, err := s.q.ExecContext(ctx, `UPDATE peers SET public_key = ? WHERE id = ?`, publicKey, id)
	if isUniqueViolation(err) {
		return fmt.Errorf("public key: %w", ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("store: set public key of %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("peer %s: %w", id, ErrNotFound)
	}
	return nil
}

// Touch sets last_seen_at.
func (s *Peers) Touch(ctx context.Context, id string, at time.Time) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE peers SET last_seen_at = ? WHERE id = ?`, formatTime(at), id); err != nil {
		return fmt.Errorf("store: touch peer %s: %w", id, err)
	}
	return nil
}

// SetClientVersion records the version a client reports on sync.
func (s *Peers) SetClientVersion(ctx context.Context, id, version string) error {
	if _, err := s.q.ExecContext(ctx, `UPDATE peers SET client_version = ? WHERE id = ?`, version, id); err != nil {
		return fmt.Errorf("store: set client version of peer %s: %w", id, err)
	}
	return nil
}

// ListByMode returns peers of one mode ordered by name.
func (s *Peers) ListByMode(ctx context.Context, mode string) ([]Peer, error) {
	rows, err := s.q.QueryContext(ctx, `SELECT `+peerColumns+` FROM peers WHERE mode = ? ORDER BY name`, mode)
	if err != nil {
		return nil, fmt.Errorf("store: list peers by mode: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan peer: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
