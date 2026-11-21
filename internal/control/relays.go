package control

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sira-labs/thawr/internal/store"
)

// Relay node policy (spec 016).
const (
	// RelayTokenPrefix marks relay registration token secrets.
	RelayTokenPrefix = "thawr_relay_" //nolint:gosec // a prefix, not a credential
	// DefaultRelayTokenTTL and MaxRelayTokenTTL bound a relay token's
	// lifetime.
	DefaultRelayTokenTTL = time.Hour
	MaxRelayTokenTTL     = 24 * time.Hour
	// DefaultTicketTTL, MinTicketTTL and MaxTicketTTL bound how long a
	// device's ticket for a relay is valid (relay.ticket_ttl).
	DefaultTicketTTL = time.Hour
	MinTicketTTL     = 5 * time.Minute
	MaxTicketTTL     = 24 * time.Hour
	// RelayOnlineWindow is how long a relay stays online after its last
	// heartbeat.
	RelayOnlineWindow = 30 * time.Second
	// TicketLen is the length of a ticket in bytes.
	TicketLen = 32

	relayTokenIDLen = 8 // hex characters after "rt_"
	relayIDLen      = 12
	// ticketPruneEvery spaces the removal of expired ticket rows.
	ticketPruneEvery = time.Minute
)

// Audit actions for relay nodes.
const (
	AuditRelayToken    = "relay.token"
	AuditRelayRegister = "relay.register"
	AuditRelayDelete   = "relay.delete"
)

// RoleRelay is the actor role of a relay node acting for itself.
const RoleRelay = "relay"

var relayFingerprintRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// CreatedRelayToken is the result of CreateToken; Secret is shown once.
type CreatedRelayToken struct {
	Token  store.RelayToken
	Secret string
}

// RelayRegistration is what a relay node sends with its one-time token.
type RelayRegistration struct {
	Token string
	// Name is the relay's name; a token issued for a name fixes it.
	Name string
	// URL is what devices dial: https with a host and a port.
	URL string
	// Fingerprint is sha256:<hex> of the relay's TLS certificate.
	Fingerprint string
	Version     string
}

// RegisteredRelay is the result of Register; Secret is returned once
// and authenticates the relay from then on.
type RegisteredRelay struct {
	Relay  store.Relay
	Secret string
}

// RelayHello is what a relay reports about itself when it attaches.
type RelayHello struct {
	URL         string
	Fingerprint string
	Version     string
}

// RelayStats are the counters a relay sends with every heartbeat.
type RelayStats struct {
	Sessions int
	Frames   uint64
	Bytes    uint64
	Drops    uint64
}

// RelayStatus is a relay with its liveness as the server sees it.
type RelayStatus struct {
	Relay  store.Relay
	Online bool
	// Since is when it last went online or offline; zero when it never
	// attached since the server started.
	Since time.Time
	Stats RelayStats
}

// RelayTicketGrant is one relay a device may use, with its ticket.
type RelayTicketGrant struct {
	Relay   store.Relay
	Ticket  []byte
	Expires time.Time
}

// Relays is the registry of standalone relay nodes: their one-time
// tokens, their registration and liveness, and the tickets devices
// present to them. A relay is not a peer and never appears in the peer
// registry, the policy or the lock.
type Relays struct {
	store     *store.Store
	now       func() time.Time
	log       *slog.Logger
	audit     *Auditor
	notify    Notifier
	ticketTTL time.Duration

	// mu guards live.
	mu        sync.Mutex
	live      map[string]*liveRelay
	lastEpoch uint64

	// ticketMu guards tickets and lastPrune. It is held across the
	// write of a new ticket's row, so ForgetPeer, which runs after the
	// transaction that deleted a peer's rows, cannot slip in between
	// the row and its cache entry and leave a dead ticket cached.
	ticketMu  sync.Mutex
	tickets   map[ticketKey]cachedTicket
	lastPrune time.Time
}

type liveRelay struct {
	// epoch numbers the control stream that owns this entry, so the
	// end of a stream a newer one replaced changes nothing.
	epoch    uint64
	online   bool
	lastBeat time.Time
	since    time.Time
	stats    RelayStats
}

type ticketKey struct{ peerID, relayID string }

// cachedTicket keeps a ticket in memory so a device gets the same one
// in every netmap until it is due for renewal; the database holds only
// its hash. A restart forgets them and issues new ones.
type cachedTicket struct {
	ticket  []byte
	issued  time.Time
	expires time.Time
}

// NewRelays builds the relay registry with the default ticket lifetime.
func NewRelays(st *store.Store, now func() time.Time, log *slog.Logger) *Relays {
	return &Relays{store: st, now: now, log: log, ticketTTL: DefaultTicketTTL,
		live: map[string]*liveRelay{}, tickets: map[ticketKey]cachedTicket{}}
}

// WithAuditor records token creation, registration and deletion.
func (r *Relays) WithAuditor(a *Auditor) *Relays {
	r.audit = a
	return r
}

// WithNotifier sets the notifier told when the set of usable relays
// changes, so devices get a new netmap.
func (r *Relays) WithNotifier(n Notifier) *Relays {
	r.notify = n
	return r
}

// WithTicketTTL sets how long a ticket is valid.
func (r *Relays) WithTicketTTL(ttl time.Duration) (*Relays, error) {
	if ttl < MinTicketTTL || ttl > MaxTicketTTL {
		return nil, fmt.Errorf("%w: ticket lifetime %s must be between %s and %s", ErrValidation, ttl, MinTicketTTL, MaxTicketTTL)
	}
	r.ticketTTL = ttl
	return r, nil
}

// CreateToken issues a one-time token that registers one relay. Only
// admins may. A name given here is the name that relay will have.
func (r *Relays) CreateToken(ctx context.Context, by Principal, name string, ttl time.Duration) (CreatedRelayToken, error) {
	if !by.IsAdmin() {
		return CreatedRelayToken{}, fmt.Errorf("%w: only an admin may create a relay token", ErrForbidden)
	}
	if name != "" && !validPeerName(name) {
		return CreatedRelayToken{}, fmt.Errorf("%w: relay name %q must be a DNS label other than %q", ErrValidation, name, HubName)
	}
	switch {
	case ttl == 0:
		ttl = DefaultRelayTokenTTL
	case ttl < 0:
		return CreatedRelayToken{}, fmt.Errorf("%w: expiry must be positive", ErrValidation)
	case ttl > MaxRelayTokenTTL:
		return CreatedRelayToken{}, fmt.Errorf("%w: expiry exceeds the maximum of %s", ErrValidation, MaxRelayTokenTTL)
	}
	id, err := newID()
	if err != nil {
		return CreatedRelayToken{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return CreatedRelayToken{}, err
	}
	secret = RelayTokenPrefix + secret
	creator := by.Name
	if by.Local {
		creator = LocalAdmin.Name
	}
	now := r.now()
	tok := store.RelayToken{ID: "rt_" + id[:relayTokenIDLen], SecretHash: hashSecret(secret), RelayName: name,
		CreatedBy: creator, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	err = r.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.RelayTokens().Create(ctx, tok); err != nil {
			return err
		}
		return r.audit.Record(ctx, tx, by, AuditRelayToken, tok.ID,
			map[string]string{"name": name, "expires_at": tok.ExpiresAt.UTC().Format(time.RFC3339)})
	})
	if err != nil {
		return CreatedRelayToken{}, err
	}
	r.log.Info("relay token created", "token", tok.ID, "name", name, "expires_at", tok.ExpiresAt, "by", by.Name)
	return CreatedRelayToken{Token: tok, Secret: secret}, nil
}

// Register consumes a relay token and creates the relay. Every token
// problem, an enrollment token included, is ErrInvalidToken, so the
// answer does not tell which kind a token is.
func (r *Relays) Register(ctx context.Context, req RelayRegistration) (RegisteredRelay, error) {
	if req.Token == "" {
		return RegisteredRelay{}, ErrInvalidToken
	}
	if err := validateRelayEndpoint(req.URL, req.Fingerprint); err != nil {
		return RegisteredRelay{}, err
	}
	id, err := newID()
	if err != nil {
		return RegisteredRelay{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return RegisteredRelay{}, err
	}
	now := r.now()
	relay := store.Relay{ID: "rl_" + id[:relayIDLen], URL: req.URL, TLSFingerprint: req.Fingerprint,
		SecretHash: hashSecret(secret), Version: req.Version, CreatedAt: now}
	err = r.store.InTx(ctx, func(tx *store.Store) error {
		tok, err := tx.RelayTokens().GetByHash(ctx, hashSecret(req.Token))
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidToken
		}
		if err != nil {
			return err
		}
		if tok.UsedAt != nil || !now.Before(tok.ExpiresAt) {
			return ErrInvalidToken
		}
		relay.Name = req.Name
		if tok.RelayName != "" {
			if req.Name != "" && req.Name != tok.RelayName {
				return fmt.Errorf("%w: this token registers the relay %q, not %q", ErrValidation, tok.RelayName, req.Name)
			}
			relay.Name = tok.RelayName
		}
		if !validPeerName(relay.Name) {
			return fmt.Errorf("%w: relay name %q must be a DNS label other than %q", ErrValidation, relay.Name, HubName)
		}
		if err := tx.Relays().Create(ctx, relay); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("%w: a relay named %q already exists", ErrValidation, relay.Name)
			}
			return err
		}
		if err := tx.RelayTokens().MarkUsed(ctx, tok.ID, relay.ID, now); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return ErrInvalidToken
			}
			return err
		}
		return r.audit.Record(ctx, tx, relayPrincipal(relay.Name), AuditRelayRegister, relay.ID,
			map[string]string{"name": relay.Name, "url": relay.URL, "tls": shortFingerprint(relay.TLSFingerprint), "token": tok.ID})
	})
	if err != nil {
		return RegisteredRelay{}, err
	}
	r.log.Info("relay registered", "relay", relay.Name, "relay_id", relay.ID, "url", relay.URL)
	return RegisteredRelay{Relay: relay, Secret: secret}, nil
}

// Authenticate returns the relay holding secret, or ErrForbidden.
func (r *Relays) Authenticate(ctx context.Context, secret string) (store.Relay, error) {
	if secret == "" {
		return store.Relay{}, ErrForbidden
	}
	relay, err := r.store.Relays().GetBySecretHash(ctx, hashSecret(secret))
	if errors.Is(err, store.ErrNotFound) {
		return store.Relay{}, ErrForbidden
	}
	return relay, err
}

// Attach marks a relay online when its control stream opens. A URL,
// fingerprint or version that differs from the stored one replaces it,
// so a relay whose certificate was regenerated is usable again without
// registering anew. The returned epoch names this attachment: a later
// Attach for the same relay replaces it, and Detach and Current tell
// the two apart.
func (r *Relays) Attach(ctx context.Context, relayID string, hello RelayHello) (uint64, error) {
	if err := validateRelayEndpoint(hello.URL, hello.Fingerprint); err != nil {
		return 0, err
	}
	now := r.now()
	err := r.store.InTx(ctx, func(tx *store.Store) error {
		relay, err := tx.Relays().GetByID(ctx, relayID)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("relay %s: %w", relayID, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if relay.URL != hello.URL || relay.TLSFingerprint != hello.Fingerprint || relay.Version != hello.Version {
			if err := tx.Relays().SetEndpoint(ctx, relayID, hello.URL, hello.Fingerprint, hello.Version); err != nil {
				return err
			}
		}
		if err := tx.Relays().Touch(ctx, relayID, now); err != nil {
			return err
		}
		// Devices learn of the relay, or of its new address, from the
		// next netmap.
		_, err = tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.lastEpoch++
	epoch := r.lastEpoch
	r.live[relayID] = &liveRelay{epoch: epoch, online: true, lastBeat: now, since: now}
	r.mu.Unlock()
	r.changed()
	r.log.Info("relay online", "relay_id", relayID, "url", hello.URL, "version", hello.Version)
	return epoch, nil
}

// Current reports whether epoch is still the relay's attachment: false
// once a newer stream attached or the relay was deleted.
func (r *Relays) Current(relayID string, epoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.live[relayID]
	return ok && l.epoch == epoch
}

// Heartbeat records that the relay attached with epoch is alive and
// what it carries. A relay that was swept offline for missing
// heartbeats comes back online with the next one. The heartbeat of a
// stream that a newer one has replaced is refused with ErrNotFound and
// changes nothing: it says nothing about the stream that is attached.
func (r *Relays) Heartbeat(ctx context.Context, relayID string, epoch uint64, stats RelayStats) error {
	now := r.now()
	r.mu.Lock()
	l, ok := r.live[relayID]
	if !ok || l.epoch != epoch {
		r.mu.Unlock()
		return fmt.Errorf("relay %s is not attached by this stream: %w", relayID, ErrNotFound)
	}
	// Not usable covers both a relay the sweep took offline and one
	// whose heartbeats stopped for longer than the window without a
	// sweep in between: Online left it out either way.
	back := !l.usable(now)
	if !back {
		l.lastBeat, l.stats = now, stats
	}
	r.mu.Unlock()
	if !back {
		return nil
	}
	// The lock was released for the generation write; a stream that
	// attached meanwhile owns the entry and this heartbeat must not
	// touch it.
	err := r.publish(ctx, func() {
		if l, ok := r.live[relayID]; ok && l.epoch == epoch {
			l.online, l.since, l.lastBeat, l.stats = true, now, now, stats
		}
	})
	if err != nil {
		return err
	}
	r.log.Info("relay online again", "relay_id", relayID)
	return nil
}

// Detach marks a relay offline when the control stream that attached
// with epoch ends. The end of a stream that a newer one has replaced
// is ignored: the relay is still attached.
func (r *Relays) Detach(ctx context.Context, relayID string, epoch uint64) error {
	now := r.now()
	r.mu.Lock()
	l, ok := r.live[relayID]
	wasOnline := ok && l.epoch == epoch && l.online
	r.mu.Unlock()
	if !wasOnline {
		return nil
	}
	err := r.publish(ctx, func() {
		if l, ok := r.live[relayID]; ok && l.epoch == epoch {
			l.online, l.since = false, now
		}
	})
	if err != nil {
		return err
	}
	r.log.Info("relay offline", "relay_id", relayID, "reason", "stream closed")
	if err := r.store.Relays().Touch(ctx, relayID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// Sweep takes relays offline whose last heartbeat is older than
// RelayOnlineWindow and reports how many. The server calls it on a
// timer; Online already leaves such relays out in between.
func (r *Relays) Sweep(ctx context.Context) (int, error) {
	now := r.now()
	stale := func(l *liveRelay) bool { return l.online && now.Sub(l.lastBeat) > RelayOnlineWindow }
	r.mu.Lock()
	pending := 0
	for _, l := range r.live {
		if stale(l) {
			pending++
		}
	}
	r.mu.Unlock()
	if pending == 0 {
		return 0, nil
	}
	var swept []string
	err := r.publish(ctx, func() {
		for id, l := range r.live {
			if stale(l) {
				l.online, l.since = false, now
				swept = append(swept, id)
			}
		}
	})
	if err != nil {
		return 0, err
	}
	sort.Strings(swept)
	for _, id := range swept {
		r.log.Warn("relay offline", "relay_id", id, "reason", "no heartbeat")
	}
	return len(swept), nil
}

// List returns every relay with its liveness, ordered by name. Admins
// only: a relay's address is infrastructure, not something a member
// needs to enumerate.
func (r *Relays) List(ctx context.Context, by Principal) ([]RelayStatus, error) {
	if !by.IsAdmin() {
		return nil, ErrForbidden
	}
	relays, err := r.store.Relays().List(ctx)
	if err != nil {
		return nil, err
	}
	now := r.now()
	out := make([]RelayStatus, 0, len(relays))
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, relay := range relays {
		st := RelayStatus{Relay: relay}
		if l, ok := r.live[relay.ID]; ok {
			st.Online, st.Since, st.Stats = l.usable(now), l.since, l.stats
		}
		out = append(out, st)
	}
	return out, nil
}

// Get returns one relay by name.
func (r *Relays) Get(ctx context.Context, by Principal, name string) (RelayStatus, error) {
	all, err := r.List(ctx, by)
	if err != nil {
		return RelayStatus{}, err
	}
	for _, st := range all {
		if st.Relay.Name == name {
			return st, nil
		}
	}
	return RelayStatus{}, fmt.Errorf("relay %q: %w", name, ErrNotFound)
}

// Delete removes a relay, its secret and its tickets (admins only) and
// bumps the generation so no netmap lists it any more. It returns the
// deleted relay so the caller can close its control stream.
func (r *Relays) Delete(ctx context.Context, by Principal, name string) (store.Relay, error) {
	if !by.IsAdmin() {
		return store.Relay{}, ErrForbidden
	}
	var relay store.Relay
	err := r.store.InTx(ctx, func(tx *store.Store) error {
		var err error
		relay, err = tx.Relays().GetByName(ctx, name)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("relay %q: %w", name, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if err := tx.Relays().Delete(ctx, relay.ID); err != nil {
			return err
		}
		if err := r.audit.Record(ctx, tx, by, AuditRelayDelete, relay.ID, map[string]string{"name": relay.Name}); err != nil {
			return err
		}
		_, err = tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return store.Relay{}, err
	}
	r.mu.Lock()
	delete(r.live, relay.ID)
	r.mu.Unlock()
	r.ticketMu.Lock()
	for k := range r.tickets {
		if k.relayID == relay.ID {
			delete(r.tickets, k)
		}
	}
	r.ticketMu.Unlock()
	r.changed()
	r.log.Info("relay deleted", "relay", relay.Name, "relay_id", relay.ID, "by", by.Name)
	return relay, nil
}

// Online returns the relays devices may use right now, ordered by
// name: attached, with a heartbeat inside RelayOnlineWindow.
func (r *Relays) Online(ctx context.Context) ([]store.Relay, error) {
	now := r.now()
	r.mu.Lock()
	usable := map[string]bool{}
	for id, l := range r.live {
		if l.usable(now) {
			usable[id] = true
		}
	}
	r.mu.Unlock()
	if len(usable) == 0 {
		return nil, nil
	}
	relays, err := r.store.Relays().List(ctx)
	if err != nil {
		return nil, err
	}
	out := relays[:0]
	for _, relay := range relays {
		if usable[relay.ID] {
			out = append(out, relay)
		}
	}
	return out, nil
}

// Tickets returns, for every online relay, the ticket peerID presents
// there. A ticket is reused until half its lifetime has passed and then
// replaced; the one it replaces stays valid until it expires, so a
// device holding the older netmap is not locked out.
func (r *Relays) Tickets(ctx context.Context, peerID string) ([]RelayTicketGrant, error) {
	relays, err := r.Online(ctx)
	if err != nil || len(relays) == 0 {
		return nil, err
	}
	now := r.now()
	r.ticketMu.Lock()
	defer r.ticketMu.Unlock()
	if err := r.pruneTicketsLocked(ctx, now); err != nil {
		return nil, err
	}
	out := make([]RelayTicketGrant, 0, len(relays))
	for _, relay := range relays {
		key := ticketKey{peerID: peerID, relayID: relay.ID}
		c, ok := r.tickets[key]
		if !ok || !now.Before(c.issued.Add(r.ticketTTL/2)) {
			c, err = r.issueTicketLocked(ctx, key, now)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, RelayTicketGrant{Relay: relay, Ticket: append([]byte(nil), c.ticket...), Expires: c.expires})
	}
	return out, nil
}

// issueTicketLocked stores a new ticket's hash and caches the ticket;
// the caller holds ticketMu.
func (r *Relays) issueTicketLocked(ctx context.Context, key ticketKey, now time.Time) (cachedTicket, error) {
	ticket := make([]byte, TicketLen)
	if _, err := rand.Read(ticket); err != nil {
		return cachedTicket{}, fmt.Errorf("control: random ticket: %w", err)
	}
	c := cachedTicket{ticket: ticket, issued: now, expires: now.Add(r.ticketTTL)}
	err := r.store.RelayTickets().Put(ctx, store.RelayTicket{TicketHash: hashSecret(string(ticket)),
		PeerID: key.peerID, RelayID: key.relayID, CreatedAt: now, ExpiresAt: c.expires})
	if err != nil {
		return cachedTicket{}, fmt.Errorf("control: ticket for peer %s at relay %s: %w", key.peerID, key.relayID, err)
	}
	r.tickets[key] = c
	return c, nil
}

// pruneTicketsLocked drops expired rows and cache entries, at most once
// per ticketPruneEvery; the caller holds ticketMu.
func (r *Relays) pruneTicketsLocked(ctx context.Context, now time.Time) error {
	if now.Sub(r.lastPrune) < ticketPruneEvery {
		return nil
	}
	if _, err := r.store.RelayTickets().DeleteExpired(ctx, now); err != nil {
		return err
	}
	r.lastPrune = now
	for k, c := range r.tickets {
		if !now.Before(c.expires) {
			delete(r.tickets, k)
		}
	}
	return nil
}

// Admit answers a relay's question whether ticket opens a session
// there: the peer it belongs to, or ErrForbidden for a ticket that is
// unknown, expired, issued for another relay, or whose peer is gone.
// The reasons are not told apart.
func (r *Relays) Admit(ctx context.Context, relayID string, ticket []byte) (store.Peer, error) {
	if len(ticket) != TicketLen {
		return store.Peer{}, ErrForbidden
	}
	t, err := r.store.RelayTickets().GetByHash(ctx, hashSecret(string(ticket)))
	if errors.Is(err, store.ErrNotFound) {
		return store.Peer{}, ErrForbidden
	}
	if err != nil {
		return store.Peer{}, err
	}
	if t.RelayID != relayID || !r.now().Before(t.ExpiresAt) {
		return store.Peer{}, ErrForbidden
	}
	p, err := r.store.Peers().GetByID(ctx, t.PeerID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Peer{}, ErrForbidden
	}
	return p, err
}

// SessionPeer returns the peer behind an admitted session as it is
// now, or ErrNotFound once it was deleted. The caller compares the key
// with the one it admitted to notice a rotation.
func (r *Relays) SessionPeer(ctx context.Context, peerID string) (store.Peer, error) {
	p, err := r.store.Peers().GetByID(ctx, peerID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Peer{}, fmt.Errorf("peer %s: %w", peerID, ErrNotFound)
	}
	return p, err
}

// ForgetPeer drops the cached tickets of a peer that was deleted or
// rotated its key; their rows are already gone, and the next netmap
// issues new ones.
func (r *Relays) ForgetPeer(peerID string) {
	r.ticketMu.Lock()
	defer r.ticketMu.Unlock()
	for k := range r.tickets {
		if k.peerID == peerID {
			delete(r.tickets, k)
		}
	}
}

// publish makes a liveness change visible: it moves the netmap
// generation, then applies the change under mu, then wakes the streams.
// When the generation cannot be written nothing changes in memory, so
// the next heartbeat or sweep finds the same condition and tries again
// instead of leaving devices with a netmap that disagrees with Online.
func (r *Relays) publish(ctx context.Context, apply func()) error {
	if _, err := r.store.Meta().IncrementGeneration(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	apply()
	r.mu.Unlock()
	r.changed()
	return nil
}

func (r *Relays) changed() {
	if r.notify != nil {
		r.notify.Changed()
	}
}

func (l *liveRelay) usable(now time.Time) bool {
	return l.online && now.Sub(l.lastBeat) <= RelayOnlineWindow
}

func relayPrincipal(name string) Principal {
	return Principal{Name: "relay:" + name, Role: RoleRelay}
}

// shortFingerprint is the first 8 hex characters of a sha256:<hex>
// fingerprint, the form logs and audit details carry.
func shortFingerprint(fp string) string {
	const prefix = "sha256:"
	if len(fp) >= len(prefix)+8 {
		return fp[len(prefix) : len(prefix)+8]
	}
	return fp
}

// validateRelayEndpoint rejects a relay URL that is not https with a
// host and a port and nothing else, and a fingerprint that is not
// sha256:<64 hex characters>.
func validateRelayEndpoint(raw, fingerprint string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: relay url %q: %s", ErrValidation, raw, err.Error())
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("%w: relay url %q must be https://host:port", ErrValidation, raw)
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: relay url %q needs a port between 1 and 65535", ErrValidation, raw)
	}
	if !relayFingerprintRe.MatchString(fingerprint) {
		return fmt.Errorf("%w: relay fingerprint must be sha256:<64 hex characters>", ErrValidation)
	}
	return nil
}
