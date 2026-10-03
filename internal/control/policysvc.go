package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/sira-labs/thawr/internal/control/policy"
	"github.com/sira-labs/thawr/internal/store"
)

// PolicyReport describes a policy after a check, reload or show.
type PolicyReport struct {
	Hash     string         `json:"hash"`
	Summary  policy.Summary `json:"summary"`
	Warnings []string       `json:"warnings"`
	Errors   []string       `json:"errors,omitempty"`
	// Source is the policy document; only Show fills it.
	Source string `json:"source,omitempty"`
}

// ErrPolicyInvalid wraps validation failures of a policy document.
var ErrPolicyInvalid = errors.New("policy invalid")

// PolicyService owns the running policy: loading, validated reloads
// that keep the previous policy on error, and the compiled form cached
// per (policy hash, persisted generation) for visibility lookups.
type PolicyService struct {
	store    *store.Store
	log      *slog.Logger
	path     string
	notifier Notifier
	audit    *Auditor
	// overlay tells a peer-selecting CIDR from a subnet route (spec 013).
	overlay netip.Prefix
	// overlay6 bounds IPv6 prefixes in rules (spec 015).
	overlay6 netip.Prefix
	// reloadMu serialises Reload end to end: transaction, publication,
	// notification and report, so two reloads cannot interleave.
	reloadMu sync.Mutex

	mu       sync.Mutex
	current  *policy.Policy
	warnings []string
	compiled *policy.Compiled
	cacheGen int64
	cacheKey string
}

// NewPolicyService builds the service around the policy file at path.
func NewPolicyService(st *store.Store, log *slog.Logger, path string, notifier Notifier) *PolicyService {
	return &PolicyService{store: st, log: log, path: path, notifier: notifier, current: policy.Empty(), cacheGen: -1}
}

// WithAuditor records reloads in the audit log.
func (s *PolicyService) WithAuditor(a *Auditor) *PolicyService {
	s.audit = a
	return s
}

// WithOverlay6 sets the IPv6 overlay prefix: an IPv6 prefix in a rule
// must lie inside it (spec 015).
func (s *PolicyService) WithOverlay6(prefix netip.Prefix) *PolicyService {
	s.overlay6 = prefix
	return s
}

// WithOverlay sets the overlay prefix: a dst CIDR outside it is a
// subnet route, one inside it selects peers (spec 013).
func (s *PolicyService) WithOverlay(overlay netip.Prefix) *PolicyService {
	s.overlay = overlay
	return s
}

// LoadInitial reads the file at startup: a missing file means the
// empty default-deny policy, an invalid one is fatal.
func (s *PolicyService) LoadInitial(ctx context.Context) error {
	p, err := policy.Load(s.path)
	switch {
	case errors.Is(err, policy.ErrNotFound):
		s.log.Warn("policy file not found, using empty default-deny policy", "path", s.path)
		p = policy.Empty()
	case err != nil:
		return err
	}
	warnings, err := s.validate(ctx, p)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current, s.warnings, s.compiled = p, warnings, nil
	s.mu.Unlock()
	for _, w := range warnings {
		s.log.Warn("policy", "warning", w)
	}
	s.log.Info("policy loaded", "path", s.path, "rules", len(p.ACLs), "hash", p.Hash)
	return nil
}

// Reload re-reads the file. An invalid file leaves the running policy
// untouched and returns ErrPolicyInvalid with the report's Errors
// filled; a valid one replaces it, bumps the netmap generation and
// notifies the hub so every client gets a new map.
func (s *PolicyService) Reload(ctx context.Context, by Principal) (PolicyReport, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	p, err := policy.Load(s.path)
	if err != nil {
		return PolicyReport{Errors: errorLines(err)}, fmt.Errorf("%w: %w", ErrPolicyInvalid, err)
	}
	warnings, err := s.validate(ctx, p)
	if err != nil {
		return PolicyReport{Hash: p.Hash, Warnings: warnings, Errors: errorLines(err)}, fmt.Errorf("%w: %w", ErrPolicyInvalid, err)
	}
	// The generation bump and the audit row commit first; the policy is
	// published only then, so a failed transaction leaves the previous
	// policy in force, as the caller's log line says.
	if err := s.store.InTx(ctx, func(tx *store.Store) error {
		if _, err := tx.Meta().IncrementGeneration(ctx); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, by, AuditPolicyReload, s.path, map[string]string{"hash": p.Hash, "rules": strconv.Itoa(len(p.ACLs))})
	}); err != nil {
		return PolicyReport{}, fmt.Errorf("control: bump generation after policy reload: %w", err)
	}
	s.mu.Lock()
	s.current, s.warnings, s.compiled = p, warnings, nil
	s.mu.Unlock()
	if s.notifier != nil {
		s.notifier.Changed()
	}
	c := s.Compiled(ctx)
	s.log.Info("policy reloaded", "path", s.path, "rules", len(p.ACLs), "hash", p.Hash, "visible_pairs", c.Summary().VisiblePairs)
	return PolicyReport{Hash: p.Hash, Summary: c.Summary(), Warnings: nonNil(warnings)}, nil
}

// Check validates a document against the registry without installing
// it and reports what it would compile to.
func (s *PolicyService) Check(ctx context.Context, data []byte) PolicyReport {
	p, err := policy.Parse(data)
	if err != nil {
		return PolicyReport{Errors: errorLines(err), Warnings: []string{}}
	}
	warnings, err := s.validate(ctx, p)
	if err != nil {
		return PolicyReport{Hash: p.Hash, Warnings: nonNil(warnings), Errors: errorLines(err)}
	}
	peers, _, cerr := s.registry(ctx)
	if cerr != nil {
		return PolicyReport{Hash: p.Hash, Warnings: nonNil(warnings), Errors: []string{cerr.Error()}}
	}
	return PolicyReport{Hash: p.Hash, Summary: policy.CompileWith(p, peers, s.overlay).Summary(), Warnings: nonNil(warnings)}
}

// Show reports the effective policy with its source.
func (s *PolicyService) Show(ctx context.Context) PolicyReport {
	s.mu.Lock()
	p, warnings := s.current, s.warnings
	s.mu.Unlock()
	c := s.Compiled(ctx)
	return PolicyReport{Hash: p.Hash, Summary: c.Summary(), Warnings: nonNil(warnings), Source: string(p.Source)}
}

// Current returns the running policy.
func (s *PolicyService) Current() *policy.Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// Compiled returns the running policy compiled against the registry,
// recompiling when the policy or the persisted generation changed.
//
// s.mu is never held while the store is read: enrolment, rename and
// token creation call Current (through PeerRefs) inside a transaction
// that holds the store's only connection, so a registry read under s.mu
// would wait on them while they wait on s.mu.
func (s *PolicyService) Compiled(ctx context.Context) *policy.Compiled {
	gen, err := s.store.Meta().Generation(ctx)
	if err != nil {
		s.log.Warn("policy: read generation", "err", err)
		gen = -1
	}
	s.mu.Lock()
	cur, cached := s.current, s.compiled
	hit := cached != nil && s.cacheGen == gen && s.cacheKey == cur.Hash && gen >= 0
	s.mu.Unlock()
	if hit {
		return cached
	}
	peers, _, err := s.registry(ctx)
	if err != nil {
		s.log.Warn("policy: read registry", "err", err)
		if cached != nil {
			return cached
		}
		return policy.Compile(policy.Empty(), nil)
	}
	c := policy.CompileWith(cur, peers, s.overlay)
	s.mu.Lock()
	// A reload while the registry was read published a newer policy;
	// the cache stays with that one.
	if s.current == cur {
		s.compiled, s.cacheGen, s.cacheKey = c, gen, cur.Hash
	}
	s.mu.Unlock()
	return c
}

// FilterFor returns the compiled receiver-side rules of one peer, as
// its netmap carries them.
func (s *PolicyService) FilterFor(ctx context.Context, peerID string) []FilterRule {
	return filterRules(s.Compiled(ctx).FilterFor(peerID))
}

// Load is Compiled with a background context, for PolicyVisibility.
func (s *PolicyService) Load() *policy.Compiled { return s.Compiled(context.Background()) }

// PeerRefs implements PeerRefs from the running policy.
func (s *PolicyService) PeerRefs(name string) []string {
	return s.Current().PeerReferences()[name]
}

// TagAllowed implements TagAllowed for Tokens.
func (s *PolicyService) TagAllowed(user, tag string) bool {
	return s.Load().MayUseTag(user, tag)
}

// validate checks p against users and peers.
func (s *PolicyService) validate(ctx context.Context, p *policy.Policy) ([]string, error) {
	peers, reg, err := s.registry(ctx)
	if err != nil {
		return nil, err
	}
	_ = peers
	return p.Validate(reg)
}

// registry reads what compilation and validation need.
func (s *PolicyService) registry(ctx context.Context) ([]policy.Peer, policy.Registry, error) {
	users, err := s.store.Users().List(ctx)
	if err != nil {
		return nil, policy.Registry{}, fmt.Errorf("control: policy: list users: %w", err)
	}
	peers, err := s.store.Peers().List(ctx)
	if err != nil {
		return nil, policy.Registry{}, fmt.Errorf("control: policy: list peers: %w", err)
	}
	routeRows, err := s.store.Routes().ListAll(ctx)
	if err != nil {
		return nil, policy.Registry{}, fmt.Errorf("control: policy: list routes: %w", err)
	}
	names := make(map[string]string, len(users))
	reg := policy.Registry{Overlay: s.overlay, Overlay6: s.overlay6}
	for _, u := range users {
		names[u.ID] = u.Name
		reg.Users = append(reg.Users, u.Name)
	}
	tags := map[string]bool{}
	for _, p := range peers {
		reg.Peers = append(reg.Peers, p.Name)
		for _, t := range p.Tags {
			if !tags[t] {
				tags[t] = true
				reg.Tags = append(reg.Tags, t)
			}
		}
	}
	return PolicyPeers(peers, names, ApprovedRoutes(routeRows)), reg, nil
}

// errorLines splits a joined validation error into one line per problem.
func errorLines(err error) []string {
	var out []string
	for _, line := range strings.Split(err.Error(), "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "policy: ")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
