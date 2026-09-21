package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/thedatadudech/thawr/internal/control/policy"
	"github.com/thedatadudech/thawr/internal/store"
)

// MaxAdvertisedRoutes bounds the prefixes one peer may advertise.
const MaxAdvertisedRoutes = 64

// RoutesService stores what peers advertise as subnet routers or exit
// nodes and what admins approved (spec 013). The policy decides who may
// use an approved route; this service only keeps the rows.
type RoutesService struct {
	store   *store.Store
	log     *slog.Logger
	now     func() time.Time
	overlay netip.Prefix
	notify  Notifier
	audit   *Auditor
}

// NewRoutesService builds the service. overlay is the prefix no route
// may overlap.
func NewRoutesService(st *store.Store, log *slog.Logger, now func() time.Time, overlay netip.Prefix) *RoutesService {
	if now == nil {
		now = time.Now
	}
	return &RoutesService{store: st, log: log, now: now, overlay: overlay}
}

// WithNotifier sets the notifier told after every change.
func (s *RoutesService) WithNotifier(n Notifier) *RoutesService {
	s.notify = n
	return s
}

// WithAuditor records advertisements and approvals in the audit log.
func (s *RoutesService) WithAuditor(a *Auditor) *RoutesService {
	s.audit = a
	return s
}

func (s *RoutesService) changed() {
	if s.notify != nil {
		s.notify.Changed()
	}
}

// ParseRoutePrefixes validates a list of advertised prefixes: canonical
// IPv4 CIDRs outside overlay, no duplicates, at most MaxAdvertisedRoutes.
func ParseRoutePrefixes(raw []string, overlay netip.Prefix) ([]netip.Prefix, error) {
	if len(raw) > MaxAdvertisedRoutes {
		return nil, fmt.Errorf("%w: at most %d routes", ErrValidation, MaxAdvertisedRoutes)
	}
	seen := make(map[netip.Prefix]bool, len(raw))
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return nil, fmt.Errorf("%w: route %q: %w", ErrValidation, r, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("%w: route %q: only IPv4 prefixes are supported", ErrValidation, r)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("%w: route %q is not canonical (use %s)", ErrValidation, r, p.Masked())
		}
		if overlay.IsValid() && p != policy.ExitPrefix && p.Overlaps(overlay) {
			return nil, fmt.Errorf("%w: route %q overlaps the overlay %s", ErrValidation, r, overlay)
		}
		if seen[p] {
			return nil, fmt.Errorf("%w: route %q listed twice", ErrValidation, r)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// Advertise makes prefixes the complete advertised set of the calling
// peer. New prefixes wait for approval; withdrawn ones lose it. Every
// change is audited and bumps the generation.
func (s *RoutesService) Advertise(ctx context.Context, by store.Peer, raw []string) ([]store.PeerRoute, error) {
	if by.Mode == store.ModeStatic {
		return nil, fmt.Errorf("%w: static peers cannot advertise routes", ErrForbidden)
	}
	prefixes, err := ParseRoutePrefixes(raw, s.overlay)
	if err != nil {
		return nil, err
	}
	texts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		texts = append(texts, p.String())
	}
	actor := PeerPrincipal(by.Name)
	var added, removed []string
	err = s.store.InTx(ctx, func(tx *store.Store) error {
		var err error
		added, removed, err = tx.Routes().Replace(ctx, by.ID, texts, s.now())
		if err != nil {
			return err
		}
		for _, p := range added {
			if err := s.audit.Record(ctx, tx, actor, AuditRouteAdvertise, by.ID, map[string]string{"name": by.Name, "prefix": p}); err != nil {
				return err
			}
		}
		for _, p := range removed {
			if err := s.audit.Record(ctx, tx, actor, AuditRouteWithdraw, by.ID, map[string]string{"name": by.Name, "prefix": p}); err != nil {
				return err
			}
		}
		if len(added)+len(removed) == 0 {
			return nil
		}
		_, err = tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("control: advertise routes of %s: %w", by.ID, err)
	}
	if len(added)+len(removed) > 0 {
		s.changed()
		s.log.Info("routes advertised", "peer", by.Name, "added", added, "withdrawn", removed)
	}
	return s.store.Routes().ListPeer(ctx, by.ID)
}

// SetApproved approves or revokes one advertised prefix of the named
// peer (admins only).
func (s *RoutesService) SetApproved(ctx context.Context, by Principal, name, prefix string, approved bool) error {
	if !by.IsAdmin() {
		return ErrForbidden
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("%w: prefix %q: %w", ErrValidation, prefix, err)
	}
	peer, err := s.store.Peers().GetByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("peer %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return err
	}
	action := AuditRouteApprove
	if !approved {
		action = AuditRouteRevoke
	}
	err = s.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.Routes().SetApproved(ctx, peer.ID, p.Masked().String(), by.Name, approved, s.now()); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%w: %s does not advertise %s", ErrNotFound, name, p.Masked())
			}
			return err
		}
		if err := s.audit.Record(ctx, tx, by, action, peer.ID, map[string]string{"name": name, "prefix": p.Masked().String()}); err != nil {
			return err
		}
		_, err := tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return err
	}
	s.changed()
	s.log.Info("route approval changed", "peer", name, "prefix", p.Masked().String(), "approved", approved, "by", by.Name)
	return nil
}

// List returns the advertised prefixes of one peer, subject to the
// registry's visibility: admins see every peer, members their own.
func (s *RoutesService) List(ctx context.Context, by Principal, name string) ([]store.PeerRoute, error) {
	peer, err := s.store.Peers().GetByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !by.IsAdmin() && peer.OwnerID != by.UserID) {
		return nil, fmt.Errorf("peer %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.store.Routes().ListPeer(ctx, peer.ID)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		rows = []store.PeerRoute{}
	}
	return rows, nil
}

// ListAll returns every advertised prefix of every peer (admins only).
func (s *RoutesService) ListAll(ctx context.Context, by Principal) ([]store.PeerRoute, error) {
	if !by.IsAdmin() {
		return nil, ErrForbidden
	}
	return s.store.Routes().ListAll(ctx)
}

// ApprovedRoutes indexes the approved prefixes by peer id, as the
// policy compiler needs them.
func ApprovedRoutes(rows []store.PeerRoute) map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	for _, r := range rows {
		if !r.Approved {
			continue
		}
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		out[r.PeerID] = append(out[r.PeerID], p)
	}
	return out
}
