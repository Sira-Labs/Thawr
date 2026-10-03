package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// ErrOverlayIPv6Changed means overlay.ipv6 in the config differs from the
// prefix the database recorded; starting would change every peer's IPv6
// address.
var ErrOverlayIPv6Changed = errors.New("server: overlay.ipv6 changed")

// resolveOverlayIPv6 decides the IPv6 overlay prefix (spec 015) and
// keeps it in the database: a configured prefix is recorded on first
// use and must match afterwards; without one the recorded prefix is
// used, or a new unique local /64 is generated from rnd and recorded.
// generated reports the last case.
func resolveOverlayIPv6(ctx context.Context, configured string, meta *store.Meta, rnd io.Reader) (prefix netip.Prefix, generated bool, err error) {
	stored, err := recordedOverlayIPv6(ctx, meta)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	if err := sameOverlayIPv6(configured, stored); err != nil {
		return netip.Prefix{}, false, err
	}
	switch {
	case stored.IsValid():
		return stored, false, nil
	case configured != "":
		prefix, err = netip.ParsePrefix(configured)
		if err != nil {
			return netip.Prefix{}, false, fmt.Errorf("server: overlay.ipv6: %w", err)
		}
		prefix = prefix.Masked()
	default:
		prefix, err = control.NewULAPrefix(rnd)
		if err != nil {
			return netip.Prefix{}, false, err
		}
		generated = true
	}
	if err := meta.Set(ctx, store.MetaOverlayIPv6, prefix.String()); err != nil {
		return netip.Prefix{}, false, err
	}
	return prefix, generated, nil
}

// recordedOverlayIPv6 returns the prefix the database recorded, or the
// zero Prefix when it has none (a database from before spec 015).
func recordedOverlayIPv6(ctx context.Context, meta *store.Meta) (netip.Prefix, error) {
	v, err := meta.Get(ctx, store.MetaOverlayIPv6)
	if errors.Is(err, store.ErrNotFound) {
		return netip.Prefix{}, nil
	}
	if err != nil {
		return netip.Prefix{}, err
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("server: the database's overlay_ipv6 %q: %w", v, err)
	}
	return p, nil
}

// sameOverlayIPv6 fails when both a configured and a recorded prefix
// exist and differ.
func sameOverlayIPv6(configured string, stored netip.Prefix) error {
	if configured == "" || !stored.IsValid() {
		return nil
	}
	p, err := netip.ParsePrefix(configured)
	if err != nil {
		return fmt.Errorf("server: overlay.ipv6: %w", err)
	}
	if p.Masked() != stored {
		return fmt.Errorf("%w from %s to %s; every peer's IPv6 address would change (remove overlay.ipv6 to keep %s)",
			ErrOverlayIPv6Changed, stored, p.Masked(), stored)
	}
	return nil
}

// backfillIPv6 gives every peer without an IPv6 address the one derived
// from its IPv4 address.
func backfillIPv6(ctx context.Context, peers *store.Peers, prefix netip.Prefix) (int, error) {
	return peers.BackfillIPv6(ctx, func(v4 string) string {
		a, err := netip.ParseAddr(v4)
		if err != nil {
			return ""
		}
		if v6 := control.IPv6For(prefix, a); v6.IsValid() {
			return v6.String()
		}
		return ""
	})
}

// overlay6 is the IPv6 overlay prefix in effect, the zero Prefix before
// Run resolved it.
func (s *Server) overlay6() netip.Prefix {
	p, _ := s.cfg.OverlayPrefix6()
	return p
}

// hubAddr6 is the hub's IPv6 overlay address, derived from its IPv4 one
// like every peer's (spec 015).
func (s *Server) hubAddr6() netip.Addr {
	return control.IPv6For(s.overlay6(), s.cfg.HubAddr().Addr())
}

// hubAddresses are the hub interface's addresses: the IPv4 one with the
// overlay's prefix length and, with the IPv6 overlay, the IPv6 one with
// the /64.
func (s *Server) hubAddresses() []netip.Prefix {
	out := []netip.Prefix{s.cfg.HubAddr()}
	if a := s.hubAddr6(); a.IsValid() {
		out = append(out, netip.PrefixFrom(a, s.overlay6().Bits()))
	}
	return out
}

// peerIPv6 is p's IPv6 overlay address when p is IPv6 capable, and zero
// otherwise: the hub routes and filters IPv6 only for peers that have
// configured the address (spec 015).
func (s *Server) peerIPv6(p store.Peer) netip.Addr {
	if !p.IPv6Capable || p.IPv6 == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(p.IPv6)
	if err != nil || !s.overlay6().Contains(a) {
		return netip.Addr{}
	}
	return a
}

// addrOrEmpty prints a, or nothing for the zero address.
func addrOrEmpty(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
