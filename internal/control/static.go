package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/sira-labs/thawr/internal/store"
	"github.com/sira-labs/thawr/internal/wg"
)

// StaticRequest describes a static (mobile) peer to create.
type StaticRequest struct {
	OwnerName string
	Name      string
	// Kind defaults to human.
	Kind string
	Tags []string
}

// StaticResult is the created peer and its private key. The key exists
// nowhere else: the caller renders it once and zeroes it.
type StaticResult struct {
	Peer       store.Peer
	PrivateKey wg.Key
	Generation int64
}

// WithOverlay sets the overlay prefix addresses are allocated from
// (needed by CreateStatic).
func (r *Registry) WithOverlay(overlay netip.Prefix) *Registry {
	r.overlay = overlay
	return r
}

// WithOverlay6 sets the IPv6 overlay prefix; static peers created with
// one get an IPv6 address and count as IPv6-capable, since their
// configuration carries both families (spec 015).
func (r *Registry) WithOverlay6(prefix netip.Prefix) *Registry {
	r.overlay6 = prefix
	return r
}

// WithTagAllowed sets the tagOwners check applied to members' requests.
func (r *Registry) WithTagAllowed(fn TagAllowed) *Registry {
	r.tagAllowed = fn
	return r
}

// CreateStatic registers a static (mobile) peer with a server-generated
// WireGuard key: admins for any owner, members for themselves and only
// with tags the policy grants them. The peer has no node secret; the
// hub routes its address. Every client gets a new netmap.
func (r *Registry) CreateStatic(ctx context.Context, by Principal, req StaticRequest) (StaticResult, error) {
	if !r.overlay.IsValid() {
		return StaticResult{}, errors.New("control: registry has no overlay prefix")
	}
	if req.OwnerName == "" {
		return StaticResult{}, fmt.Errorf("%w: owner is required", ErrValidation)
	}
	if !by.IsAdmin() && by.Name != req.OwnerName {
		return StaticResult{}, fmt.Errorf("%w: %s may only add peers for themselves", ErrForbidden, by.Name)
	}
	if req.Name == "" || !validPeerName(req.Name) {
		return StaticResult{}, fmt.Errorf("%w: name %q must be a DNS label other than %q", ErrValidation, req.Name, HubName)
	}
	if !by.IsAdmin() && r.peerRefs != nil {
		if refs := r.peerRefs(req.Name); len(refs) > 0 {
			return StaticResult{}, fmt.Errorf("%w: the policy selects peer:%s (%s); only an admin may add a peer with that name", ErrForbidden, req.Name, strings.Join(refs, ", "))
		}
	}
	kind := req.Kind
	if kind == "" {
		kind = store.KindHuman
	}
	if err := validKind(kind); err != nil {
		return StaticResult{}, err
	}
	tags, err := normalizeTags(req.Tags)
	if err != nil {
		return StaticResult{}, err
	}
	if !by.IsAdmin() {
		for _, tag := range tags {
			if r.tagAllowed == nil || !r.tagAllowed(by.Name, tag) {
				return StaticResult{}, fmt.Errorf("%w: %s may not use %s", ErrForbidden, by.Name, tag)
			}
		}
	}
	owner, err := r.store.Users().GetByName(ctx, req.OwnerName)
	if errors.Is(err, store.ErrNotFound) {
		return StaticResult{}, fmt.Errorf("%w: unknown owner %q", ErrValidation, req.OwnerName)
	}
	if err != nil {
		return StaticResult{}, err
	}
	key, err := wg.GenerateKey()
	if err != nil {
		return StaticResult{}, err
	}
	peerID, err := newID()
	if err != nil {
		return StaticResult{}, err
	}
	res := StaticResult{PrivateKey: key}
	err = r.store.InTx(ctx, func(tx *store.Store) error {
		allocated, err := tx.Peers().AllocatedIPv4s(ctx)
		if err != nil {
			return err
		}
		addrs := make([]netip.Addr, 0, len(allocated))
		for _, a := range allocated {
			if ip, err := netip.ParseAddr(a); err == nil {
				addrs = append(addrs, ip)
			}
		}
		ip, err := NextAddress(r.overlay, addrs)
		if err != nil {
			return err
		}
		res.Peer = store.Peer{
			ID: peerID, Name: req.Name, Kind: kind, Mode: store.ModeStatic, OwnerID: owner.ID, Tags: tags,
			PublicKey: key.PublicKey().String(), IPv4: ip.String(), CreatedAt: r.now(), OS: "wireguard-app",
		}
		if v6 := IPv6For(r.overlay6, ip); v6.IsValid() {
			res.Peer.IPv6, res.Peer.IPv6Capable = v6.String(), true
		}
		if err := tx.Peers().Create(ctx, res.Peer); err != nil {
			return err
		}
		if err := r.audit.Record(ctx, tx, by, AuditPeerCreateStatic, peerID,
			map[string]string{"name": req.Name, "kind": kind, "owner": owner.Name, "tags": tagsDetail(tags), "ipv4": ip.String(), "ipv6": res.Peer.IPv6, "key": wg.Fingerprint(key.PublicKey())}); err != nil {
			return err
		}
		res.Generation, err = tx.Meta().IncrementGeneration(ctx)
		return err
	})
	if err != nil {
		return StaticResult{}, err
	}
	r.changed()
	r.log.Info("static peer created", "peer", res.Peer.Name, "peer_id", res.Peer.ID, "owner", owner.Name,
		"ipv4", res.Peer.IPv4, "ipv6", res.Peer.IPv6, "key", wg.Fingerprint(key.PublicKey()), "by", by.Name, "generation", res.Generation)
	return res, nil
}
