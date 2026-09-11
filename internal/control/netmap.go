package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
)

// EndpointKind classifies a candidate address.
type EndpointKind int

// Endpoint kinds in probing priority order.
const (
	EndpointLocal EndpointKind = iota + 1
	EndpointReflexive
	EndpointStable
)

// String names the kind as the client and the admin API show it.
func (k EndpointKind) String() string {
	switch k {
	case EndpointLocal:
		return "local"
	case EndpointReflexive:
		return "reflexive"
	case EndpointStable:
		return "stable"
	default:
		return ""
	}
}

// Endpoint is one ip:port a peer may be reached at.
type Endpoint struct {
	Addr netip.AddrPort
	Kind EndpointKind
}

// NetPeer is one visible peer as delivered to a client.
type NetPeer struct {
	ID         string
	Name       string
	Kind       string
	Owner      string
	PublicKey  string
	IPv4       netip.Addr
	Online     bool
	Endpoints  []Endpoint
	Symmetric  bool
	Keepalive  bool
	AllowedIPs []netip.Prefix
	// ViaHub marks a static (mobile) peer: the receiver adds no
	// WireGuard peer for it because the hub routes its address.
	ViaHub bool
	// Signatures are lock signatures over this peer's current record
	// (spec 012).
	Signatures []PeerSignature
}

// HubPeer is the server's own WireGuard interface as seen by a peer.
type HubPeer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []netip.Prefix
	Signatures []PeerSignature
}

// FilterRule allows SrcIPv4 to reach the receiver on a port range.
type FilterRule struct {
	SrcIPv4 netip.Addr
	Proto   string
	PortLo  uint16
	PortHi  uint16
}

// NetMap is one peer's complete view of the network.
type NetMap struct {
	Generation int64
	SelfID     string
	SelfName   string
	SelfKind   string
	// SelfSignatures are the lock signatures over the receiver's own
	// current record (spec 012).
	SelfSignatures []PeerSignature
	SelfIPv4       netip.Addr
	Overlay        netip.Prefix
	Peers          []NetPeer
	Hub            HubPeer
	Filter         []FilterRule
	// STUN lists the server's STUN listeners as host:port.
	STUN []string
	// Lock is the current signed lock record; nil while none was set.
	Lock *lock.Signed
}

// Visibility decides whether two peers may see each other's keys and
// which sources may reach a peer on which ports.
type Visibility interface {
	Visible(a, b store.Peer) bool
	// FilterFor lists the receiver-side rules for dst; nil means no
	// port is open (ICMP between visible peers stays implicit).
	FilterFor(dst store.Peer) []FilterRule
}

// OwnerVisibility is the rule of the early specs, kept for tests: peers
// with the same non-empty owner see each other and no port is open.
type OwnerVisibility struct{}

// Visible implements Visibility.
func (OwnerVisibility) Visible(a, b store.Peer) bool {
	return a.OwnerID != "" && a.OwnerID == b.OwnerID
}

// FilterFor implements Visibility.
func (OwnerVisibility) FilterFor(store.Peer) []FilterRule { return nil }

// HubConfig describes the server's WireGuard interface for netmaps.
type HubConfig struct {
	PublicKey string
	Endpoint  string
	Address   netip.Addr
	Overlay   netip.Prefix
	// STUNAddrs are the public host:port of the STUN listeners.
	STUNAddrs []string
}

// Presence reports whether a peer is online.
type Presence interface {
	Online(peerID string) bool
}

// NetMapBuilder computes per-peer netmaps from the store and the
// in-memory tables.
type NetMapBuilder struct {
	store      *store.Store
	visibility Visibility
	endpoints  *EndpointTable
	presence   Presence
	hub        HubConfig
	generation func() int64
}

// NewNetMapBuilder builds the netmap builder. generation supplies the
// current sequence number.
func NewNetMapBuilder(st *store.Store, vis Visibility, ep *EndpointTable, pr Presence, hub HubConfig, generation func() int64) *NetMapBuilder {
	return &NetMapBuilder{store: st, visibility: vis, endpoints: ep, presence: pr, hub: hub, generation: generation}
}

// Build returns the netmap for peerID or ErrNotFound when it no longer
// exists. The map contains public keys and addresses only.
func (b *NetMapBuilder) Build(ctx context.Context, peerID string) (NetMap, error) {
	self, err := b.store.Peers().GetByID(ctx, peerID)
	if errors.Is(err, store.ErrNotFound) {
		return NetMap{}, fmt.Errorf("peer %s: %w", peerID, ErrNotFound)
	}
	if err != nil {
		return NetMap{}, err
	}
	all, err := b.store.Peers().List(ctx)
	if err != nil {
		return NetMap{}, err
	}
	selfIP, err := netip.ParseAddr(self.IPv4)
	if err != nil {
		return NetMap{}, fmt.Errorf("control: peer %s address %q: %w", self.ID, self.IPv4, err)
	}
	owners, err := b.ownerNames(ctx)
	if err != nil {
		return NetMap{}, err
	}
	lockRec, err := LoadLockRecord(ctx, b.store)
	if err != nil {
		return NetMap{}, err
	}
	sigRows, err := b.store.Signatures().ListAll(ctx)
	if err != nil {
		return NetMap{}, err
	}
	sigs := IndexSignatures(sigRows)
	nm := NetMap{
		Generation:     b.generation(),
		SelfID:         self.ID,
		SelfName:       self.Name,
		SelfKind:       self.Kind,
		SelfIPv4:       selfIP,
		SelfSignatures: sigs[self.ID+"\x00"+self.PublicKey],
		Overlay:        b.hub.Overlay,
		Hub: HubPeer{
			PublicKey:  b.hub.PublicKey,
			Endpoint:   b.hub.Endpoint,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.hub.Address, 32)},
			Signatures: sigs[lock.HubID+"\x00"+b.hub.PublicKey],
		},
		Lock:   lockRec,
		Peers:  []NetPeer{},
		Filter: append([]FilterRule{}, b.visibility.FilterFor(self)...),
		STUN:   append([]string{}, b.hub.STUNAddrs...),
	}
	for _, p := range all {
		if p.ID == self.ID {
			continue
		}
		ip, err := netip.ParseAddr(p.IPv4)
		if err != nil {
			continue
		}
		if !b.visibility.Visible(self, p) {
			continue
		}
		online := false
		if b.presence != nil {
			online = b.presence.Online(p.ID)
		}
		// Static peers are reached through the hub: their address is
		// routed to the hub and they appear as via-hub entries so status
		// and the receiver-side filter know them.
		if p.Mode == store.ModeStatic {
			nm.Hub.AllowedIPs = append(nm.Hub.AllowedIPs, netip.PrefixFrom(ip, 32))
			nm.Peers = append(nm.Peers, NetPeer{ID: p.ID, Name: p.Name, Kind: p.Kind, Owner: owners[p.OwnerID],
				PublicKey: p.PublicKey, IPv4: ip, Online: online, ViaHub: true, Signatures: sigs[p.ID+"\x00"+p.PublicKey]})
			continue
		}
		var (
			eps       []Endpoint
			symmetric bool
		)
		if b.endpoints != nil {
			eps, symmetric = b.endpoints.Get(p.ID)
		}
		nm.Peers = append(nm.Peers, NetPeer{
			ID:         p.ID,
			Name:       p.Name,
			Kind:       p.Kind,
			Owner:      owners[p.OwnerID],
			PublicKey:  p.PublicKey,
			IPv4:       ip,
			Online:     online,
			Endpoints:  eps,
			Symmetric:  symmetric,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)},
			Signatures: sigs[p.ID+"\x00"+p.PublicKey],
		})
	}
	return nm, nil
}

// ownerNames maps user ids to names so netmaps can show owners.
func (b *NetMapBuilder) ownerNames(ctx context.Context) (map[string]string, error) {
	users, err := b.store.Users().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("control: list users: %w", err)
	}
	names := make(map[string]string, len(users))
	for _, u := range users {
		names[u.ID] = u.Name
	}
	return names, nil
}
