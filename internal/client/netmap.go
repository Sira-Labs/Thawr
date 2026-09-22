package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/control"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/wg"
)

// NetMapFile caches the last netmap so WireGuard can be restored before
// the server is reachable.
const NetMapFile = "netmap.json"

// PeerKeepalive is the persistent keepalive toward the hub and toward
// peers flagged keepalive.
const PeerKeepalive = 25 * time.Second

// NetMap is the client-side, JSON-serialisable form of a netmap.
type NetMap struct {
	Generation int64     `json:"generation"`
	SelfID     string    `json:"self_id"`
	SelfName   string    `json:"self_name"`
	SelfKind   string    `json:"self_kind"`
	SelfIPv4   string    `json:"self_ipv4"`
	Overlay    string    `json:"overlay"`
	Peers      []Peer    `json:"peers"`
	Hub        HubPeer   `json:"hub"`
	ReceivedAt time.Time `json:"received_at"`
	// ServerVersion is what the server reported about itself.
	ServerVersion string `json:"server_version"`
	// STUN lists the server's STUN listeners as host:port.
	STUN []string `json:"stun"`
	// Filter is the receiver-side policy: who may reach this device on
	// which ports.
	Filter []FilterRule `json:"filter"`
	// SelfSignatures are the lock signatures over this device's own
	// record; Lock is the signed lock record the server offers, nil
	// when it has none (spec 012).
	SelfSignatures []PeerSignature `json:"self_signatures,omitempty"`
	Lock           *lock.Signed    `json:"lock,omitempty"`
	// Forward are the rules this device enforces as a router and
	// Advertised what the server knows about its own advertisements
	// (spec 013).
	Forward    []ForwardRule     `json:"forward,omitempty"`
	Advertised []AdvertisedRoute `json:"advertised,omitempty"`
}

// ForwardRule allows Src to reach Dst (a CIDR) through this device.
type ForwardRule struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Proto  string `json:"proto"`
	PortLo uint16 `json:"port_lo"`
	PortHi uint16 `json:"port_hi"`
}

// AdvertisedRoute is one prefix this device advertises and whether an
// admin approved it.
type AdvertisedRoute struct {
	Prefix   string `json:"prefix"`
	Approved bool   `json:"approved"`
}

// FilterRule allows Src to reach this device on a port range.
type FilterRule struct {
	Src    string `json:"src"`
	Proto  string `json:"proto"`
	PortLo uint16 `json:"port_lo"`
	PortHi uint16 `json:"port_hi"`
}

// Endpoint is one candidate address of a peer with its kind
// ("local", "reflexive" or "stable").
type Endpoint struct {
	Addr string `json:"addr"`
	Kind string `json:"kind"`
}

// Endpoint kind names as cached and shown in status.
const (
	KindLocal     = "local"
	KindReflexive = "reflexive"
	KindStable    = "stable"
)

func kindFromProto(k thawrv1.EndpointKind) string {
	switch k {
	case thawrv1.EndpointKind_ENDPOINT_KIND_LOCAL:
		return KindLocal
	case thawrv1.EndpointKind_ENDPOINT_KIND_REFLEXIVE:
		return KindReflexive
	case thawrv1.EndpointKind_ENDPOINT_KIND_STABLE:
		return KindStable
	}
	return ""
}

func kindFromName(s string) control.EndpointKind {
	switch s {
	case KindLocal:
		return control.EndpointLocal
	case KindReflexive:
		return control.EndpointReflexive
	case KindStable:
		return control.EndpointStable
	}
	return 0
}

// Candidates returns the peer's parseable endpoints in netmap order.
func (p Peer) Candidates() []control.Endpoint {
	out := make([]control.Endpoint, 0, len(p.Endpoints))
	for _, e := range p.Endpoints {
		ap, err := netip.ParseAddrPort(e.Addr)
		if err != nil {
			continue
		}
		out = append(out, control.Endpoint{Addr: ap, Kind: kindFromName(e.Kind)})
	}
	return out
}

// Peer is one visible peer.
type Peer struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Owner      string     `json:"owner"`
	PublicKey  string     `json:"public_key"`
	IPv4       string     `json:"ipv4"`
	Online     bool       `json:"online"`
	Endpoints  []Endpoint `json:"endpoints"`
	Symmetric  bool       `json:"symmetric"`
	Keepalive  bool       `json:"keepalive"`
	AllowedIPs []string   `json:"allowed_ips"`
	// ViaHub marks a static (mobile) peer reached through the hub: no
	// WireGuard peer and no path of its own.
	ViaHub bool `json:"via_hub"`
	// Signatures are the network-lock signatures over this peer's
	// current record (spec 012).
	Signatures []PeerSignature `json:"signatures,omitempty"`
	// ExitNode marks a peer this device may route its internet traffic
	// through (spec 013).
	ExitNode bool `json:"exit_node,omitempty"`
}

// PeerSignature is one lock key's signature over a peer record, as
// strings so the cached netmap stays readable.
type PeerSignature struct {
	Signer    string `json:"signer"`
	Signature string `json:"signature"`
}

// HubPeer is the server's WireGuard interface.
type HubPeer struct {
	PublicKey  string          `json:"public_key"`
	Endpoint   string          `json:"endpoint"`
	AllowedIPs []string        `json:"allowed_ips"`
	Signatures []PeerSignature `json:"signatures,omitempty"`
}

// NetMapFromProto converts a received netmap.
func NetMapFromProto(m *thawrv1.NetMap, now time.Time) NetMap {
	nm := NetMap{
		Generation:     m.GetGeneration(),
		SelfID:         m.GetSelf().GetId(),
		SelfName:       m.GetSelf().GetName(),
		SelfKind:       m.GetSelf().GetKind(),
		SelfIPv4:       m.GetSelf().GetIpv4(),
		Overlay:        m.GetSelf().GetOverlayCidr(),
		Peers:          []Peer{},
		Hub:            HubPeer{PublicKey: m.GetHub().GetPublicKey(), Endpoint: m.GetHub().GetEndpoint(), AllowedIPs: append([]string{}, m.GetHub().GetAllowedIps()...), Signatures: signaturesFromProto(m.GetHub().GetSignatures())},
		SelfSignatures: signaturesFromProto(m.GetSelf().GetSignatures()),
		Lock:           lockFromProto(m.GetLock()),
		ReceivedAt:     now,
		ServerVersion:  m.GetServerVersion(),
		STUN:           append([]string{}, m.GetSelf().GetStunAddrs()...),
		Filter:         []FilterRule{},
	}
	for _, f := range m.GetFilter() {
		if f.GetPortLo() > 65535 || f.GetPortHi() > 65535 {
			continue
		}
		nm.Filter = append(nm.Filter, FilterRule{Src: f.GetSrcIpv4(), Proto: f.GetProto(), PortLo: uint16(f.GetPortLo()), PortHi: uint16(f.GetPortHi())}) //nolint:gosec // range-checked above
	}
	for _, f := range m.GetForward() {
		if f.GetPortLo() > 65535 || f.GetPortHi() > 65535 {
			continue
		}
		nm.Forward = append(nm.Forward, ForwardRule{Src: f.GetSrcIpv4(), Dst: f.GetDstCidr(), Proto: f.GetProto(), PortLo: uint16(f.GetPortLo()), PortHi: uint16(f.GetPortHi())}) //nolint:gosec // range-checked above
	}
	for _, a := range m.GetSelf().GetAdvertised() {
		nm.Advertised = append(nm.Advertised, AdvertisedRoute{Prefix: a.GetPrefix(), Approved: a.GetApproved()})
	}
	for _, p := range m.GetPeers() {
		peer := Peer{ID: p.GetId(), Name: p.GetName(), Kind: p.GetKind(), Owner: p.GetOwner(), PublicKey: p.GetPublicKey(), IPv4: p.GetIpv4(),
			Online: p.GetOnline(), Symmetric: p.GetSymmetric(), Keepalive: p.GetKeepalive(), ViaHub: p.GetViaHub(), ExitNode: p.GetExitNode(),
			Endpoints: []Endpoint{}, AllowedIPs: append([]string{}, p.GetAllowedIps()...), Signatures: signaturesFromProto(p.GetSignatures())}
		for _, e := range p.GetEndpoints() {
			peer.Endpoints = append(peer.Endpoints, Endpoint{Addr: e.GetAddr(), Kind: kindFromProto(e.GetKind())})
		}
		nm.Peers = append(nm.Peers, peer)
	}
	return nm
}

func signaturesFromProto(in []*thawrv1.PeerSignature) []PeerSignature {
	if len(in) == 0 {
		return nil
	}
	out := make([]PeerSignature, 0, len(in))
	for _, s := range in {
		out = append(out, PeerSignature{Signer: s.GetSignerKey(), Signature: s.GetSignature()})
	}
	return out
}

// lockFromProto converts the offered lock record; a malformed one is
// dropped, which the client treats like a server offering none.
func lockFromProto(in *thawrv1.SignedLockRecord) *lock.Signed {
	if in == nil || in.GetRecord() == nil {
		return nil
	}
	out := lock.Signed{Record: lock.Record{Generation: in.GetRecord().GetGeneration(), Disabled: in.GetRecord().GetDisabled()}}
	for _, sg := range in.GetRecord().GetSigners() {
		key, err := lock.ParsePublicKey(sg.GetKey())
		if err != nil {
			return nil
		}
		out.Record.Signers = append(out.Record.Signers, lock.Signer{Key: key, PeerID: sg.GetPeerId()})
	}
	sig, err := lock.ParseSignature(in.GetSignature())
	if err != nil {
		return nil
	}
	out.Signature = sig
	return &out
}

// SaveNetMap caches nm in the state directory (mode 0600).
func SaveNetMap(dir string, nm NetMap) error {
	data, err := json.MarshalIndent(nm, "", "  ")
	if err != nil {
		return fmt.Errorf("client: encode netmap: %w", err)
	}
	return writeSecret(dir, NetMapFile, append(data, '\n'))
}

// LoadNetMap reads the cached netmap; ok is false when there is none.
func LoadNetMap(dir string) (nm NetMap, ok bool, err error) {
	data, err := os.ReadFile(filepath.Join(dir, NetMapFile))
	if errors.Is(err, os.ErrNotExist) {
		return NetMap{}, false, nil
	}
	if err != nil {
		return NetMap{}, false, fmt.Errorf("client: read netmap cache: %w", err)
	}
	if err := json.Unmarshal(data, &nm); err != nil {
		return NetMap{}, false, fmt.Errorf("client: parse %s: %w", NetMapFile, err)
	}
	return nm, true, nil
}

// BuildConfig turns a netmap into the full WireGuard configuration of
// this device: every visible peer with its allowed prefixes and the hub
// with its endpoint and keepalive. Mesh peers get no endpoint here; the
// path prober owns it (a zero endpoint leaves the device's current one).
func BuildConfig(nm NetMap, key wg.Key, listenPort int, overlay netip.Prefix) (wg.Config, error) {
	return BuildConfigWith(nm, key, listenPort, overlay, "")
}

// BuildConfigWith is BuildConfig with an exit node: the named peer, when
// the netmap flags it as one, carries 0.0.0.0/0 and the tunnel's own
// packets get the fwmark that keeps them out of it (spec 013).
func BuildConfigWith(nm NetMap, key wg.Key, listenPort int, overlay netip.Prefix, exitNode string) (wg.Config, error) {
	selfIP, err := netip.ParseAddr(nm.SelfIPv4)
	if err != nil {
		return wg.Config{}, fmt.Errorf("client: self address %q: %w", nm.SelfIPv4, err)
	}
	cfg := wg.Config{
		PrivateKey: key,
		ListenPort: listenPort,
		Addresses:  []netip.Prefix{netip.PrefixFrom(selfIP, overlay.Bits())},
	}
	if nm.Hub.PublicKey != "" {
		hubKey, err := wg.ParseKey(nm.Hub.PublicKey)
		if err != nil {
			return wg.Config{}, fmt.Errorf("client: hub key: %w", err)
		}
		hub := wg.Peer{PublicKey: hubKey, Keepalive: PeerKeepalive}
		if ep, err := resolveEndpoint(nm.Hub.Endpoint); err == nil {
			hub.Endpoint = ep
		}
		hub.AllowedIPs, err = parsePrefixes(nm.Hub.AllowedIPs)
		if err != nil {
			return wg.Config{}, fmt.Errorf("client: hub allowed ips: %w", err)
		}
		cfg.Peers = append(cfg.Peers, hub)
	}
	for _, p := range nm.Peers {
		if p.ViaHub {
			continue // the hub's allowed IPs route it
		}
		pub, err := wg.ParseKey(p.PublicKey)
		if err != nil {
			return wg.Config{}, fmt.Errorf("client: peer %s key: %w", p.Name, err)
		}
		peer := wg.Peer{PublicKey: pub}
		if p.Keepalive {
			peer.Keepalive = PeerKeepalive
		}
		peer.AllowedIPs, err = parsePrefixes(p.AllowedIPs)
		if err != nil {
			return wg.Config{}, fmt.Errorf("client: peer %s allowed ips: %w", p.Name, err)
		}
		if ip, err := netip.ParseAddr(p.IPv4); err == nil && len(peer.AllowedIPs) == 0 {
			peer.AllowedIPs = []netip.Prefix{netip.PrefixFrom(ip, 32)}
		}
		if exitNode != "" && p.ExitNode && p.Name == exitNode {
			peer.AllowedIPs = append(peer.AllowedIPs, wg.ExitRoute)
			cfg.FwMark = wg.DefaultFwMark
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg, nil
}

// RoutesOf lists the prefixes cfg reaches through peers beyond their
// own /32 addresses: what the OS routing table must carry.
func RoutesOf(cfg wg.Config, overlay netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range cfg.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() == 32 && overlay.Contains(a.Addr()) {
				continue
			}
			out = append(out, a)
		}
	}
	return out
}

// FilterSet turns the netmap's filter into the device's: visible peers
// and the hub may ping, listed sources reach the listed ports.
func FilterSet(nm NetMap, iface string, self netip.Addr) wg.FilterSet {
	return FilterSetFor(nm, iface, self, netip.Prefix{}, nil)
}

// FilterSetFor is FilterSet for a device that advertises routes: the
// netmap's forward rules whose destination lies inside a prefix this
// device itself advertises are enforced on its forwarding path and
// those prefixes are masqueraded for overlay sources (spec 013). Rules
// for anything else are dropped: a server cannot make a router forward
// what the router never offered.
func FilterSetFor(nm NetMap, iface string, self netip.Addr, overlay netip.Prefix, advertised []netip.Prefix) wg.FilterSet {
	set := wg.FilterSet{Interface: iface, Hook: wg.HookInput, Local: self}
	serves := func(dst netip.Prefix) bool {
		for _, adv := range advertised {
			if adv == wg.ExitRoute {
				if dst == wg.ExitRoute {
					return true
				}
				continue
			}
			if dst != wg.ExitRoute && adv.Bits() <= dst.Bits() && adv.Contains(dst.Addr()) {
				return true
			}
		}
		return false
	}
	for _, f := range nm.Forward {
		src, err := netip.ParseAddr(f.Src)
		if err != nil {
			continue
		}
		dst, err := netip.ParsePrefix(f.Dst)
		if err != nil || !serves(dst) {
			continue
		}
		set.Forward = append(set.Forward, wg.ForwardRule{Src: netip.PrefixFrom(src, 32), Dst: dst, Proto: f.Proto, Lo: f.PortLo, Hi: f.PortHi})
	}
	if len(advertised) > 0 {
		set.Masquerade, set.MasqueradeFrom = append([]netip.Prefix(nil), advertised...), overlay
	}
	seen := map[netip.Addr]bool{}
	visible := func(ip netip.Addr) {
		if !seen[ip] {
			seen[ip] = true
			set.Visible = append(set.Visible, ip)
		}
	}
	for _, p := range nm.Peers {
		if ip, err := netip.ParseAddr(p.IPv4); err == nil {
			visible(ip)
		}
	}
	for _, a := range nm.Hub.AllowedIPs {
		if p, err := netip.ParsePrefix(a); err == nil && p.Bits() == 32 {
			visible(p.Addr())
		}
	}
	for _, f := range nm.Filter {
		src, err := netip.ParseAddr(f.Src)
		if err != nil {
			continue
		}
		set.Rules = append(set.Rules, wg.FilterRule{Src: netip.PrefixFrom(src, 32), Proto: f.Proto, Lo: f.PortLo, Hi: f.PortHi})
	}
	return set
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}
