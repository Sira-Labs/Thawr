package wg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/thedatadudech/thawr/internal/stun"
)

// Key is a 32-byte WireGuard key (private, public or preshared).
type Key = wgtypes.Key

// GenerateKey returns a new random private key from crypto/rand via
// wgtypes; Thawr never implements key generation itself.
func GenerateKey() (Key, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Key{}, fmt.Errorf("wg: generate key: %w", err)
	}
	return k, nil
}

// ParseKey decodes a base64 key as printed by `wg`.
func ParseKey(s string) (Key, error) {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		return Key{}, fmt.Errorf("wg: parse key: %w", err)
	}
	return k, nil
}

// Fingerprint returns the first 8 hex characters of SHA-256(key), the
// only form in which keys appear in logs.
func Fingerprint(k Key) string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:4])
}

// Config is the full desired state of a WireGuard interface. Adapters
// diff it against the device; peers not listed are removed.
type Config struct {
	PrivateKey Key
	ListenPort int
	Addresses  []netip.Prefix
	Peers      []Peer
	// FwMark marks the tunnel's own packets so policy routing keeps
	// them out of the tunnel while an exit node carries the default
	// route (Linux, spec 013); zero leaves the mark unset.
	FwMark uint32
}

// Peer is one remote WireGuard peer.
type Peer struct {
	PublicKey Key
	// Endpoint is zero when unknown (the peer must initiate).
	Endpoint   netip.AddrPort
	AllowedIPs []netip.Prefix
	// Keepalive of zero disables persistent keepalive.
	Keepalive time.Duration
}

// PeerStats is the runtime state of one peer as reported by the device.
type PeerStats struct {
	PublicKey     Key
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// Device is a WireGuard interface, kernel or userspace.
type Device interface {
	// Configure applies the full desired state: listed peers are created
	// or updated in place (sessions of unchanged peers survive), peers
	// not listed are removed. A zero Endpoint leaves the current one.
	Configure(ctx context.Context, cfg Config) error
	// SetPeer creates or updates one peer without touching the others.
	SetPeer(ctx context.Context, p Peer) error
	// RemovePeer deletes one peer; a missing peer is not an error.
	RemovePeer(ctx context.Context, key Key) error
	// Stats reports per-peer counters and handshake times.
	Stats(ctx context.Context) ([]PeerStats, error)
	// Backend is "kernel", "userspace" or "fake".
	Backend() string
	// Name is the interface name actually created (macOS assigns utunN).
	Name() string
	Close() error
}

// Routable is implemented by devices that install OS routes through
// the interface for prefixes reached via peers (spec 013). The default
// route 0.0.0.0/0 is the exit node: on Linux it goes into a policy
// routing table keyed by the interface's fwmark, elsewhere it is
// refused.
type Routable interface {
	SetRoutes(ctx context.Context, prefixes []netip.Prefix) error
}

// STUNCapable is implemented by devices that can send STUN requests
// from their own WireGuard socket (the userspace adapter). The kernel
// adapter cannot share its socket, so callers fall back to a separate
// one when the assertion fails.
type STUNCapable interface {
	STUNTransport() stun.Transport
}

// Options controls Open.
type Options struct {
	// Name is the requested interface name. On macOS it must be "utun"
	// (kernel-assigned number) or "utunN".
	Name string
	// MTU defaults to 1420.
	MTU    int
	Logger *slog.Logger
	// ForceUserspace skips the kernel adapter even where available.
	ForceUserspace bool
}

// DefaultMTU is WireGuard's conventional MTU for IPv4 over Ethernet.
const DefaultMTU = 1420

// Errors of the router and exit-node features (spec 013).
var (
	// ErrRouterUnsupported means this platform cannot forward and
	// masquerade for other peers in this release (Linux only).
	ErrRouterUnsupported = errors.New("wg: subnet routers and exit nodes need Linux in this release")
	// ErrExitNodeUnsupported means this platform cannot route its
	// default route through a peer in this release (Linux only).
	ErrExitNodeUnsupported = errors.New("wg: using an exit node needs Linux in this release")
)

// Errors returned by Open.
var (
	// ErrKernelUnavailable means the kernel module is missing on this
	// host; Open falls back to userspace on it.
	ErrKernelUnavailable = errors.New("wg: kernel WireGuard unavailable")
	// ErrPlatformUnsupported means no adapter works on this OS yet.
	ErrPlatformUnsupported = errors.New("wg: platform not supported")
)

func (o Options) withDefaults() Options {
	if o.MTU == 0 {
		o.MTU = DefaultMTU
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}
