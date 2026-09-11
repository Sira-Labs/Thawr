package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/wg"
)

// DefaultPort is used when the server address has none.
const DefaultPort = "443"

// Options control an enrollment.
type Options struct {
	// Server is https://host[:port] or host[:port].
	Server string
	Token  string
	// Fingerprint pins the server certificate. When empty the server is
	// probed and, unless AcceptFingerprint is set, a *FingerprintError
	// reports what was seen so the operator can confirm it.
	Fingerprint       string
	AcceptFingerprint bool
	// Name optionally requests the peer name.
	Name     string
	StateDir string
	// LockSigner is the full lock public key that must have signed the
	// first lock record (spec 012); empty trusts the first record.
	LockSigner string
	// Hostname defaults to os.Hostname.
	Hostname string
	Version  string
	Timeout  time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

// FingerprintError is returned when no fingerprint was given and the
// server's was not accepted explicitly.
type FingerprintError struct {
	Server   string
	Observed string
}

func (e *FingerprintError) Error() string {
	return fmt.Sprintf("client: %s presents certificate %s; re-run with --fingerprint %s or --accept-fingerprint if you trust it",
		e.Server, e.Observed, e.Observed)
}

// Enroll registers this device: it generates the node key, connects to
// the server over pinned TLS, redeems the token and persists the state.
func Enroll(ctx context.Context, opts Options) (State, error) {
	if opts.Token == "" {
		return State{}, errors.New("client: token required")
	}
	if ls := strings.TrimSpace(opts.LockSigner); ls != "" {
		if _, err := lock.ParsePublicKey(ls); err != nil {
			return State{}, fmt.Errorf("client: --lock-signer must be the full lock public key from `thawr client lock status` on a signer: %w", err)
		}
	}
	if opts.StateDir == "" {
		opts.StateDir = DefaultDir()
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	addr, err := ServerAddr(opts.Server)
	if err != nil {
		return State{}, err
	}
	if existing, err := LoadState(opts.StateDir); err == nil {
		return State{}, fmt.Errorf("%w as %s (%s); run `thawr client down --forget` first", ErrAlreadyEnrolled, existing.Name, existing.IPv4)
	} else if !errors.Is(err, ErrNotEnrolled) {
		return State{}, err
	}

	// The certificate is checked before anything is sent: a probe shows
	// what the server presents, and the actual call pins it again.
	observed, err := ProbeFingerprint(ctx, addr, opts.Timeout)
	if err != nil {
		return State{}, err
	}
	fingerprint := strings.ToLower(opts.Fingerprint)
	switch {
	case fingerprint == "" && !opts.AcceptFingerprint:
		return State{}, &FingerprintError{Server: addr, Observed: observed}
	case fingerprint == "":
		fingerprint = observed
	case !ValidFingerprint(fingerprint):
		return State{}, fmt.Errorf("client: fingerprint %q must be sha256:<64 hex characters>", opts.Fingerprint)
	case fingerprint != observed:
		return State{}, fmt.Errorf("%w (server presented %s)", ErrFingerprintMismatch, observed)
	}
	tlsCfg, err := PinnedTLSConfig(fingerprint)
	if err != nil {
		return State{}, err
	}

	key, err := wg.GenerateKey()
	if err != nil {
		return State{}, err
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	hostname = shortHostname(hostname)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return State{}, fmt.Errorf("client: connect: %w", err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	resp, err := thawrv1.NewControlClient(conn).Enroll(ctx, &thawrv1.EnrollRequest{
		Token:         opts.Token,
		PublicKey:     key.PublicKey().String(),
		Hostname:      hostname,
		Os:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		ClientVersion: opts.Version,
		Name:          opts.Name,
	})
	if err != nil {
		return State{}, fmt.Errorf("client: enroll: %w", err)
	}

	st := State{
		Server:       addr,
		Fingerprint:  fingerprint,
		PeerID:       resp.GetPeerId(),
		Name:         resp.GetName(),
		IPv4:         resp.GetIpv4(),
		OverlayCIDR:  resp.GetOverlayCidr(),
		NodeSecret:   resp.GetNodeSecret(),
		HubPublicKey: resp.GetHubPublicKey(),
		HubEndpoint:  resp.GetHubEndpoint(),
		EnrolledAt:   opts.Now(),
		LockSigner:   strings.TrimSpace(opts.LockSigner),
	}
	if err := SaveKey(opts.StateDir, key); err != nil {
		return State{}, err
	}
	if err := SaveState(opts.StateDir, st); err != nil {
		_ = Forget(opts.StateDir)
		return State{}, err
	}
	return st, nil
}

// ServerAddr normalises https://host[:port] or host[:port] to host:port.
func ServerAddr(server string) (string, error) {
	s := strings.TrimSpace(server)
	if s == "" {
		return "", errors.New("client: server address required")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("client: server %q is not a valid URL", server)
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("client: server %q must use https", server)
		}
		if u.Path != "" && u.Path != "/" {
			return "", fmt.Errorf("client: server %q must not have a path", server)
		}
		s = u.Host
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, DefaultPort
	}
	if host == "" {
		return "", fmt.Errorf("client: server %q has no host", server)
	}
	return net.JoinHostPort(host, port), nil
}

// shortHostname keeps the first DNS label of a hostname, capped at the
// 63 characters the server accepts, so "alice-laptop.local" enrols as
// "alice-laptop" and long runner names still validate.
func shortHostname(h string) string {
	h = strings.TrimSpace(h)
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}
