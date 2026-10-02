package client

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// FingerprintPrefix is the scheme of certificate fingerprints.
const FingerprintPrefix = "sha256:"

// PinnedServerName is the TLS server name (SNI) every client sends. The
// server answers it with the self-signed certificate clients pin, even
// when it also holds an ACME certificate for browsers (spec 014). The
// .invalid top-level domain is reserved (RFC 2606), so the name never
// belongs to a real host.
const PinnedServerName = "thawr-pinned.invalid"

// ErrFingerprintMismatch means the server presented a certificate other
// than the pinned one.
var ErrFingerprintMismatch = errors.New("client: server certificate does not match the pinned fingerprint")

// Fingerprint returns sha256:<hex> of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return FingerprintPrefix + hex.EncodeToString(sum[:])
}

// ValidFingerprint reports whether s has the sha256:<64 hex> shape.
func ValidFingerprint(s string) bool {
	h, ok := strings.CutPrefix(s, FingerprintPrefix)
	if !ok || len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// PinnedTLSConfig trusts exactly one server certificate, identified by
// fingerprint, regardless of certificate authorities. Thawr servers use
// self-signed certificates by default, so pinning is the trust model.
func PinnedTLSConfig(fingerprint string) (*tls.Config, error) {
	if !ValidFingerprint(fingerprint) {
		return nil, fmt.Errorf("client: fingerprint %q must be sha256:<64 hex characters>", fingerprint)
	}
	want := strings.ToLower(fingerprint)
	check := func(der []byte) error {
		got := Fingerprint(der)
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			return fmt.Errorf("%w (server presented %s)", ErrFingerprintMismatch, got)
		}
		return nil
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ServerName:             PinnedServerName,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true, //nolint:gosec // replaced by fingerprint pinning below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrFingerprintMismatch
			}
			return check(rawCerts[0])
		},
		// VerifyConnection also covers resumed sessions.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrFingerprintMismatch
			}
			return check(cs.PeerCertificates[0].Raw)
		},
	}, nil
}

// ProbeFingerprint connects to addr and returns the fingerprint of the
// certificate it presents, for explicit trust-on-first-use.
func ProbeFingerprint(ctx context.Context, addr string, timeout time.Duration) (string, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         PinnedServerName,
			InsecureSkipVerify: true, //nolint:gosec // probe only; nothing is sent on this connection
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("client: connect to %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("client: %s presented no certificate", addr)
	}
	return Fingerprint(certs[0].Raw), nil
}
