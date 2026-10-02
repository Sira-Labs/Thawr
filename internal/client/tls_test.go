package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// testCert is a throwaway self-signed certificate for name.
func testCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sniServer serves pinned for PinnedServerName and other for any other
// name, as a server in acme mode does, and records the names it saw.
func sniServer(t *testing.T, pinned, other tls.Certificate) (addr string, seen func() []string) {
	t.Helper()
	var mu sync.Mutex
	var names []string
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			names = append(names, h.ServerName)
			mu.Unlock()
			if h.ServerName == PinnedServerName {
				return &pinned, nil
			}
			return &other, nil
		},
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(c, cfg)
				_ = tc.HandshakeContext(context.Background())
				_ = tc.Close()
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return net.JoinHostPort("localhost", port), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), names...)
	}
}

func TestPinnedDialSendsPinnedSNI(t *testing.T) {
	pinned, other := testCert(t, "thawr"), testCert(t, "localhost")
	addr, seen := sniServer(t, pinned, other)
	ctx := context.Background()

	got, err := ProbeFingerprint(ctx, addr, 5*time.Second)
	if err != nil {
		t.Fatalf("ProbeFingerprint: %v", err)
	}
	if want := Fingerprint(pinned.Certificate[0]); got != want {
		t.Errorf("probe saw %s, want the pinned certificate %s", got, want)
	}

	// A host name in the address would be the SNI without ServerName;
	// the pinned name must win so the server's other certificate is
	// never offered.
	cfg, err := PinnedTLSConfig(got)
	if err != nil {
		t.Fatal(err)
	}
	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	_ = conn.Close()

	// Pinning the other certificate fails: the server never presents it
	// to a client that asks for the pinned name.
	cfg, err = PinnedTLSConfig(Fingerprint(other.Certificate[0]))
	if err != nil {
		t.Fatal(err)
	}
	d = tls.Dialer{Config: cfg}
	if conn, err := d.DialContext(ctx, "tcp", addr); !errors.Is(err, ErrFingerprintMismatch) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("dial pinned to the other certificate: %v, want ErrFingerprintMismatch", err)
	}

	for _, n := range seen() {
		if n != PinnedServerName {
			t.Errorf("server saw SNI %q, want only %q", n, PinnedServerName)
		}
	}
}
