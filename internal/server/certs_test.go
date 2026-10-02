package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/config"
)

func TestCertificateBySNI(t *testing.T) {
	pinned, acmeCert := &tls.Certificate{}, &tls.Certificate{}
	stub := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return acmeCert, nil }
	acmeSel := &certSelector{pinned: pinned, domain: "vpn.example.org", acme: stub}
	plainSel := &certSelector{pinned: pinned}

	cases := []struct {
		name string
		sel  *certSelector
		sni  string
		want *tls.Certificate
	}{
		{"pinned name", acmeSel, client.PinnedServerName, pinned},
		{"no name (old client dialling an IP)", acmeSel, "", pinned},
		{"acme domain", acmeSel, "vpn.example.org", acmeCert},
		{"acme domain, other case, trailing dot", acmeSel, "VPN.Example.ORG.", acmeCert},
		{"another name", acmeSel, "other.example.org", pinned},
		{"self-signed mode, the domain", plainSel, "vpn.example.org", pinned},
		{"self-signed mode, pinned name", plainSel, client.PinnedServerName, pinned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.sel.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.sni})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("SNI %q got the wrong certificate", tc.sni)
			}
		})
	}
	if !slices.Contains(acmeSel.nextProtos(), acme.ALPNProto) {
		t.Errorf("acme mode protocols %v lack %s", acmeSel.nextProtos(), acme.ALPNProto)
	}
	if slices.Contains(plainSel.nextProtos(), acme.ALPNProto) {
		t.Errorf("self-signed mode offers %s", acme.ALPNProto)
	}
}

func TestCertSelectorWarm(t *testing.T) {
	notAfter := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	var asked *tls.ClientHelloInfo
	sel := &certSelector{domain: "vpn.example.org", acme: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		asked = h
		return &tls.Certificate{Leaf: &x509.Certificate{NotAfter: notAfter}}, nil
	}}
	got, err := sel.warm()
	if err != nil || !got.Equal(notAfter) {
		t.Fatalf("warm = %v, %v; want %v", got, err, notAfter)
	}
	// The manager hands an ECDSA certificate only to a hello that
	// accepts one, as current browsers do.
	if asked.ServerName != "vpn.example.org" || !slices.Contains(asked.SignatureSchemes, tls.ECDSAWithP256AndSHA256) {
		t.Errorf("warm-up hello %+v", asked)
	}

	refused := errors.New("ca refused")
	sel.acme = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, refused }
	if _, err := sel.warm(); !errors.Is(err, refused) {
		t.Errorf("warm error = %v, want %v", err, refused)
	}
}

// TestACMEModeKeepsClientsOnPinnedCert runs a server in acme mode whose
// CA refuses every request: clients (pinned name) and old clients (no
// name) still get the pinned certificate, and only the domain is sent
// to the ACME manager, which fails without the CA.
func TestACMEModeKeepsClientsOnPinnedCert(t *testing.T) {
	ca := httptest.NewTLSServer(http.NotFoundHandler())
	defer ca.Close()
	cfg, _ := testConfig(t)
	cfg.TLS = config.TLS{Mode: config.TLSModeACME, Email: "ops@example.org", Domain: "vpn.example.org", ACMEDirectory: ca.URL + "/directory"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	addr := h.srv.HTTPSAddr()
	// The warm-up at start asks the CA, which refuses; it must finish
	// before the test removes data_dir/acme.
	waitFor(t, func() bool { return strings.Contains(h.logs.String(), "acme certificate not obtained") })

	tlsCfg, err := client.PinnedTLSConfig(h.srv.tlsFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := tls.Dialer{Config: tlsCfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("client dial with the pinned name: %v", err)
	}
	_ = conn.Close()

	got, err := client.ProbeFingerprint(ctx, addr, 5*time.Second)
	if err != nil || got != h.srv.tlsFingerprint {
		t.Errorf("probe: %s %v, want %s", got, err, h.srv.tlsFingerprint)
	}

	old := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}
	d = tls.Dialer{Config: old}
	conn, err = d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial without a server name: %v", err)
	}
	if fp := client.Fingerprint(conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw); fp != h.srv.tlsFingerprint {
		t.Errorf("no server name got %s, want the pinned %s", fp, h.srv.tlsFingerprint)
	}
	_ = conn.Close()

	browser := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "vpn.example.org", InsecureSkipVerify: true}
	d = tls.Dialer{Config: browser}
	if conn, err := d.DialContext(ctx, "tcp", addr); err == nil {
		fp := client.Fingerprint(conn.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw)
		_ = conn.Close()
		t.Fatalf("the acme domain got a certificate (%s) although the CA is down; pinned is %s", fp, h.srv.tlsFingerprint)
	}
}
