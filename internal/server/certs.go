package server

import (
	"crypto/tls"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sira-labs/thawr/internal/config"
)

// certSelector picks the HTTPS certificate for each connection by its
// TLS server name (spec 014). Clients send client.PinnedServerName and
// always get the pinned certificate, so an ACME certificate and its
// renewals never touch their pins. Only the configured ACME domain is
// handed to the ACME manager; every other name, including an empty one
// (a client from before 014 dialling an IP literal), gets the pinned
// certificate.
type certSelector struct {
	pinned *tls.Certificate
	// domain and acme are empty and nil unless tls.mode is acme.
	domain string
	acme   func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// GetCertificate implements tls.Config.GetCertificate.
func (c *certSelector) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.acme != nil && strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), c.domain) {
		return c.acme(hello)
	}
	return c.pinned, nil
}

// nextProtos lists the listener's ALPN protocols; acme mode adds
// acme-tls/1 so the CA's TLS-ALPN-01 challenge is answered on the HTTPS
// port and no port 80 is needed.
func (c *certSelector) nextProtos() []string {
	protos := []string{"h2", "http/1.1"}
	if c.acme != nil {
		protos = append(protos, acme.ALPNProto)
	}
	return protos
}

// warmHello stands for a current browser: it accepts ECDSA, so the
// manager obtains the certificate browsers will be served.
var warmHello = tls.ClientHelloInfo{
	SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	SupportedCurves:  []tls.CurveID{tls.CurveP256},
	CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
}

// warm obtains, or loads from the cache, the ACME certificate. The
// server calls it once the HTTPS listener is up, so the first browser
// does not wait for issuance inside its TLS handshake (which the HTTP
// server cuts off after ten seconds) and a misconfigured domain shows
// in the log at start. It returns the certificate's expiry.
func (c *certSelector) warm() (time.Time, error) {
	hello := warmHello
	hello.ServerName = c.domain
	cert, err := c.acme(&hello)
	if err != nil {
		return time.Time{}, err
	}
	if cert.Leaf == nil {
		return time.Time{}, nil
	}
	return cert.Leaf.NotAfter, nil
}

// newCertSelector serves pinned and, in acme mode, an autocert manager
// for cfg.ACMEDomain() that caches its account key and certificates in
// data_dir/acme. The operator accepts the CA's terms by choosing
// tls.mode acme.
func newCertSelector(cfg *config.Config, pinned *tls.Certificate) *certSelector {
	sel := &certSelector{pinned: pinned}
	if cfg.TLS.Mode != config.TLSModeACME {
		return sel
	}
	sel.domain = strings.ToLower(cfg.ACMEDomain())
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, ACMEDir)),
		HostPolicy: autocert.HostWhitelist(sel.domain),
		Email:      cfg.TLS.Email,
	}
	if cfg.TLS.ACMEDirectory != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.TLS.ACMEDirectory}
	}
	sel.acme = m.GetCertificate
	return sel
}
