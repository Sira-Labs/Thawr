package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sira-labs/thawr/internal/config"
)

// TLS file names inside data_dir/tls.
const (
	TLSDir      = "tls"
	TLSCertFile = "cert.pem"
	TLSKeyFile  = "key.pem"
)

// selfSignedValidity is ten years; rotation is a phase 2 concern.
const selfSignedValidity = 10 * 365 * 24 * time.Hour

// loadTLS returns the certificate for the HTTPS listener according to
// cfg.TLS: loaded from the configured files, or loaded from data_dir/tls
// and generated there on first start.
func loadTLS(cfg *config.Config, now time.Time) (cert tls.Certificate, created bool, err error) {
	if cfg.TLS.Mode == config.TLSModeFile {
		cert, err = tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return tls.Certificate{}, false, fmt.Errorf("server: load tls files: %w", err)
		}
		return cert, false, nil
	}
	dir := filepath.Join(cfg.DataDir, TLSDir)
	certPath := filepath.Join(dir, TLSCertFile)
	keyPath := filepath.Join(dir, TLSKeyFile)
	cert, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return cert, false, nil
	}
	if !os.IsNotExist(err) {
		return tls.Certificate{}, false, fmt.Errorf("server: load %s: %w", certPath, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, false, fmt.Errorf("server: create %s: %w", dir, err)
	}
	certPEM, keyPEM, err := generateSelfSigned(cfg.PublicHost(), now)
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writeSecretFile(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, false, err
	}
	if err := writeSecretFile(certPath, certPEM); err != nil {
		return tls.Certificate{}, false, err
	}
	cert, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("server: parse generated certificate: %w", err)
	}
	return cert, true, nil
}

// generateSelfSigned creates an ECDSA P-256 server certificate for host
// (DNS name or IP address) valid for selfSignedValidity.
func generateSelfSigned(host string, now time.Time) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("server: generate tls key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("server: tls serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Thawr"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("server: create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("server: marshal tls key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// tlsFingerprint is "sha256:<hex>" of the leaf certificate's DER bytes,
// the value clients pin.
func tlsFingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return "sha256:" + hex.EncodeToString(sum[:])
}
