package control

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
)

// newID returns a random 128-bit identifier in hex.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("control: random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// newSecret returns 32 random bytes in URL-safe base64 without padding.
func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("control: random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// hashSecret is SHA-256 in hex, the only form secrets are stored in.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validLabel reports whether s is a DNS-label style name.
func validLabel(s string) bool { return labelRe.MatchString(s) }

// HubName is the name hub.thawr gives the server's hub address; no peer
// may take it, or its name would never resolve to it.
const HubName = "hub"

// validPeerName reports whether s may name a peer: a DNS label other
// than HubName.
func validPeerName(s string) bool { return validLabel(s) && s != HubName }
