package lock

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Sizes of the encoded values.
const (
	KeySize       = ed25519.PublicKeySize
	SignatureSize = ed25519.SignatureSize
)

// PublicKey is an Ed25519 lock public key.
type PublicKey [KeySize]byte

// PrivateKey is an Ed25519 lock private key; only the seed is ever
// written to disk.
type PrivateKey struct {
	key ed25519.PrivateKey
}

// Signature is an Ed25519 signature over a record's canonical bytes.
type Signature [SignatureSize]byte

// GenerateKey creates a lock key from r (crypto/rand in production).
func GenerateKey(r io.Reader) (PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("lock: generate key: %w", err)
	}
	return PrivateKey{key: priv}, nil
}

// Public returns the key's public half.
func (k PrivateKey) Public() PublicKey {
	var pub PublicKey
	if len(k.key) == ed25519.PrivateKeySize {
		copy(pub[:], k.key.Public().(ed25519.PublicKey))
	}
	return pub
}

// IsZero reports whether the key was never set.
func (k PrivateKey) IsZero() bool { return len(k.key) == 0 }

// String encodes the 32-byte seed in base64, the form kept in lock.key.
func (k PrivateKey) String() string {
	if k.IsZero() {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.key.Seed())
}

// ParsePrivateKey decodes a base64 seed.
func ParsePrivateKey(s string) (PrivateKey, error) {
	seed, err := decode(s, ed25519.SeedSize)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("lock: private key: %w", err)
	}
	return PrivateKey{key: ed25519.NewKeyFromSeed(seed)}, nil
}

// String encodes the key in base64, like a WireGuard key.
func (p PublicKey) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// IsZero reports whether the key is unset.
func (p PublicKey) IsZero() bool { return p == PublicKey{} }

// ParsePublicKey decodes a base64 public key.
func ParsePublicKey(s string) (PublicKey, error) {
	var p PublicKey
	raw, err := decode(s, KeySize)
	if err != nil {
		return p, fmt.Errorf("lock: public key: %w", err)
	}
	copy(p[:], raw)
	return p, nil
}

// MarshalText implements encoding.TextMarshaler for JSON map keys and
// fields.
func (p PublicKey) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *PublicKey) UnmarshalText(b []byte) error {
	k, err := ParsePublicKey(string(b))
	if err != nil {
		return err
	}
	*p = k
	return nil
}

// Fingerprint is the first 8 hex characters of SHA-256 over the key,
// the form used in logs, audit rows and CLI output. It is 32 bits: fine
// for a person comparing two screens, never for authenticating a key
// (a hostile party can grind a collision), so every check takes the
// full public key.
func Fingerprint(p PublicKey) string {
	sum := sha256.Sum256(p[:])
	return hex.EncodeToString(sum[:4])
}

// String encodes the signature in base64.
func (s Signature) String() string { return base64.StdEncoding.EncodeToString(s[:]) }

// ParseSignature decodes a base64 signature.
func ParseSignature(str string) (Signature, error) {
	var s Signature
	raw, err := decode(str, SignatureSize)
	if err != nil {
		return s, fmt.Errorf("lock: signature: %w", err)
	}
	copy(s[:], raw)
	return s, nil
}

// MarshalText implements encoding.TextMarshaler.
func (s Signature) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Signature) UnmarshalText(b []byte) error {
	sig, err := ParseSignature(string(b))
	if err != nil {
		return err
	}
	*s = sig
	return nil
}

// Sign signs msg (a record's canonical bytes) with the lock key.
func Sign(k PrivateKey, msg []byte) (Signature, error) {
	var sig Signature
	if k.IsZero() {
		return sig, errors.New("lock: sign with an empty key")
	}
	copy(sig[:], ed25519.Sign(k.key, msg))
	return sig, nil
}

// Verify reports whether sig is a valid signature of msg by pub.
func Verify(pub PublicKey, msg []byte, sig Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig[:])
}

func decode(s string, want int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != want {
		return nil, fmt.Errorf("%d bytes, want %d", len(raw), want)
	}
	return raw, nil
}
