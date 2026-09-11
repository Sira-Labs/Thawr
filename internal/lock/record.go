package lock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Canonical record prefixes; a signature over one kind of record can
// never be replayed as the other.
const (
	peerPrefix = "thawr/peer/v1\n"
	lockPrefix = "thawr/lock/v1\n"
)

// HubID is the peer id the hub's record carries; the hub has no peers
// row.
const HubID = "hub"

// Errors of Accept.
var (
	// ErrStale means the record's generation does not exceed the
	// current one (a replay or an old record).
	ErrStale = errors.New("lock: record generation is not newer")
	// ErrNotSigned means the signature does not verify against any key
	// of the current signer set.
	ErrNotSigned = errors.New("lock: record is not signed by a current lock key")
	// ErrInvalid means the record itself is malformed.
	ErrInvalid = errors.New("lock: invalid record")
)

// maxField bounds every length-prefixed field.
const maxField = 65535

// PeerRecord is what a lock key signs for one peer: the server's id
// for it, the name people type, and the WireGuard public key. The hub
// is the record (HubID, HubID, hub key).
type PeerRecord struct {
	ID   string
	Name string
	Key  [32]byte
}

// Bytes returns the canonical encoding: the prefix, then id, name and
// key each as a big-endian uint16 length followed by the bytes.
func (r PeerRecord) Bytes() ([]byte, error) {
	if r.ID == "" || r.Name == "" {
		return nil, fmt.Errorf("%w: peer record needs id and name", ErrInvalid)
	}
	var b bytes.Buffer
	b.WriteString(peerPrefix)
	for _, f := range [][]byte{[]byte(r.ID), []byte(r.Name), r.Key[:]} {
		if err := writeField(&b, f); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// Signer is one device allowed to sign: its lock key and its peer id.
type Signer struct {
	Key    PublicKey `json:"key"`
	PeerID string    `json:"peer_id"`
}

// Record is the trusted signer set. A record with Disabled set turns
// the lock off; it is signed like any other so the server cannot do
// that on its own.
type Record struct {
	Generation uint64   `json:"generation"`
	Disabled   bool     `json:"disabled"`
	Signers    []Signer `json:"signers"`
}

// Bytes returns the canonical encoding with signers sorted by key.
func (r Record) Bytes() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	signers := r.sorted()
	var b bytes.Buffer
	b.WriteString(lockPrefix)
	_ = binary.Write(&b, binary.BigEndian, r.Generation)
	disabled := byte(0)
	if r.Disabled {
		disabled = 1
	}
	b.WriteByte(disabled)
	_ = binary.Write(&b, binary.BigEndian, uint16(len(signers))) //nolint:gosec // bounded by validate
	for _, s := range signers {
		if err := writeField(&b, s.Key[:]); err != nil {
			return nil, err
		}
		if err := writeField(&b, []byte(s.PeerID)); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// Has reports whether key is in the signer set.
func (r Record) Has(key PublicKey) bool {
	for _, s := range r.Signers {
		if s.Key == key {
			return true
		}
	}
	return false
}

// SignerKey returns the lock key of the signer with that peer id.
func (r Record) SignerKey(peerID string) (PublicKey, bool) {
	for _, s := range r.Signers {
		if s.PeerID == peerID {
			return s.Key, true
		}
	}
	return PublicKey{}, false
}

// Enabled reports whether the record turns the lock on.
func (r Record) Enabled() bool { return !r.Disabled && len(r.Signers) > 0 }

func (r Record) validate() error {
	if len(r.Signers) > maxField {
		return fmt.Errorf("%w: too many signers", ErrInvalid)
	}
	if !r.Disabled && len(r.Signers) == 0 {
		return fmt.Errorf("%w: an enabled record needs at least one signer", ErrInvalid)
	}
	seen := map[PublicKey]bool{}
	for _, s := range r.Signers {
		if s.Key.IsZero() || s.PeerID == "" {
			return fmt.Errorf("%w: signer needs key and peer id", ErrInvalid)
		}
		if seen[s.Key] {
			return fmt.Errorf("%w: duplicate signer key %s", ErrInvalid, Fingerprint(s.Key))
		}
		seen[s.Key] = true
	}
	return nil
}

func (r Record) sorted() []Signer {
	out := append([]Signer(nil), r.Signers...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Key[:], out[j].Key[:]) < 0 })
	return out
}

// Signed is a record with the signature a lock key put on it.
type Signed struct {
	Record    Record    `json:"record"`
	Signature Signature `json:"signature"`
}

// Accept decides whether next may replace current. With no current
// record the first one is accepted as it is (first contact). Otherwise
// next must carry a higher generation and a signature by a key of the
// current set.
func Accept(current *Record, next Signed) error {
	msg, err := next.Record.Bytes()
	if err != nil {
		return err
	}
	if current == nil {
		// First contact: the record must at least be signed by one of
		// its own keys, so a garbage record never becomes the pin.
		if !signedByAny(next.Record, msg, next.Signature) {
			return ErrNotSigned
		}
		return nil
	}
	if next.Record.Generation <= current.Generation {
		return fmt.Errorf("%w: %d <= %d", ErrStale, next.Record.Generation, current.Generation)
	}
	if !signedByAny(*current, msg, next.Signature) {
		return ErrNotSigned
	}
	return nil
}

func signedByAny(set Record, msg []byte, sig Signature) bool {
	for _, s := range set.Signers {
		if Verify(s.Key, msg, sig) {
			return true
		}
	}
	return false
}

func writeField(b *bytes.Buffer, f []byte) error {
	if len(f) > maxField {
		return fmt.Errorf("%w: field of %d bytes", ErrInvalid, len(f))
	}
	_ = binary.Write(b, binary.BigEndian, uint16(len(f))) //nolint:gosec // bounded above
	b.Write(f)
	return nil
}
