package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/store"
	"github.com/thedatadudech/thawr/internal/wg"
)

// Audit actions of the network lock.
const (
	AuditLockSet  = "lock.set"
	AuditPeerSign = "peer.sign"
)

// PeerSignature is one lock key's signature over a peer record as
// carried in netmaps.
type PeerSignature struct {
	Signer    lock.PublicKey
	Signature lock.Signature
}

// LockPeer is one peer as a signer sees it: enough to build and sign
// its record, plus whether the current key is already signed.
type LockPeer struct {
	ID        string
	Name      string
	Kind      string
	PublicKey string
	Signed    bool
	// LockKey is the lock public key the peer reported on sync, if any.
	LockKey string
}

// PeerSigning is one signature a signer submits together with a lock
// record.
type PeerSigning struct {
	PeerID    string
	PublicKey string
	Signer    lock.PublicKey
	Signature lock.Signature
}

// LockService keeps the lock record and the peer signatures (spec
// 012). It never holds a lock private key: signers are client devices.
type LockService struct {
	store  *store.Store
	now    func() time.Time
	log    *slog.Logger
	hubKey string
	notify Notifier
	audit  *Auditor

	// mu guards reported, the lock public keys peers announced on
	// sync; in memory only, like endpoints.
	mu       sync.Mutex
	reported map[string]string
}

// NewLockService builds the service. hubKey is the hub's WireGuard
// public key, whose record signers sign under lock.HubID.
func NewLockService(st *store.Store, now func() time.Time, log *slog.Logger, hubKey string) *LockService {
	return &LockService{store: st, now: now, log: log, hubKey: hubKey, reported: map[string]string{}}
}

// WithNotifier sets the notifier told after every change.
func (s *LockService) WithNotifier(n Notifier) *LockService {
	s.notify = n
	return s
}

// WithAuditor records lock changes and signatures in the audit log.
func (s *LockService) WithAuditor(a *Auditor) *LockService {
	s.audit = a
	return s
}

func (s *LockService) changed() {
	if s.notify != nil {
		s.notify.Changed()
	}
}

// Current returns the stored record, or nil when none was ever set.
func (s *LockService) Current(ctx context.Context) (*lock.Signed, error) {
	return LoadLockRecord(ctx, s.store)
}

// LoadLockRecord reads the signed record from meta; nil when unset.
func LoadLockRecord(ctx context.Context, st *store.Store) (*lock.Signed, error) {
	raw, err := st.Meta().Get(ctx, store.MetaLockRecord)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec lock.Signed
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, fmt.Errorf("control: lock record in meta: %w", err)
	}
	return &rec, nil
}

// Set installs a record on behalf of by. The first record (or the one
// that restarts a lineage) must come from a device an admin owns:
// otherwise any enrolled device could make itself the only signer and
// hold everyone else. Later ones must pass lock.Accept against the
// stored one. sigs are signatures by by's key in next, stored in the
// same transaction so the record and its signatures reach every
// device in one netmap.
func (s *LockService) Set(ctx context.Context, by store.Peer, next lock.Signed, sigs []PeerSigning) error {
	cur, err := s.Current(ctx)
	if err != nil {
		return err
	}
	var curRec *lock.Record
	if cur != nil {
		curRec = &cur.Record
	}
	if curRec == nil || len(curRec.Signers) == 0 {
		if err := s.requireAdminOwner(ctx, by); err != nil {
			return err
		}
	}
	if err := lock.Accept(curRec, next); err != nil {
		return fmt.Errorf("%w: %w", ErrValidation, err)
	}
	signerKey, isSigner := next.Record.SignerKey(by.ID)
	if len(sigs) > 0 && (!isSigner || !next.Record.Enabled()) {
		return fmt.Errorf("%w: only a signer of the new record may attach signatures", ErrValidation)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("control: encode lock record: %w", err)
	}
	var gen int64
	err = s.store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.Meta().Set(ctx, store.MetaLockRecord, string(data)); err != nil {
			return err
		}
		for _, sg := range sigs {
			if sg.Signer != signerKey {
				return fmt.Errorf("%w: signature over %s is not by %s's key in the record", ErrValidation, sg.PeerID, by.Name)
			}
			if err := s.signInTx(ctx, tx, by, sg); err != nil {
				return err
			}
		}
		gen, err = tx.Meta().IncrementGeneration(ctx)
		if err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, PeerPrincipal(by.Name), AuditLockSet, "lock", map[string]string{
			"generation": strconv.FormatUint(next.Record.Generation, 10), "signers": strconv.Itoa(len(next.Record.Signers)),
			"disabled": strconv.FormatBool(next.Record.Disabled), "by_key": lock.Fingerprint(signerOf(next))})
	})
	if err != nil {
		return err
	}
	s.changed()
	s.log.Info("lock record set", "generation", next.Record.Generation, "signers", len(next.Record.Signers), "disabled", next.Record.Disabled, "by", by.Name, "netmap_generation", gen)
	return nil
}

// signerOf returns the key of the record's own signer list that
// verifies its signature, for the audit row; zero when none does (a
// disable record signed by a previous key).
func signerOf(rec lock.Signed) lock.PublicKey {
	msg, err := rec.Record.Bytes()
	if err != nil {
		return lock.PublicKey{}
	}
	for _, sg := range rec.Record.Signers {
		if lock.Verify(sg.Key, msg, rec.Signature) {
			return sg.Key
		}
	}
	return lock.PublicKey{}
}

// requireAdminOwner refuses a peer whose owner is not an admin user.
func (s *LockService) requireAdminOwner(ctx context.Context, by store.Peer) error {
	if by.OwnerID == "" {
		return fmt.Errorf("%w: the first lock record must come from a device owned by an admin; %s has no owner", ErrForbidden, by.Name)
	}
	owner, err := s.store.Users().GetByID(ctx, by.OwnerID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: the first lock record must come from a device owned by an admin", ErrForbidden)
	}
	if err != nil {
		return err
	}
	if owner.Role != store.RoleAdmin {
		return fmt.Errorf("%w: the first lock record must come from a device owned by an admin; %s belongs to %s (%s)", ErrForbidden, by.Name, owner.Name, owner.Role)
	}
	return nil
}

// signerKeyOf checks that the current record names by as signer with
// that key. It reads through st so a caller inside a
// transaction passes the transaction store: the pool has one SQLite
// connection and a read on it would wait for the open transaction.
func (s *LockService) signerKeyOf(ctx context.Context, st *store.Store, by store.Peer, key lock.PublicKey) error {
	cur, err := LoadLockRecord(ctx, st)
	if err != nil {
		return err
	}
	if cur == nil || !cur.Record.Enabled() {
		return fmt.Errorf("%w: the network lock is not enabled", ErrForbidden)
	}
	want, ok := cur.Record.SignerKey(by.ID)
	if !ok || want != key {
		return fmt.Errorf("%w: %s is not a signer with key %s", ErrForbidden, by.Name, lock.Fingerprint(key))
	}
	return nil
}

// Record returns the peer record a signer signs for peerID, resolving
// the hub and checking that publicKey is the peer's current key.
func (s *LockService) Record(ctx context.Context, st *store.Store, peerID, publicKey string) (lock.PeerRecord, string, error) {
	name := peerID
	current := s.hubKey
	if peerID != lock.HubID {
		p, err := st.Peers().GetByID(ctx, peerID)
		if errors.Is(err, store.ErrNotFound) {
			return lock.PeerRecord{}, "", fmt.Errorf("peer %s: %w", peerID, ErrNotFound)
		}
		if err != nil {
			return lock.PeerRecord{}, "", err
		}
		name, current = p.Name, p.PublicKey
	}
	if publicKey != current {
		return lock.PeerRecord{}, "", fmt.Errorf("%w: %s is not the current key of %s", ErrValidation, wg.Fingerprint(mustKey(publicKey)), name)
	}
	key, err := parsePublicKey(publicKey)
	if err != nil {
		return lock.PeerRecord{}, "", err
	}
	return lock.PeerRecord{ID: peerID, Name: name, Key: [32]byte(key)}, name, nil
}

// Sign stores by's signature over peerID's current record.
func (s *LockService) Sign(ctx context.Context, by store.Peer, peerID, publicKey string, signer lock.PublicKey, sig lock.Signature) error {
	if err := s.signerKeyOf(ctx, s.store, by, signer); err != nil {
		return err
	}
	err := s.store.InTx(ctx, func(tx *store.Store) error {
		return s.signInTx(ctx, tx, by, PeerSigning{PeerID: peerID, PublicKey: publicKey, Signer: signer, Signature: sig})
	})
	if err != nil {
		return err
	}
	s.changed()
	return nil
}

// signInTx verifies one signature against the peer's current record
// and stores it with its audit row; the caller has checked that the
// signer key belongs to by.
func (s *LockService) signInTx(ctx context.Context, tx *store.Store, by store.Peer, sg PeerSigning) error {
	rec, name, err := s.Record(ctx, tx, sg.PeerID, sg.PublicKey)
	if err != nil {
		return err
	}
	msg, err := rec.Bytes()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if !lock.Verify(sg.Signer, msg, sg.Signature) {
		return fmt.Errorf("%w: signature over %s does not verify", ErrValidation, name)
	}
	if err := tx.Signatures().Put(ctx, store.PeerSignature{PeerID: sg.PeerID, PublicKey: sg.PublicKey, SignerKey: sg.Signer.String(), Signature: sg.Signature.String(), SignedAt: s.now()}); err != nil {
		return err
	}
	if _, err := tx.Meta().IncrementGeneration(ctx); err != nil {
		return err
	}
	if err := s.audit.Record(ctx, tx, PeerPrincipal(by.Name), AuditPeerSign, sg.PeerID,
		map[string]string{"name": name, "key": wg.Fingerprint(wg.Key(rec.Key)), "signer": lock.Fingerprint(sg.Signer)}); err != nil {
		return err
	}
	s.log.Info("peer signed", "peer", name, "peer_id", sg.PeerID, "signer", lock.Fingerprint(sg.Signer), "by", by.Name)
	return nil
}

// VerifyRotation checks a signature a rotating signer sends over its
// own new key, so RotateKey can store it in the same transaction. tx is
// the store of that transaction.
func (s *LockService) VerifyRotation(ctx context.Context, tx *store.Store, by store.Peer, newPublicKey string, signer lock.PublicKey, sig lock.Signature) (store.PeerSignature, error) {
	if err := s.signerKeyOf(ctx, tx, by, signer); err != nil {
		return store.PeerSignature{}, err
	}
	key, err := parsePublicKey(newPublicKey)
	if err != nil {
		return store.PeerSignature{}, err
	}
	msg, err := lock.PeerRecord{ID: by.ID, Name: by.Name, Key: [32]byte(key)}.Bytes()
	if err != nil {
		return store.PeerSignature{}, fmt.Errorf("%w: %w", ErrValidation, err)
	}
	if !lock.Verify(signer, msg, sig) {
		return store.PeerSignature{}, fmt.Errorf("%w: rotation signature does not verify", ErrValidation)
	}
	return store.PeerSignature{PeerID: by.ID, PublicKey: newPublicKey, SignerKey: signer.String(), Signature: sig.String(), SignedAt: s.now()}, nil
}

// IsSigner reports whether peerID is a signer of the current record.
func (s *LockService) IsSigner(ctx context.Context, peerID string) (bool, error) {
	cur, err := s.Current(ctx)
	if err != nil || cur == nil || !cur.Record.Enabled() {
		return false, err
	}
	_, ok := cur.Record.SignerKey(peerID)
	return ok, nil
}

// ReportKey remembers the lock public key a peer announced on sync
// (empty forgets it).
func (s *LockService) ReportKey(peerID, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" {
		delete(s.reported, peerID)
		return
	}
	s.reported[peerID] = key
}

// ListPeers returns every peer and the hub with their signing state,
// for a signer choosing what to sign.
func (s *LockService) ListPeers(ctx context.Context) ([]LockPeer, LockPeer, error) {
	cur, err := s.Current(ctx)
	if err != nil {
		return nil, LockPeer{}, err
	}
	all, err := s.store.Peers().List(ctx)
	if err != nil {
		return nil, LockPeer{}, err
	}
	sigs, err := s.store.Signatures().ListAll(ctx)
	if err != nil {
		return nil, LockPeer{}, err
	}
	idx := IndexSignatures(sigs)
	var set lock.Record
	if cur != nil {
		set = cur.Record
	}
	s.mu.Lock()
	reported := make(map[string]string, len(s.reported))
	for k, v := range s.reported {
		reported[k] = v
	}
	s.mu.Unlock()
	out := make([]LockPeer, 0, len(all))
	for _, p := range all {
		out = append(out, LockPeer{ID: p.ID, Name: p.Name, Kind: p.Kind, PublicKey: p.PublicKey, LockKey: reported[p.ID],
			Signed: IsSigned(set, lock.PeerRecord{ID: p.ID, Name: p.Name, Key: [32]byte(mustKey(p.PublicKey))}, idx[p.ID+"\x00"+p.PublicKey])})
	}
	hub := LockPeer{ID: lock.HubID, Name: lock.HubID, Kind: store.KindServer, PublicKey: s.hubKey,
		Signed: IsSigned(set, lock.PeerRecord{ID: lock.HubID, Name: lock.HubID, Key: [32]byte(mustKey(s.hubKey))}, idx[lock.HubID+"\x00"+s.hubKey])}
	return out, hub, nil
}

// IndexSignatures groups stored signatures by peer id and public key
// (joined by a NUL), converting them to the netmap form.
func IndexSignatures(rows []store.PeerSignature) map[string][]PeerSignature {
	idx := map[string][]PeerSignature{}
	for _, r := range rows {
		signer, err := lock.ParsePublicKey(r.SignerKey)
		if err != nil {
			continue
		}
		sig, err := lock.ParseSignature(r.Signature)
		if err != nil {
			continue
		}
		k := r.PeerID + "\x00" + r.PublicKey
		idx[k] = append(idx[k], PeerSignature{Signer: signer, Signature: sig})
	}
	return idx
}

// IsSigned reports whether one of sigs is a valid signature over rec
// by a key of set.
func IsSigned(set lock.Record, rec lock.PeerRecord, sigs []PeerSignature) bool {
	if !set.Enabled() {
		return false
	}
	msg, err := rec.Bytes()
	if err != nil {
		return false
	}
	for _, s := range sigs {
		if set.Has(s.Signer) && lock.Verify(s.Signer, msg, s.Signature) {
			return true
		}
	}
	return false
}

// mustKey parses a stored key; a stored key always parses, an empty
// one yields the zero key.
func mustKey(s string) wg.Key {
	k, _ := wg.ParseKey(s)
	return k
}
