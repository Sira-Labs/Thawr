package client

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	thawrv1 "github.com/thedatadudech/thawr/internal/api/proto/thawr/v1"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/wg"
)

// LockKeyFile holds this device's Ed25519 lock private key (spec 012).
// It exists only on devices that ran `thawr client lock init` or
// `lock key`.
const LockKeyFile = "lock.key"

// ErrNoLockKey is returned by signing operations on a device without a
// lock key.
var ErrNoLockKey = errors.New("client: this device has no lock key; run `thawr client lock key` and let a signer add it")

// ErrNotSigner is returned when a device holds a lock key the current
// record does not name.
var ErrNotSigner = errors.New("client: this device is not a signer of the network lock")

// ErrLockOff is returned by operations that need the lock enabled.
var ErrLockOff = errors.New("client: the network lock is not enabled; run `thawr client lock init` on the device that should hold the first key")

// LoadLockKey reads LockKeyFile; a missing file is a zero key.
func LoadLockKey(dir string) (lock.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(dir, LockKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return lock.PrivateKey{}, nil
	}
	if err != nil {
		return lock.PrivateKey{}, fmt.Errorf("client: read %s: %w", LockKeyFile, err)
	}
	k, err := lock.ParsePrivateKey(strings.TrimSpace(string(data)))
	if err != nil {
		return lock.PrivateKey{}, fmt.Errorf("client: parse %s: %w", LockKeyFile, err)
	}
	return k, nil
}

// SaveLockKey writes LockKeyFile with mode 0600.
func SaveLockKey(dir string, k lock.PrivateKey) error {
	return writeSecret(dir, LockKeyFile, []byte(k.String()+"\n"))
}

// LockStatus is the network lock as this device sees it.
type LockStatus struct {
	// Enabled says whether the pinned record turns the lock on.
	Enabled bool `json:"enabled"`
	// Signer says whether this device holds a key the record names.
	Signer bool `json:"signer"`
	// HasKey says whether a lock key exists on this device at all.
	HasKey     bool               `json:"has_key"`
	Generation uint64             `json:"generation"`
	Signers    []LockSignerStatus `json:"signers"`
	// Rejected says why the record the server offers (or its absence)
	// was not adopted; empty when the pin matches the offer.
	Rejected string `json:"rejected"`
	// SelfSigned says whether this device's own record is signed while
	// the lock is on; other devices hold it until it is.
	SelfSigned bool `json:"self_signed"`
}

// LockSignerStatus is one signer of the pinned record.
type LockSignerStatus struct {
	PeerID string `json:"peer_id"`
	// Name is the signer's peer name when this device can see it.
	Name        string `json:"name"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

// LockSigned is one entry a signing operation signed.
type LockSigned struct {
	Name string `json:"name"`
	// Fingerprint is of the WireGuard key that was signed; the person
	// compares it with `thawr client status` on that device.
	Fingerprint string `json:"fingerprint"`
}

// LockResult reports a lock operation: the record generation now in
// force and the entries signed on the way.
type LockResult struct {
	Generation uint64       `json:"generation"`
	Signer     string       `json:"signer"`
	Signed     []LockSigned `json:"signed"`
	// PublicKey is this device's lock public key (lock key, lock init).
	PublicKey string `json:"public_key,omitempty"`
}

// lockStatusLocked builds LockStatus; d.mu must be held.
func (d *Daemon) lockStatusLocked() LockStatus {
	st := LockStatus{Signers: []LockSignerStatus{}, HasKey: !d.lockKey.IsZero(), Rejected: d.lockRejected}
	rec := d.pins.Lock()
	if rec == nil {
		return st
	}
	st.Generation = rec.Record.Generation
	st.Enabled = rec.Record.Enabled()
	if !st.Enabled {
		return st
	}
	names := map[string]string{d.state.PeerID: d.state.Name}
	if d.offered != nil {
		for _, p := range d.offered.Peers {
			names[p.ID] = p.Name
		}
	}
	for _, s := range rec.Record.Signers {
		st.Signers = append(st.Signers, LockSignerStatus{PeerID: s.PeerID, Name: names[s.PeerID], Key: s.Key.String(), Fingerprint: lock.Fingerprint(s.Key)})
		if !d.lockKey.IsZero() && s.Key == d.lockKey.Public() && s.PeerID == d.state.PeerID {
			st.Signer = true
		}
	}
	if d.offered != nil {
		st.SelfSigned = signedBy(rec.Record, d.state.PeerID, d.state.Name, d.key.PublicKey().String(), d.offered.SelfSignatures)
	}
	return st
}

// signerContext returns what a signing operation needs: the gRPC
// client, this device's lock key and the pinned record, checking that
// the device may sign.
func (d *Daemon) signerContext() (thawrv1.ControlClient, lock.PrivateKey, *lock.Signed, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client == nil {
		return nil, lock.PrivateKey{}, nil, errors.New("client: not connected to the server")
	}
	if d.lockKey.IsZero() {
		return nil, lock.PrivateKey{}, nil, ErrNoLockKey
	}
	rec := d.pins.Lock()
	if rec == nil || !rec.Record.Enabled() {
		return nil, lock.PrivateKey{}, nil, ErrLockOff
	}
	if k, ok := rec.Record.SignerKey(d.state.PeerID); !ok || k != d.lockKey.Public() {
		return nil, lock.PrivateKey{}, nil, ErrNotSigner
	}
	return d.client, d.lockKey, rec, nil
}

// ensureLockKey loads or creates the lock key file and returns it.
func (d *Daemon) ensureLockKey() (lock.PrivateKey, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.lockKey.IsZero() {
		return d.lockKey, false, nil
	}
	k, err := lock.GenerateKey(rand.Reader)
	if err != nil {
		return lock.PrivateKey{}, false, err
	}
	if err := SaveLockKey(d.opts.StateDir, k); err != nil {
		return lock.PrivateKey{}, false, err
	}
	d.lockKey = k
	return k, true, nil
}

// peerSigning signs (id, name, key) with k and returns the request plus
// the fingerprint of the signed WireGuard key.
func peerSigning(k lock.PrivateKey, id, name, key string) (*thawrv1.SignPeerRequest, string, error) {
	wk, err := wg.ParseKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("client: key of %s: %w", name, err)
	}
	msg, err := lock.PeerRecord{ID: id, Name: name, Key: [32]byte(wk)}.Bytes()
	if err != nil {
		return nil, "", err
	}
	sig, err := lock.Sign(k, msg)
	if err != nil {
		return nil, "", err
	}
	return &thawrv1.SignPeerRequest{PeerId: id, PublicKey: key, SignerKey: k.Public().String(), Signature: sig.String()}, wg.Fingerprint(wk), nil
}

// signPeerRecord signs (id, name, key) with k and sends it.
func signPeerRecord(ctx context.Context, client thawrv1.ControlClient, k lock.PrivateKey, id, name, key string) (string, error) {
	req, fp, err := peerSigning(k, id, name, key)
	if err != nil {
		return "", err
	}
	if _, err := client.SignPeer(ctx, req); err != nil {
		return "", fmt.Errorf("client: sign %s: %w", name, err)
	}
	return fp, nil
}

// setLockRecord signs rec with k, sends it with sigs, pins it locally
// and re-applies the last netmap.
func (d *Daemon) setLockRecord(ctx context.Context, client thawrv1.ControlClient, k lock.PrivateKey, rec lock.Record, sigs []*thawrv1.SignPeerRequest) error {
	msg, err := rec.Bytes()
	if err != nil {
		return err
	}
	sig, err := lock.Sign(k, msg)
	if err != nil {
		return err
	}
	signed := lock.Signed{Record: rec, Signature: sig}
	out := &thawrv1.LockRecord{Generation: rec.Generation, Disabled: rec.Disabled}
	for _, s := range rec.Signers {
		out.Signers = append(out.Signers, &thawrv1.LockSigner{Key: s.Key.String(), PeerId: s.PeerID})
	}
	if _, err := client.SetLock(ctx, &thawrv1.SetLockRequest{Lock: &thawrv1.SignedLockRecord{Record: out, Signature: sig.String()}, Signatures: sigs}); err != nil {
		return fmt.Errorf("client: set lock record: %w", err)
	}
	d.mu.Lock()
	err = d.pins.SetLock(signed)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.reapply(ctx)
}

// LockInit enables the network lock with this device as the only
// signer. The record and the signatures over the hub, this device and
// every peer it currently sees go to the server in one request, so
// enabling never shows another device the record without them; peers
// outside this device's policy view stay unsigned until `lock sign`,
// which lists them all.
func (d *Daemon) LockInit(ctx context.Context) (LockResult, error) {
	d.mu.Lock()
	client, offered, rec, selfKey := d.client, d.offered, d.pins.Lock(), d.key.PublicKey().String()
	d.mu.Unlock()
	if client == nil {
		return LockResult{}, errors.New("client: not connected to the server")
	}
	if offered == nil {
		return LockResult{}, errors.New("client: no netmap yet")
	}
	var gen uint64 = 1
	if rec != nil {
		if rec.Record.Enabled() {
			return LockResult{}, errors.New("client: the network lock is already enabled; use `lock add-signer` to add a signer")
		}
		gen = rec.Record.Generation + 1
	}
	k, _, err := d.ensureLockKey()
	if err != nil {
		return LockResult{}, err
	}
	res := LockResult{Generation: gen, Signer: lock.Fingerprint(k.Public()), Signed: []LockSigned{}, PublicKey: k.Public().String()}
	var sigs []*thawrv1.SignPeerRequest
	add := func(id, name, key string) error {
		req, fp, err := peerSigning(k, id, name, key)
		if err != nil {
			return err
		}
		sigs = append(sigs, req)
		res.Signed = append(res.Signed, LockSigned{Name: name, Fingerprint: fp})
		return nil
	}
	if err := add(lock.HubID, lock.HubID, offered.Hub.PublicKey); err != nil {
		return LockResult{}, err
	}
	if err := add(d.state.PeerID, d.state.Name, selfKey); err != nil {
		return LockResult{}, err
	}
	for _, p := range offered.Peers {
		if p.ViaHub || p.ID == "" || p.PublicKey == "" {
			continue
		}
		if err := add(p.ID, p.Name, p.PublicKey); err != nil {
			return LockResult{}, err
		}
	}
	record := lock.Record{Generation: gen, Signers: []lock.Signer{{Key: k.Public(), PeerID: d.state.PeerID}}}
	if err := d.setLockRecord(ctx, client, k, record, sigs); err != nil {
		return LockResult{}, err
	}
	d.log.Info("network lock enabled", "generation", gen, "signer", res.Signer, "signed", len(res.Signed))
	return res, nil
}

// LockSign signs the named peers ("all" for every unsigned one, "hub"
// for the hub) as this signer sees them through the server's full
// list. ErrUnknownPeer names an unknown entry.
func (d *Daemon) LockSign(ctx context.Context, names []string) (LockResult, error) {
	client, k, rec, err := d.signerContext()
	if err != nil {
		return LockResult{}, err
	}
	list, err := client.ListLockPeers(ctx, &thawrv1.Empty{})
	if err != nil {
		return LockResult{}, fmt.Errorf("client: list peers: %w", err)
	}
	all := append([]*thawrv1.LockPeer{list.GetHub()}, list.GetPeers()...)
	var chosen []*thawrv1.LockPeer
	for _, name := range names {
		name = stripZone(name)
		if name == "all" {
			for _, p := range all {
				if !p.GetSigned() {
					chosen = append(chosen, p)
				}
			}
			continue
		}
		i := slices.IndexFunc(all, func(p *thawrv1.LockPeer) bool { return p.GetName() == name })
		if i < 0 {
			return LockResult{}, fmt.Errorf("%w: %s", ErrUnknownPeer, name)
		}
		chosen = append(chosen, all[i])
	}
	res := LockResult{Generation: rec.Record.Generation, Signer: lock.Fingerprint(k.Public()), Signed: []LockSigned{}}
	seen := map[string]bool{}
	for _, p := range chosen {
		if seen[p.GetId()] {
			continue
		}
		seen[p.GetId()] = true
		fp, err := signPeerRecord(ctx, client, k, p.GetId(), p.GetName(), p.GetPublicKey())
		if err != nil {
			return res, err
		}
		res.Signed = append(res.Signed, LockSigned{Name: p.GetName(), Fingerprint: fp})
	}
	sort.Slice(res.Signed, func(i, j int) bool { return res.Signed[i].Name < res.Signed[j].Name })
	return res, nil
}

// LockKey creates this device's lock key if needed and returns its
// public key; the daemon reports it on its next sync so a signer can
// add this device.
func (d *Daemon) LockKey() (LockResult, error) {
	k, created, err := d.ensureLockKey()
	if err != nil {
		return LockResult{}, err
	}
	if created {
		d.resync()
	}
	d.mu.Lock()
	var gen uint64
	if rec := d.pins.Lock(); rec != nil {
		gen = rec.Record.Generation
	}
	d.mu.Unlock()
	return LockResult{Generation: gen, Signer: lock.Fingerprint(k.Public()), Signed: []LockSigned{}, PublicKey: k.Public().String()}, nil
}

// LockAddSigner adds the named peer, which must have reported a lock
// key, to the signer set with a new record signed by this device.
func (d *Daemon) LockAddSigner(ctx context.Context, name string) (LockResult, error) {
	client, k, rec, err := d.signerContext()
	if err != nil {
		return LockResult{}, err
	}
	name = stripZone(name)
	list, err := client.ListLockPeers(ctx, &thawrv1.Empty{})
	if err != nil {
		return LockResult{}, fmt.Errorf("client: list peers: %w", err)
	}
	i := slices.IndexFunc(list.GetPeers(), func(p *thawrv1.LockPeer) bool { return p.GetName() == name })
	if i < 0 {
		return LockResult{}, fmt.Errorf("%w: %s", ErrUnknownPeer, name)
	}
	p := list.GetPeers()[i]
	if p.GetLockKey() == "" {
		return LockResult{}, fmt.Errorf("client: %s has not reported a lock key; run `thawr client lock key` there first", name)
	}
	key, err := lock.ParsePublicKey(p.GetLockKey())
	if err != nil {
		return LockResult{}, fmt.Errorf("client: lock key of %s: %w", name, err)
	}
	next := lock.Record{Generation: rec.Record.Generation + 1, Signers: append(slices.Clone(rec.Record.Signers), lock.Signer{Key: key, PeerID: p.GetId()})}
	if err := d.setLockRecord(ctx, client, k, next, nil); err != nil {
		return LockResult{}, err
	}
	d.log.Info("signer added", "peer", name, "signer", lock.Fingerprint(key), "generation", next.Generation)
	return LockResult{Generation: next.Generation, Signer: lock.Fingerprint(k.Public()), Signed: []LockSigned{{Name: name, Fingerprint: lock.Fingerprint(key)}}}, nil
}

// LockDisable turns the lock off with a signed disabled record that
// keeps the signer set, so only a signer can turn it on again.
func (d *Daemon) LockDisable(ctx context.Context) (LockResult, error) {
	client, k, rec, err := d.signerContext()
	if err != nil {
		return LockResult{}, err
	}
	next := lock.Record{Generation: rec.Record.Generation + 1, Disabled: true, Signers: slices.Clone(rec.Record.Signers)}
	if err := d.setLockRecord(ctx, client, k, next, nil); err != nil {
		return LockResult{}, err
	}
	d.log.Info("network lock disabled", "generation", next.Generation)
	return LockResult{Generation: next.Generation, Signer: lock.Fingerprint(k.Public()), Signed: []LockSigned{}}, nil
}

// selfRotation signs newKey with this device's lock key when it is a
// signer, so the rotation reaches other devices already signed.
func (d *Daemon) selfRotation(newKey wg.Key) (signer, signature string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec := d.pins.Lock()
	if d.lockKey.IsZero() || rec == nil || !rec.Record.Enabled() {
		return "", "", nil
	}
	if k, ok := rec.Record.SignerKey(d.state.PeerID); !ok || k != d.lockKey.Public() {
		return "", "", nil
	}
	msg, err := lock.PeerRecord{ID: d.state.PeerID, Name: d.state.Name, Key: [32]byte(newKey.PublicKey())}.Bytes()
	if err != nil {
		return "", "", err
	}
	sig, err := lock.Sign(d.lockKey, msg)
	if err != nil {
		return "", "", err
	}
	return d.lockKey.Public().String(), sig.String(), nil
}
