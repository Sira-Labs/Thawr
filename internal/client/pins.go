package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/wg"
)

// PinsFile records the hub key and every peer key this device has
// accepted, so a later netmap cannot swap one unnoticed (spec 011).
const PinsFile = "pins.json"

// ErrNotHeld is returned by Trust for a name that is not held.
var ErrNotHeld = errors.New("client: nothing to trust")

// pinEntry is one accepted peer: the id the server assigned and the
// WireGuard public key seen under it.
type pinEntry struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// pinFile is the on-disk shape of PinsFile.
type pinFile struct {
	Hub   string              `json:"hub"`
	Peers map[string]pinEntry `json:"peers"`
	// Lock is the pinned network-lock record (spec 012); absent while
	// this device never saw one.
	Lock *lock.Signed `json:"lock,omitempty"`
}

// Reasons an entry is held.
const (
	// HeldKeyChanged: the offered key differs from the pinned one.
	HeldKeyChanged = "key_changed"
	// HeldUnsigned: the network lock is on and no signer signed the
	// offered record.
	HeldUnsigned = "unsigned"
)

// Pins is the set of accepted keys, keyed by peer name. It is not safe
// for concurrent use; the daemon calls it under its own lock.
type Pins struct {
	dir   string
	hub   string
	peers map[string]pinEntry
	lock  *lock.Signed
	// dirty is set while the in-memory set is ahead of the file, so a
	// failed write is retried on the next Apply instead of being lost
	// at the next start.
	dirty bool
}

// HeldStatus describes one netmap entry the client refuses to apply
// because its key differs from the pinned one.
type HeldStatus struct {
	// Name is the peer's name, or "hub".
	Name  string `json:"name"`
	IPv4  string `json:"ipv4"`
	Kind  string `json:"kind"`
	Owner string `json:"owner"`
	// PinnedKey is the accepted key, OfferedKey the one the netmap
	// carries now.
	PinnedKey  string `json:"pinned_key"`
	OfferedKey string `json:"offered_key"`
	// Since is when this offered key was first held.
	Since time.Time `json:"since"`
	// Reason is HeldKeyChanged or HeldUnsigned.
	Reason string `json:"reason"`
	// id is the offered peer id, needed to accept it.
	id string
}

// LoadPins reads PinsFile from dir; a missing file is an empty set. A
// file that exists but cannot be parsed is an error: resetting it
// silently would re-pin whatever the next netmap carries.
func LoadPins(dir string) (*Pins, error) {
	p := &Pins{dir: dir, peers: map[string]pinEntry{}}
	data, err := os.ReadFile(filepath.Join(dir, PinsFile))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, fmt.Errorf("client: read %s: %w", PinsFile, err)
	}
	var f pinFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("client: parse %s: %w", PinsFile, err)
	}
	p.hub = f.Hub
	for name, e := range f.Peers {
		if name == "" || e.ID == "" || e.Key == "" {
			return nil, fmt.Errorf("client: parse %s: entry %q is incomplete", PinsFile, name)
		}
		p.peers[name] = e
	}
	if f.Lock != nil {
		if err := lock.Accept(nil, *f.Lock); err != nil {
			return nil, fmt.Errorf("client: parse %s: lock record: %w", PinsFile, err)
		}
		p.lock = f.Lock
	}
	return p, nil
}

// save writes the set with mode 0600 through a temporary file.
func (p *Pins) save() error {
	f := pinFile{Hub: p.hub, Peers: p.peers, Lock: p.lock}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("client: encode %s: %w", PinsFile, err)
	}
	return writeSecret(p.dir, PinsFile, append(data, '\n'))
}

// Apply checks nm against the pins and returns the netmap to apply with
// every held entry removed, plus the held list. Unknown names are
// pinned (first contact is trusted), a known id under a new name copies
// its pin to the new name, and a known name whose id or key differs is
// held. The old name's pin is kept on a rename, so a later peer taking
// that name is held rather than trusted. prev carries the current held
// list so Since survives netmaps that change nothing. Pins are written
// when they changed.
func (p *Pins) Apply(nm NetMap, now time.Time, prev []HeldStatus) (NetMap, []HeldStatus, error) {
	since := func(name, offered string) time.Time {
		for _, h := range prev {
			if h.Name == name && h.OfferedKey == offered {
				return h.Since
			}
		}
		return now
	}
	var held []HeldStatus
	changed := false
	byID := map[string]pinEntry{}
	for _, e := range p.peers {
		byID[e.ID] = e
	}
	out := nm
	out.Peers = make([]Peer, 0, len(nm.Peers))
	if nm.Hub.PublicKey != "" {
		switch p.hub {
		case "":
			p.hub, changed = nm.Hub.PublicKey, true
		case nm.Hub.PublicKey:
		default:
			held = append(held, HeldStatus{Name: HubName, IPv4: hubAddr(nm), Kind: "server", PinnedKey: p.hub, OfferedKey: nm.Hub.PublicKey, Since: since(HubName, nm.Hub.PublicKey), Reason: HeldKeyChanged})
			out.Hub = HubPeer{}
		}
	}
	for _, peer := range nm.Peers {
		if peer.ViaHub || peer.Name == "" || peer.ID == "" || peer.PublicKey == "" {
			out.Peers = append(out.Peers, peer)
			continue
		}
		pin, known := p.peers[peer.Name]
		if !known {
			if moved, ok := byID[peer.ID]; ok {
				pin = moved // renamed: the accepted key travels with the id
			} else {
				pin = pinEntry{ID: peer.ID, Key: peer.PublicKey}
			}
			p.peers[peer.Name], changed = pin, true
		}
		if pin.ID == peer.ID && pin.Key == peer.PublicKey {
			out.Peers = append(out.Peers, peer)
			continue
		}
		held = append(held, HeldStatus{Name: peer.Name, IPv4: peer.IPv4, Kind: peer.Kind, Owner: peer.Owner, PinnedKey: pin.Key, OfferedKey: peer.PublicKey,
			Since: since(peer.Name, peer.PublicKey), Reason: HeldKeyChanged, id: peer.ID})
	}
	if changed || p.dirty {
		p.dirty = true
		if err := p.save(); err != nil {
			return NetMap{}, nil, err
		}
		p.dirty = false
	}
	sort.Slice(held, func(i, j int) bool { return held[i].Name < held[j].Name })
	return out, held, nil
}

// Trust accepts the offered key of one held entry and persists it.
func (p *Pins) Trust(h HeldStatus) error {
	if h.Name == HubName {
		p.hub = h.OfferedKey
	} else {
		p.peers[h.Name] = pinEntry{ID: h.id, Key: h.OfferedKey}
	}
	p.dirty = true
	if err := p.save(); err != nil {
		return err
	}
	p.dirty = false
	return nil
}

// Lock returns the pinned lock record, nil when none was ever pinned.
func (p *Pins) Lock() *lock.Signed { return p.lock }

// Enabled reports whether the pinned record turns the lock on.
func (p *Pins) Enabled() bool { return p.lock != nil && p.lock.Record.Enabled() }

// UpdateLock reconciles the record the server offers with the pinned
// one and returns why the offer was not adopted, empty when it was or
// when nothing changed. The first record is pinned as offered; a later
// one must pass lock.Accept against the pin. A server that offers
// nothing while a record is pinned does not turn the lock off: the pin
// stays until a signed disabled record arrives. The pin is written by
// the next Apply.
func (p *Pins) UpdateLock(offered *lock.Signed) string {
	switch {
	case offered == nil && p.lock == nil:
		return ""
	case offered == nil:
		return "server offers no lock record; keeping the pinned one"
	case p.lock != nil && p.lock.Record.Generation == offered.Record.Generation && p.lock.Signature == offered.Signature:
		return ""
	}
	var cur *lock.Record
	if p.lock != nil {
		cur = &p.lock.Record
	}
	if err := lock.Accept(cur, *offered); err != nil {
		return fmt.Sprintf("offered record (generation %d) refused: %v", offered.Record.Generation, err)
	}
	p.lock, p.dirty = offered, true
	return ""
}

// SetLock pins a record this device produced itself and persists it.
func (p *Pins) SetLock(s lock.Signed) error {
	p.lock, p.dirty = &s, true
	if err := p.save(); err != nil {
		return err
	}
	p.dirty = false
	return nil
}

// Accept records key for name (HubName for the hub) as the pinned one
// without a trust step: the lock signers vouched for it. The pin is
// written by the next Apply.
func (p *Pins) Accept(name, id, key string) {
	if name == HubName {
		if p.hub != key {
			p.hub, p.dirty = key, true
		}
		return
	}
	if e := p.peers[name]; e.ID != id || e.Key != key {
		p.peers[name], p.dirty = pinEntry{ID: id, Key: key}, true
	}
}

// HoldUnsigned removes from nm every entry (hub included, ViaHub peers
// excepted) whose record carries no valid signature by a signer of set
// and returns them as held with reason HeldUnsigned; signed entries
// are accepted into the pins so a signed rotation needs no trust.
func (p *Pins) HoldUnsigned(nm NetMap, set lock.Record, now time.Time, prev []HeldStatus) (NetMap, []HeldStatus) {
	since := func(name, offered string) time.Time {
		for _, h := range prev {
			if h.Name == name && h.OfferedKey == offered && h.Reason == HeldUnsigned {
				return h.Since
			}
		}
		return now
	}
	var held []HeldStatus
	out := nm
	out.Peers = make([]Peer, 0, len(nm.Peers))
	if nm.Hub.PublicKey != "" {
		if signedBy(set, lock.HubID, lock.HubID, nm.Hub.PublicKey, nm.Hub.Signatures) {
			p.Accept(HubName, "", nm.Hub.PublicKey)
		} else {
			held = append(held, HeldStatus{Name: HubName, IPv4: hubAddr(nm), Kind: "server", PinnedKey: p.hub, OfferedKey: nm.Hub.PublicKey, Since: since(HubName, nm.Hub.PublicKey), Reason: HeldUnsigned})
			out.Hub = HubPeer{}
		}
	}
	for _, peer := range nm.Peers {
		if peer.ViaHub || peer.Name == "" || peer.ID == "" || peer.PublicKey == "" {
			out.Peers = append(out.Peers, peer)
			continue
		}
		if signedBy(set, peer.ID, peer.Name, peer.PublicKey, peer.Signatures) {
			p.Accept(peer.Name, peer.ID, peer.PublicKey)
			out.Peers = append(out.Peers, peer)
			continue
		}
		held = append(held, HeldStatus{Name: peer.Name, IPv4: peer.IPv4, Kind: peer.Kind, Owner: peer.Owner, PinnedKey: p.peers[peer.Name].Key, OfferedKey: peer.PublicKey,
			Since: since(peer.Name, peer.PublicKey), Reason: HeldUnsigned, id: peer.ID})
	}
	return out, held
}

// signedBy reports whether one of sigs is a valid signature by a key of
// set over the record (id, name, key).
func signedBy(set lock.Record, id, name, key string, sigs []PeerSignature) bool {
	wk, err := wg.ParseKey(key)
	if err != nil {
		return false
	}
	msg, err := lock.PeerRecord{ID: id, Name: name, Key: [32]byte(wk)}.Bytes()
	if err != nil {
		return false
	}
	for _, s := range sigs {
		signer, err := lock.ParsePublicKey(s.Signer)
		if err != nil || !set.Has(signer) {
			continue
		}
		sig, err := lock.ParseSignature(s.Signature)
		if err != nil {
			continue
		}
		if lock.Verify(signer, msg, sig) {
			return true
		}
	}
	return false
}

// hubAddr is the hub's overlay address as the netmap routes it.
func hubAddr(nm NetMap) string {
	for _, a := range nm.Hub.AllowedIPs {
		if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Bits() == 32 {
			return pfx.Addr().String()
		}
	}
	return ""
}

// fingerprintOf renders a key string as its fingerprint for logs; an
// unparseable key is shown as "?" rather than in full.
func fingerprintOf(key string) string {
	k, err := wg.ParseKey(key)
	if err != nil {
		return "?"
	}
	return wg.Fingerprint(k)
}
