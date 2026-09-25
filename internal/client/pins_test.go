package client

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/wg"
)

func testKey(t *testing.T) string {
	t.Helper()
	k, err := wg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

func pinNetMap(hub string, peers ...Peer) NetMap {
	return NetMap{SelfIPv4: "100.64.0.2", Overlay: "100.64.0.0/10", Peers: peers,
		Hub: HubPeer{PublicKey: hub, Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"100.64.0.1/32"}}}
}

func heldNames(held []HeldStatus) string {
	names := make([]string, 0, len(held))
	for _, h := range held {
		names = append(names, h.Name)
	}
	return strings.Join(names, ",")
}

func TestPinsFirstContactThenHold(t *testing.T) {
	dir := t.TempDir()
	p, err := LoadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	hub, nasKey, boxKey := testKey(t), testKey(t), testKey(t)
	now := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	nas := Peer{ID: "p1", Name: "nas", IPv4: "100.64.0.3", Kind: "server", PublicKey: nasKey}
	box := Peer{ID: "p2", Name: "box", IPv4: "100.64.0.4", Kind: "agent", PublicKey: boxKey}
	phone := Peer{ID: "p3", Name: "phone", IPv4: "100.64.0.21", PublicKey: testKey(t), ViaHub: true}

	out, held, err := p.Apply(pinNetMap(hub, nas, box, phone), now, nil)
	if err != nil || len(held) != 0 || len(out.Peers) != 3 || out.Hub.PublicKey != hub {
		t.Fatalf("first contact: held=%v peers=%d err=%v", held, len(out.Peers), err)
	}
	if fi, err := os.Stat(filepath.Join(dir, PinsFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("pins file: %v %v", fi, err)
	}

	// The same netmap again: nothing held, nothing rewritten.
	before, _ := os.ReadFile(filepath.Join(dir, PinsFile))
	if _, held, err = p.Apply(pinNetMap(hub, nas, box, phone), now.Add(time.Minute), nil); err != nil || len(held) != 0 {
		t.Fatalf("repeat: held=%v err=%v", held, err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, PinsFile)); string(after) != string(before) {
		t.Error("pins rewritten without a change")
	}

	// nas rotates: held, out of the applied netmap, Since is the first time seen.
	rotated := nas
	rotated.PublicKey = testKey(t)
	out, held, err = p.Apply(pinNetMap(hub, rotated, box, phone), now.Add(2*time.Minute), nil)
	if err != nil || heldNames(held) != "nas" || len(out.Peers) != 2 {
		t.Fatalf("rotation: held=%s peers=%d err=%v", heldNames(held), len(out.Peers), err)
	}
	h := held[0]
	if h.PinnedKey != nasKey || h.OfferedKey != rotated.PublicKey || h.IPv4 != "100.64.0.3" || h.Kind != "server" || !h.Since.Equal(now.Add(2*time.Minute)) {
		t.Errorf("held entry: %+v", h)
	}
	_, held2, _ := p.Apply(pinNetMap(hub, rotated, box, phone), now.Add(3*time.Minute), held)
	if !held2[0].Since.Equal(h.Since) {
		t.Error("Since not carried over between netmaps")
	}
	// A different offered key restarts the clock.
	again := nas
	again.PublicKey = testKey(t)
	_, held3, _ := p.Apply(pinNetMap(hub, again, box, phone), now.Add(4*time.Minute), held2)
	if !held3[0].Since.Equal(now.Add(4 * time.Minute)) {
		t.Error("Since kept for a new offered key")
	}

	// The server backs off to the pinned key: released.
	if _, held, _ = p.Apply(pinNetMap(hub, nas, box, phone), now, held3); len(held) != 0 {
		t.Errorf("pinned key still held: %v", held)
	}

	// Trust accepts the offered key; the pin survives a reload.
	_, held, _ = p.Apply(pinNetMap(hub, rotated, box, phone), now, nil)
	if err := p.Trust(held[0]); err != nil {
		t.Fatal(err)
	}
	p2, err := LoadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, held, err = p2.Apply(pinNetMap(hub, rotated, box, phone), now, nil); err != nil || len(held) != 0 {
		t.Errorf("after trust and reload: held=%v err=%v", held, err)
	}
	if _, held, _ = p2.Apply(pinNetMap(hub, nas, box, phone), now, nil); heldNames(held) != "nas" {
		t.Errorf("old key accepted after trust: %v", held)
	}
}

func TestPinsRenameAndSubstitution(t *testing.T) {
	p, _ := LoadPins(t.TempDir())
	hub, nasKey := testKey(t), testKey(t)
	now := time.Now()
	nas := Peer{ID: "p1", Name: "nas", IPv4: "100.64.0.3", PublicKey: nasKey}
	if _, _, err := p.Apply(pinNetMap(hub, nas), now, nil); err != nil {
		t.Fatal(err)
	}

	// Rename: the id carries its key to the new name.
	renamed := nas
	renamed.Name = "nas-old"
	out, held, err := p.Apply(pinNetMap(hub, renamed), now, nil)
	if err != nil || len(held) != 0 || len(out.Peers) != 1 {
		t.Fatalf("rename: held=%v err=%v", held, err)
	}
	if e := p.peers["nas-old"]; e.ID != "p1" || e.Key != nasKey {
		t.Errorf("pin not copied to the new name: %+v", p.peers)
	}

	// A new peer taking the old name is held: the name still pins p1.
	taker := Peer{ID: "p9", Name: "nas", IPv4: "100.64.0.9", PublicKey: testKey(t)}
	out, held, err = p.Apply(pinNetMap(hub, renamed, taker), now, nil)
	if err != nil || heldNames(held) != "nas" || len(out.Peers) != 1 || out.Peers[0].Name != "nas-old" {
		t.Fatalf("substitution: held=%s peers=%+v err=%v", heldNames(held), out.Peers, err)
	}
	if held[0].PinnedKey != nasKey || held[0].id != "p9" {
		t.Errorf("held entry: %+v", held[0])
	}

	// Rename combined with a new key: copied, then held.
	both := Peer{ID: "p1", Name: "nas-new", IPv4: "100.64.0.3", PublicKey: testKey(t)}
	_, held, _ = p.Apply(pinNetMap(hub, both), now, nil)
	if heldNames(held) != "nas-new" || held[0].PinnedKey != nasKey {
		t.Errorf("rename with new key: %+v", held)
	}

	// A genuinely new name and id is trusted on first contact.
	fresh := Peer{ID: "p5", Name: "fresh", IPv4: "100.64.0.5", PublicKey: testKey(t)}
	if _, held, _ = p.Apply(pinNetMap(hub, fresh), now, nil); len(held) != 0 {
		t.Errorf("new peer held: %v", held)
	}
}

func TestPinsHubHeld(t *testing.T) {
	p, _ := LoadPins(t.TempDir())
	hub, other := testKey(t), testKey(t)
	now := time.Now()
	nas := Peer{ID: "p1", Name: "nas", IPv4: "100.64.0.3", PublicKey: testKey(t)}
	if _, _, err := p.Apply(pinNetMap(hub, nas), now, nil); err != nil {
		t.Fatal(err)
	}
	out, held, err := p.Apply(pinNetMap(other, nas), now, nil)
	if err != nil || heldNames(held) != HubName || out.Hub.PublicKey != "" || len(out.Hub.AllowedIPs) != 0 || len(out.Peers) != 1 {
		t.Fatalf("hub change: held=%v hub=%+v err=%v", held, out.Hub, err)
	}
	if held[0].IPv4 != "100.64.0.1" || held[0].Kind != "server" || held[0].PinnedKey != hub || held[0].OfferedKey != other {
		t.Errorf("held hub: %+v", held[0])
	}
	if err := p.Trust(held[0]); err != nil {
		t.Fatal(err)
	}
	if out, held, _ = p.Apply(pinNetMap(other, nas), now, nil); len(held) != 0 || out.Hub.PublicKey != other {
		t.Errorf("after trusting the hub: held=%v hub=%+v", held, out.Hub)
	}
	// A netmap without a hub (server not configured yet) pins nothing and holds nothing.
	empty, _ := LoadPins(t.TempDir())
	if _, held, _ = empty.Apply(NetMap{Peers: []Peer{nas}}, now, nil); len(held) != 0 || empty.hub != "" {
		t.Errorf("hubless netmap: held=%v hub=%q", held, empty.hub)
	}
}

func TestLoadPinsRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PinsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPins(dir); err == nil || !strings.Contains(err.Error(), PinsFile) {
		t.Errorf("corrupt file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PinsFile), []byte(`{"hub":"","peers":{"nas":{"id":"","key":"k"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPins(dir); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("incomplete entry: %v", err)
	}
	if _, err := LoadPins(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing dir: %v", err)
	}
}

// TestPinsRetryFailedSave: a pin write that fails is retried on the next
// Apply even when that netmap changes nothing, so a restart never
// re-pins what the file lost.
func TestPinsRetryFailedSave(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPins(dir)
	if err != nil {
		t.Fatal(err)
	}
	p.dir = filepath.Join(blocker, "pins") // a directory under a regular file cannot be created
	hub := testKey(t)
	nas := Peer{ID: "p1", Name: "nas", IPv4: "100.64.0.3", PublicKey: testKey(t)}
	if _, _, err := p.Apply(pinNetMap(hub, nas), time.Now(), nil); err == nil {
		t.Fatal("save under a regular file succeeded")
	}
	if !p.dirty {
		t.Fatal("failed save did not mark the pins dirty")
	}
	p.dir = dir
	if _, held, err := p.Apply(pinNetMap(hub, nas), time.Now(), nil); err != nil || len(held) != 0 || p.dirty {
		t.Fatalf("retry: held=%v dirty=%v err=%v", held, p.dirty, err)
	}
	again, err := LoadPins(dir)
	if err != nil || again.hub != hub || again.peers["nas"].ID != "p1" {
		t.Errorf("pins not persisted on retry: %+v %v", again, err)
	}
}
