//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestNetworkLockHoldsUnsignedPeers: alice enables the lock; a third
// device that enrols afterwards is held as unsigned on both clients
// until alice signs it; bob's unsigned rotation is held until signed,
// alice's own rotation is signed on the way and needs no trust; the
// server reports the lock and audits lock.set and peer.sign; disable
// turns it off everywhere. Spec 012 acceptance.
func TestNetworkLockHoldsUnsignedPeers(t *testing.T) {
	m := newStarMesh(t, "version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n", false)
	ctx := context.Background()
	sock := func(name string) string { return filepath.Join(m.dir, name+".sock") }
	waitStatus := func(i int, cond func(clientStatus) bool, what string) clientStatus {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			st := m.status(i)
			if cond(st) {
				return st
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %+v", what, st)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	held := func(st clientStatus, name, reason string) bool {
		for _, h := range st.Held {
			if h.Name == name && h.Reason == reason {
				return true
			}
		}
		return false
	}
	peerKey := func(st clientStatus, name string) string {
		for _, p := range st.Peers {
			if p.Name == name {
				return p.PublicKey
			}
		}
		return ""
	}
	waitStatus(0, func(st clientStatus) bool {
		return len(st.Peers) == 1 && st.Peers[0].Name == "bob-box" && !st.Lock.Enabled
	}, "alice never saw bob")
	if state, _, err := pingPathOnce(ctx, m.clients[0], m.bin, sock("alice-box"), "bob-box"); err != nil || state != "direct" {
		t.Fatalf("path before the lock: %s %v", state, err)
	}

	// Enable on alice: the hub, alice and bob are signed in the same step.
	out, err := m.clients[0].cmd(ctx, m.bin, "client", "lock", "init", "--socket", sock("alice-box")).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "network lock enabled (generation 1)") || !strings.Contains(string(out), "signed bob-box") || !strings.Contains(string(out), "signed hub") {
		t.Fatalf("lock init: %v\n%s", err, out)
	}
	alice := waitStatus(0, func(st clientStatus) bool { return st.Lock.Enabled && st.Lock.Signer && st.Lock.SelfSigned }, "alice not a signer")
	bob := waitStatus(1, func(st clientStatus) bool { return st.Lock.Enabled && st.Lock.SelfSigned }, "bob did not adopt the record")
	if bob.Lock.Signer || len(bob.Held) != 0 || len(alice.Held) != 0 || bob.Lock.Generation != 1 {
		t.Errorf("after init: alice=%+v bob=%+v", alice.Lock, bob.Lock)
	}
	if state, _, err := pingPathOnce(ctx, m.clients[0], m.bin, sock("alice-box"), "bob-box"); err != nil || state != "direct" {
		t.Errorf("path after the lock: %s %v", state, err)
	}

	// A third device enrols: unsigned, held on both until alice signs it.
	carol := addStarClient(t, m, 2, "alice", "carol-box")
	for i, name := range []string{"alice-box", "bob-box"} {
		st := waitStatus(i, func(st clientStatus) bool { return held(st, "carol-box", "unsigned") }, name+" did not hold carol")
		for _, p := range st.Peers {
			if p.Name == "carol-box" && p.Path != "unsigned" {
				t.Errorf("%s: carol row %+v", name, p)
			}
		}
	}
	waitClientStatus(t, ctx, carol, m.bin, sock("carol-box"), func(st clientStatus) bool { return st.Lock.Enabled && !st.Lock.SelfSigned }, "carol does not see herself unsigned")
	if out, err := m.clients[1].cmd(ctx, m.bin, "client", "status", "--socket", sock("bob-box")).CombinedOutput(); err != nil ||
		!strings.Contains(string(out), "1 unsigned: thawr client lock sign carol-box") || !strings.Contains(string(out), "lock: on") {
		t.Errorf("bob status text: %v\n%s", err, out)
	}
	if _, _, err := pingPathOnce(ctx, m.clients[0], m.bin, sock("alice-box"), "carol-box"); err == nil {
		t.Error("ping of an unsigned peer succeeded")
	}
	if out, err := m.clients[1].cmd(ctx, m.bin, "client", "trust", "carol-box", "--socket", sock("bob-box")).CombinedOutput(); err == nil {
		t.Errorf("trust released an unsigned peer:\n%s", out)
	}
	if out, err := m.clients[1].cmd(ctx, m.bin, "client", "lock", "sign", "carol-box", "--socket", sock("bob-box")).CombinedOutput(); err == nil {
		t.Errorf("bob (no signer) signed:\n%s", out)
	}
	if out, err := m.clients[0].cmd(ctx, m.bin, "client", "lock", "sign", "carol-box", "--socket", sock("alice-box")).CombinedOutput(); err != nil || !strings.Contains(string(out), "signed carol-box") {
		t.Fatalf("lock sign: %v\n%s", err, out)
	}
	for i, name := range []string{"alice-box", "bob-box"} {
		waitStatus(i, func(st clientStatus) bool { return len(st.Held) == 0 && len(st.Peers) == 2 }, name+" did not release carol")
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		state, _, err := pingPathOnce(ctx, m.clients[0], m.bin, sock("alice-box"), "carol-box")
		if err == nil && state == "direct" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("path to carol after signing: %s %v", state, err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// bob's rotation is unsigned and held; alice's is signed on the way.
	if out, err := m.clients[1].cmd(ctx, m.bin, "client", "rotate-key", "--socket", sock("bob-box")).CombinedOutput(); err != nil || !strings.Contains(string(out), "thawr client lock sign bob-box") {
		t.Fatalf("bob rotate-key: %v\n%s", err, out)
	}
	waitStatus(0, func(st clientStatus) bool { return held(st, "bob-box", "unsigned") }, "alice did not hold bob's unsigned key")
	if out, err := m.clients[0].cmd(ctx, m.bin, "client", "lock", "sign", "--all", "--socket", sock("alice-box")).CombinedOutput(); err != nil || !strings.Contains(string(out), "signed bob-box") {
		t.Fatalf("lock sign --all: %v\n%s", err, out)
	}
	waitStatus(0, func(st clientStatus) bool { return len(st.Held) == 0 }, "bob not released after signing")
	before := peerKey(m.status(1), "alice-box")
	if out, err := m.clients[0].cmd(ctx, m.bin, "client", "rotate-key", "--socket", sock("alice-box")).CombinedOutput(); err != nil || !strings.Contains(string(out), "key rotated and signed") {
		t.Fatalf("alice rotate-key: %v\n%s", err, out)
	}
	waitStatus(1, func(st clientStatus) bool {
		return peerKey(st, "alice-box") != before && peerKey(st, "alice-box") != "" && len(st.Held) == 0
	}, "bob did not switch to alice's signed key")

	// The server's view and the audit trail.
	if out, err := m.admin("lock"); err != nil || !strings.Contains(string(out), "lock: on (generation 1)") || !strings.Contains(string(out), "signer alice-box") || !strings.Contains(string(out), "every peer is signed") {
		t.Errorf("admin lock: %v\n%s", err, out)
	}
	if out, err := m.admin("peer", "list"); err != nil || !strings.Contains(string(out), "SIGNED") || strings.Contains(string(out), " no\n") {
		t.Errorf("admin peer list: %v\n%s", err, out)
	}
	raw, err := m.admin("audit", "--action", "lock.set", "--json")
	if err != nil {
		t.Fatalf("admin audit: %v\n%s", err, raw)
	}
	var entries []struct {
		Actor   string            `json:"actor"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != 1 || entries[0].Actor != "peer:alice-box" || entries[0].Details["generation"] != "1" {
		t.Errorf("lock.set rows: %v %s", err, raw)
	}
	raw, _ = m.admin("audit", "--action", "peer.sign", "--json")
	entries = nil
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) < 5 {
		t.Errorf("peer.sign rows: %v %s", err, raw)
	}

	// Disable from the signer turns the lock off everywhere.
	if out, err := m.clients[0].cmd(ctx, m.bin, "client", "lock", "disable", "--socket", sock("alice-box")).CombinedOutput(); err != nil || !strings.Contains(string(out), "network lock disabled (generation 2)") {
		t.Fatalf("lock disable: %v\n%s", err, out)
	}
	waitStatus(1, func(st clientStatus) bool { return !st.Lock.Enabled && st.Lock.Generation == 2 }, "bob did not see the lock go off")
	if out, err := m.admin("lock"); err != nil || !strings.Contains(string(out), "lock: off (disabled at generation 2)") {
		t.Errorf("admin lock after disable: %v\n%s", err, out)
	}
}

// addStarClient attaches one more client namespace to the star mesh
// (subnet 10.9.<i>) and enrols it for owner under name.
func addStarClient(t *testing.T, m *mobileMesh, i int, owner, name string) *netns {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	ns := newNetns(t, "c"+string(rune('1'+i)))
	veth := "v" + string(rune('a'+i))
	sub := "10.9." + string(rune('0'+i))
	ip(t, "link", "add", veth+"s", "type", "veth", "peer", "name", veth+"c")
	ip(t, "link", "set", veth+"s", "netns", m.srv.name)
	ip(t, "link", "set", veth+"c", "netns", ns.name)
	m.srv.ip(t, "addr", "add", sub+".1/24", "dev", veth+"s")
	m.srv.ip(t, "link", "set", veth+"s", "up")
	ns.ip(t, "addr", "add", sub+".2/24", "dev", veth+"c")
	ns.ip(t, "link", "set", veth+"c", "up")
	ns.ip(t, "route", "add", "default", "via", sub+".1")
	var tok struct {
		Secret string `json:"secret"`
	}
	out, err := m.admin("token", "create", "--owner", owner, "--json")
	if err != nil {
		t.Fatalf("token create: %v\n%s", err, out)
	}
	if err := json.Unmarshal(out, &tok); err != nil {
		t.Fatal(err)
	}
	fp := fingerprintFromState(t, filepath.Join(m.dir, "alice-box", "state.json"))
	d := ns.cmd(ctx, m.bin, "client", "up", "--dns", "off", "--server", "https://"+sub+".1:8443", "--token", tok.Secret,
		"--fingerprint", fp, "--state-dir", filepath.Join(m.dir, name), "--socket", filepath.Join(m.dir, name+".sock"), "--name", name)
	d.Stdout, d.Stderr = testWriter{t, name}, testWriter{t, name}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Process.Signal(syscall.SIGTERM); _ = d.Wait() })
	return ns
}

// waitClientStatus polls `client status --json` in ns until cond holds.
func waitClientStatus(t *testing.T, ctx context.Context, ns *netns, bin, socket string, cond func(clientStatus) bool, what string) clientStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var st clientStatus
		if out, err := ns.cmd(ctx, bin, "client", "status", "--json", "--socket", socket).Output(); err == nil {
			_ = json.Unmarshal(out, &st)
		}
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %+v", what, st)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// fingerprintFromState reads the pinned server fingerprint from an
// enrolled client's state file, so a later client can enrol against
// the same server without parsing the server's logs again.
func fingerprintFromState(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &st); err != nil || st.Fingerprint == "" {
		t.Fatalf("fingerprint from %s: %v", path, err)
	}
	return st.Fingerprint
}
