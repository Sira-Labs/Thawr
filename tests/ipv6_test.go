//go:build integration && linux

package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// hostIPv6 reports whether the kernel runs IPv6 (not booted with
// ipv6.disable=1).
func hostIPv6() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}

// requireIPv6 skips a test that needs IPv6 in the namespaces.
func requireIPv6(t *testing.T) {
	t.Helper()
	if !hostIPv6() {
		t.Skip("the kernel runs without IPv6")
	}
}

// TestIPv6OverlayEndToEnd: two upgraded clients get IPv6 overlay
// addresses, ping each other over IPv6, resolve AAAA and ip6.arpa
// names, and the policy that opens one port and denies another holds
// over IPv6 as over IPv4. Spec 015 acceptance 3 and 7.
func TestIPv6OverlayEndToEnd(t *testing.T) {
	requireIPv6(t)
	m := newStarMesh(t, "version: 1\nacls:\n"+
		"  - action: accept\n    src: [alice]\n    dst: ['bob:8080']\n    proto: tcp\n"+
		"  - action: accept\n    src: [alice]\n    dst: ['bob:*']\n    proto: icmp\n", false)
	ctx := context.Background()
	var alice, bob clientStatus
	deadline := time.Now().Add(30 * time.Second)
	for {
		alice, bob = m.status(0), m.status(1)
		if alice.Self.IPv6 != "" && bob.Self.IPv6 != "" && len(alice.Peers) == 1 && alice.Peers[0].IPv6 != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no IPv6 overlay addresses: %+v / %+v", alice, bob)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if alice.Peers[0].IPv6 != bob.Self.IPv6 {
		t.Errorf("alice lists bob at %s, bob has %s", alice.Peers[0].IPv6, bob.Self.IPv6)
	}
	// The address carries the IPv4 one in its last 32 bits.
	if !strings.HasSuffix(bob.Self.IPv6, "::6440:3") || bob.Self.IPv4 != "100.64.0.3" {
		t.Errorf("bob %s / %s: IPv6 not derived from IPv4", bob.Self.IPv4, bob.Self.IPv6)
	}

	deadline = time.Now().Add(20 * time.Second)
	for {
		out, err := m.clients[0].cmd(ctx, "ping", "-6", "-c", "2", "-W", "2", bob.Self.IPv6).CombinedOutput()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ping -6 alice → bob: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}

	if got, err := dnsQuery(ctx, m.clients[0], alice.Self.IPv4, "bob-box.thawr", "aaaa"); err != nil || strings.Join(got, ",") != bob.Self.IPv6 {
		t.Errorf("alice resolves AAAA bob-box: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[0], alice.Self.IPv4, "bob-box.thawr", "a"); err != nil || strings.Join(got, ",") != bob.Self.IPv4 {
		t.Errorf("alice resolves A bob-box: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[0], alice.Self.IPv4, bob.Self.IPv6, "ptr"); err != nil || strings.Join(got, ",") != "bob-box.thawr." {
		t.Errorf("alice reverse-resolves bob's IPv6: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[1], bob.Self.IPv4, "hub.thawr", "aaaa"); err != nil || len(got) != 1 || !strings.HasSuffix(got[0], "::6440:1") {
		t.Errorf("bob resolves AAAA hub: %v %v", got, err)
	}

	// Listeners on bob: 8080 (allowed) and 9090 (denied), over IPv6.
	for _, port := range []string{"8080", "9090"} {
		l := m.clients[1].cmd(ctx, "nc", "-6", "-l", "-k", "-p", port)
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Process.Kill(); _ = l.Wait() })
	}
	time.Sleep(500 * time.Millisecond)
	connect := func(port string) bool {
		out, err := m.clients[0].cmd(ctx, "nc", "-6", "-z", "-w", "2", bob.Self.IPv6, port).CombinedOutput()
		t.Logf("nc [%s]:%s: err=%v %s", bob.Self.IPv6, port, err, out)
		return err == nil
	}
	if !connect("8080") {
		t.Fatal("allowed port 8080 unreachable over IPv6")
	}
	if connect("9090") {
		t.Fatal("denied port 9090 reachable over IPv6")
	}
	// bob may not reach alice at all.
	if out, err := m.clients[1].cmd(ctx, "ping", "-6", "-c", "1", "-W", "2", alice.Self.IPv6).CombinedOutput(); err == nil {
		t.Errorf("bob pinged alice over IPv6 although the policy denies it:\n%s", out)
	}
}

// TestIPv6PhoneViaHub: a phone added after the upgrade carries both
// addresses in its config and reaches its owner's device over IPv6
// through the hub. Spec 015 acceptance 5.
func TestIPv6PhoneViaHub(t *testing.T) {
	requireIPv6(t)
	m := newMobileMesh(t, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['alice:*']\n")
	ctx := context.Background()
	var box, phone6 string
	deadline := time.Now().Add(20 * time.Second)
	for {
		st := m.status(0)
		box = st.Self.IPv6
		for _, p := range st.Peers {
			if p.Name == "alice-phone" && p.Path == "hub" {
				phone6 = p.IPv6
			}
		}
		if box != "" && phone6 != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("alice-box never listed the phone with IPv6: %+v", st)
		}
		time.Sleep(500 * time.Millisecond)
	}
	raw, err := os.ReadFile(m.dir + "/phone.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), phone6+"/128") {
		t.Errorf("phone config lacks %s/128:\n%s", phone6, raw)
	}
	deadline = time.Now().Add(20 * time.Second)
	for {
		out, err := m.phone.cmd(ctx, "ping", "-6", "-c", "2", "-W", "2", box).CombinedOutput()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("phone → alice-box over IPv6: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}
	if out, err := m.clients[0].cmd(ctx, "ping", "-6", "-c", "2", "-W", "2", phone6).CombinedOutput(); err != nil {
		t.Fatalf("alice-box → phone over IPv6: %v\n%s", err, out)
	}
}
