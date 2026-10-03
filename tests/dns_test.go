//go:build integration && linux

package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// dnsQuery resolves name against server:53 from inside ns by re-running
// this test binary there (TestHelperDNSQuery), since the namespaces have
// no resolver tools of their own. kind is "a", "aaaa" or "ptr". It returns the
// answers sorted, or the helper's error.
func dnsQuery(ctx context.Context, ns *netns, server, name, kind string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := ns.cmd(ctx, exe, "-test.run", "^TestHelperDNSQuery$")
	cmd.Env = append(os.Environ(), "THAWR_DNS_HELPER=1", "THAWR_DNS_SERVER="+server, "THAWR_DNS_NAME="+name, "THAWR_DNS_KIND="+kind)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return nil, fmt.Errorf("query %s %s @%s: %w: %s", kind, name, server, err, text)
	}
	if strings.Contains(text, "ERR ") {
		return nil, fmt.Errorf("query %s %s @%s: %s", kind, name, server, text)
	}
	var answers []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "ANS ") {
			answers = append(answers, strings.TrimPrefix(line, "ANS "))
		}
	}
	sort.Strings(answers)
	return answers, nil
}

// TestHelperDNSQuery is the body dnsQuery runs inside a namespace; it is
// a no-op in a normal test run.
func TestHelperDNSQuery(t *testing.T) {
	if os.Getenv("THAWR_DNS_HELPER") == "" {
		t.Skip("helper process only")
	}
	server, name, kind := os.Getenv("THAWR_DNS_SERVER"), os.Getenv("THAWR_DNS_NAME"), os.Getenv("THAWR_DNS_KIND")
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch kind {
	case "a":
		ips, err := r.LookupNetIP(ctx, "ip4", name)
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		for _, ip := range ips {
			fmt.Println("ANS", ip.String())
		}
	case "aaaa":
		ips, err := r.LookupNetIP(ctx, "ip6", name)
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		for _, ip := range ips {
			fmt.Println("ANS", ip.String())
		}
	case "ptr":
		names, err := r.LookupAddr(ctx, name)
		if err != nil {
			fmt.Println("ERR", err)
			return
		}
		for _, n := range names {
			fmt.Println("ANS", n)
		}
	default:
		fmt.Println("ERR unknown kind", kind)
	}
}

// TestDNSNames: each client resolves its visible peers, itself and the
// hub through its own resolver, refuses names outside the zone, and
// stops resolving a removed peer. Spec 010 acceptance.
func TestDNSNames(t *testing.T) {
	m := newStarMesh(t, "version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n", false)
	ctx := context.Background()
	var aliceIP, bobIP string
	deadline := time.Now().Add(20 * time.Second)
	for {
		a, b := m.status(0), m.status(1)
		aliceIP, bobIP = a.Self.IPv4, b.Self.IPv4
		if aliceIP != "" && bobIP != "" && len(a.Peers) >= 1 && len(b.Peers) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients never saw each other: %+v / %+v", a, b)
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The daemons were started with --dns serve, so nothing under /etc
	// changed, but the resolvers answer on the overlay addresses.
	if got, err := dnsQuery(ctx, m.clients[0], aliceIP, "bob-box.thawr", "a"); err != nil || strings.Join(got, ",") != bobIP {
		t.Fatalf("alice resolves bob-box: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[0], aliceIP, "alice-box.thawr", "a"); err != nil || strings.Join(got, ",") != aliceIP {
		t.Errorf("alice resolves herself: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[1], bobIP, "hub.thawr", "a"); err != nil || strings.Join(got, ",") != "100.64.0.1" {
		t.Errorf("bob resolves hub: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.clients[1], bobIP, aliceIP, "ptr"); err != nil || strings.Join(got, ",") != "alice-box.thawr." {
		t.Errorf("bob reverse-resolves alice: %v %v", got, err)
	}
	if _, err := dnsQuery(ctx, m.clients[0], aliceIP, "nobody.thawr", "a"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("unknown name: %v", err)
	}
	if _, err := dnsQuery(ctx, m.clients[0], aliceIP, "example.com", "a"); err == nil {
		t.Error("client resolver answered a name outside the zone")
	}
	// A client's status shows the resolver serving without registration.
	out, err := m.clients[0].cmd(ctx, m.bin, "client", "status", "--socket", m.dir+"/alice-box.sock").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DNS: serving, not registered") {
		t.Errorf("status header: %v\n%s", err, out)
	}
	// Removal propagates to the resolver with the next netmap.
	if out, err := m.admin("peer", "delete", "bob-box"); err != nil {
		t.Fatalf("delete bob-box: %v\n%s", err, out)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, err := dnsQuery(ctx, m.clients[0], aliceIP, "bob-box.thawr", "a")
		if err != nil && strings.Contains(err.Error(), "no such host") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bob-box still resolves after deletion: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestDNSPhoneViaHub: the phone's exported config points at the hub
// resolver, which answers the names the policy lets the phone see and
// hides the rest; a name outside the zone is forwarded and, with no
// reachable upstream in the namespace, fails instead of hanging.
func TestDNSPhoneViaHub(t *testing.T) {
	m := newMobileMesh(t, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['alice:*']\n")
	ctx := context.Background()
	if m.phoneDNS != "DNS = 100.64.0.1, thawr" {
		t.Errorf("exported phone config DNS line: %q", m.phoneDNS)
	}
	var aliceIP, bobIP string
	deadline := time.Now().Add(20 * time.Second)
	for {
		a, b := m.status(0), m.status(1)
		aliceIP, bobIP = a.Self.IPv4, b.Self.IPv4
		if aliceIP != "" && bobIP != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients not up: %+v / %+v", a, b)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := m.phoneReaches(ctx, "100.64.0.1", 20*time.Second); err != nil {
		t.Fatalf("phone cannot reach the hub: %v", err)
	}
	if got, err := dnsQuery(ctx, m.phone, "100.64.0.1", "alice-box.thawr", "a"); err != nil || strings.Join(got, ",") != aliceIP {
		t.Fatalf("phone resolves alice-box: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.phone, "100.64.0.1", "hub.thawr", "a"); err != nil || strings.Join(got, ",") != "100.64.0.1" {
		t.Errorf("phone resolves hub: %v %v", got, err)
	}
	if got, err := dnsQuery(ctx, m.phone, "100.64.0.1", aliceIP, "ptr"); err != nil || strings.Join(got, ",") != "alice-box.thawr." {
		t.Errorf("phone reverse-resolves alice-box: %v %v", got, err)
	}
	if _, err := dnsQuery(ctx, m.phone, "100.64.0.1", "bob-box.thawr", "a"); err == nil || !strings.Contains(err.Error(), "no such host") {
		t.Errorf("phone learned bob-box, which the policy hides: %v", err)
	}
	start := time.Now()
	if _, err := dnsQuery(ctx, m.phone, "100.64.0.1", "example.invalid", "a"); err == nil {
		t.Error("a name outside the zone resolved with no upstream reachable")
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("forwarding to an unreachable upstream took %s", d)
	}
}
