//go:build integration && linux

package tests

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRelaySymmetricNATs: two clients behind symmetric NATs cannot punch
// a hole and talk through the relay instead; ping works and the path
// reads "relay" on both sides. Spec 005 acceptance.
func TestRelaySymmetricNATs(t *testing.T) {
	requireNAT(t)
	status, pingPath, sites := natMesh(t, []natKind{natSymmetric, natSymmetric}, false)
	start := time.Now()
	state, _, _ := pingPath(0)
	if state != "relay" {
		t.Fatalf("path = %s, want relay", state)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("relay path took %s, want <= 10 s", took)
	}
	st := status(0)
	if !st.Relay.Connected || st.Relay.Peers != 1 {
		t.Errorf("relay status: %+v", st.Relay)
	}
	peerIP := st.Peers[0].IPv4
	// client-2 joins the relay once the server tells it client-1 waits
	// there: within 10 s of both being online (spec 005), so allow 20 s
	// for the first echo.
	deadline := time.Now().Add(20 * time.Second)
	for sites[0].client.cmd(context.Background(), "ping", "-c", "1", "-W", "1", peerIP).Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("no echo from %s through the relay within %s", peerIP, time.Since(start).Round(time.Second))
		}
	}
	t.Logf("first echo through the relay %s after the clients were up", time.Since(start).Round(100*time.Millisecond))
	if out, err := sites[0].client.cmd(context.Background(), "ping", "-c", "3", "-W", "2", peerIP).CombinedOutput(); err != nil {
		t.Fatalf("ping %s through the relay: %v\n%s", peerIP, err, out)
	}
	other := status(1)
	if len(other.Peers) != 1 || other.Peers[0].Path != "relay" || other.Peers[0].RxBytes == 0 {
		t.Errorf("client-2 side: %+v", other)
	}
}

// TestRelayToDirectUpgrade: relayed peers move to direct once their NATs
// allow it (the rules are swapped for restricted cones, which changes
// the reflexive candidates and triggers a probe round on both sides).
func TestRelayToDirectUpgrade(t *testing.T) {
	requireNAT(t)
	status, pingPath, sites := natMesh(t, []natKind{natSymmetric, natSymmetric}, false)
	if state, _, _ := pingPath(0); state != "relay" {
		t.Fatalf("path = %s, want relay first", state)
	}
	for i, site := range sites {
		applyNAT(t, site.nat, natRestricted, "p"+strconv.Itoa(i)+"n", site.lanIP)
		// Existing conntrack entries keep the old random mappings.
		_ = site.nat.cmd(context.Background(), "conntrack", "-F").Run()
	}
	peerIP := status(0).Peers[0].IPv4
	deadline := time.Now().Add(3 * time.Minute) // discovery every 60 s, then a probe round
	for {
		st := status(0)
		if len(st.Peers) == 1 && st.Peers[0].Path == "direct" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no upgrade to direct: %+v", st)
		}
		time.Sleep(time.Second)
	}
	if out, err := sites[0].client.cmd(context.Background(), "ping", "-c", "3", "-W", "2", peerIP).CombinedOutput(); err != nil {
		t.Fatalf("ping after upgrade: %v\n%s", err, out)
	}
	// The proxy closes after the client's 10 s release delay.
	deadline = time.Now().Add(15 * time.Second)
	for status(0).Relay.Peers != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("relay proxy still held after the upgrade: %+v", status(0).Relay)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestRelayThroughput is a sanity check with iperf3 through the relay.
func TestRelayThroughput(t *testing.T) {
	requireNAT(t)
	if _, err := exec.LookPath("iperf3"); err != nil {
		t.Skip("iperf3 not found")
	}
	status, pingPath, sites := natMesh(t, []natKind{natSymmetric, natSymmetric}, false)
	if state, _, _ := pingPath(0); state != "relay" {
		t.Fatalf("path = %s, want relay", state)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	server := sites[1].client.cmd(ctx, "iperf3", "-s", "-1")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	time.Sleep(time.Second)
	peerIP := status(0).Peers[0].IPv4
	out, err := sites[0].client.cmd(ctx, "iperf3", "-c", peerIP, "-t", "5", "-f", "m").CombinedOutput()
	if err != nil {
		t.Fatalf("iperf3: %v\n%s", err, out)
	}
	mbit := 0.0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "receiver") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "Mbits/sec" && i > 0 {
					mbit, _ = strconv.ParseFloat(fields[i-1], 64)
				}
			}
		}
	}
	if mbit < 50 {
		t.Errorf("relay throughput %.1f Mbit/s, want >= 50\n%s", mbit, out)
	}
}
