//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestEncryptedPingTwoClients is the project's canonical integration test:
// a server and two clients in three namespaces joined by veth pairs;
// after enrolment the clients ping each other over the overlay, and the
// peer's WireGuard counters grow, proving the packets went through the
// tunnel. Spec 003 acceptance.
func TestEncryptedPingTwoClients(t *testing.T) {
	requireNetns(t)
	bin := thawrBinary(t)
	dir := shortTempDir(t)

	srvNs := newNetns(t, "srv")
	clients := []*netns{newNetns(t, "c1"), newNetns(t, "c2")}
	// Star topology: each client namespace has a veth into the server
	// namespace; the server routes between them so clients reach each
	// other directly (spec 004 adds NAT traversal for the harder cases).
	srvNs.ipForward(t)
	for i, ns := range clients {
		veth := "v" + string(rune('a'+i))
		sub := "10.9." + string(rune('0'+i))
		ip(t, "link", "add", veth+"s", "type", "veth", "peer", "name", veth+"c")
		ip(t, "link", "set", veth+"s", "netns", srvNs.name)
		ip(t, "link", "set", veth+"c", "netns", ns.name)
		srvNs.ip(t, "addr", "add", sub+".1/24", "dev", veth+"s")
		srvNs.ip(t, "link", "set", veth+"s", "up")
		ns.ip(t, "addr", "add", sub+".2/24", "dev", veth+"c")
		ns.ip(t, "link", "set", veth+"c", "up")
		ns.ip(t, "route", "add", "default", "via", sub+".1")
	}

	writeFile(t, filepath.Join(dir, "policy.yaml"), allowAllPolicy)
	writeFile(t, filepath.Join(dir, "server.yaml"), strings.NewReplacer("127.0.0.1", "0.0.0.0").Replace(serverConfig(dir)))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	srv := srvNs.cmd(ctx, bin, "server", "--config", filepath.Join(dir, "server.yaml"))
	stderr, err := srv.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Signal(syscall.SIGTERM); _ = srv.Wait() }()
	fingerprint := fingerprintFromLogs(t, waitForReady(t, stderr))
	socket := filepath.Join(dir, "admin.sock")

	writeFile(t, filepath.Join(dir, "pw"), "integrationpassword\n")
	userCmd := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "user", "create", "alice", "--role", "member")
	userCmd.Env = append(userCmd.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(dir, "pw"))
	if out, err := userCmd.CombinedOutput(); err != nil {
		t.Fatalf("user create: %v\n%s", err, out)
	}

	var daemons []*exec.Cmd
	for i, ns := range clients {
		var tok struct {
			Secret string `json:"secret"`
		}
		out, err := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "token", "create", "--owner", "alice", "--json").CombinedOutput()
		if err != nil {
			t.Fatalf("token create: %v\n%s", err, out)
		}
		if err := json.Unmarshal(out, &tok); err != nil {
			t.Fatal(err)
		}
		name := "client-" + string(rune('1'+i))
		d := ns.cmd(ctx, bin, "client", "up", "--dns", "serve", "--server", "https://10.9."+string(rune('0'+i))+".1:8443", "--token", tok.Secret,
			"--fingerprint", fingerprint, "--state-dir", filepath.Join(dir, name), "--socket", filepath.Join(dir, name+".sock"), "--name", name)
		d.Stdout, d.Stderr = testWriter{t, name}, testWriter{t, name}
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		daemons = append(daemons, d)
	}
	defer func() {
		for _, d := range daemons {
			_ = d.Process.Signal(syscall.SIGTERM)
			_ = d.Wait()
		}
	}()

	// Wait until each client is connected and sees the other.
	type status struct {
		Self struct {
			IPv4 string `json:"ipv4"`
		} `json:"self"`
		Server struct {
			State string `json:"state"`
		} `json:"server"`
		Peers []struct {
			Name    string `json:"name"`
			IPv4    string `json:"ipv4"`
			RxBytes uint64 `json:"rx_bytes"`
		} `json:"peers"`
	}
	getStatus := func(i int) status {
		var st status
		out, err := clients[i].cmd(ctx, bin, "client", "status", "--json", "--socket", filepath.Join(dir, "client-"+string(rune('1'+i))+".sock")).Output()
		if err != nil {
			return st
		}
		_ = json.Unmarshal(out, &st)
		return st
	}
	deadline := time.Now().Add(20 * time.Second)
	var st1, st2 status
	for {
		st1, st2 = getStatus(0), getStatus(1)
		if st1.Server.State == "connected" && st2.Server.State == "connected" && len(st1.Peers) == 1 && len(st2.Peers) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients not synced: %+v / %+v", st1, st2)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// The direct path settles within seconds of the sync (spec 004);
	// until it does there is nothing to carry a ping.
	deadline = time.Now().Add(20 * time.Second)
	for clients[0].cmd(ctx, "ping", "-c", "1", "-W", "1", st2.Self.IPv4).Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("no path from client-1 to %s within 20 s", st2.Self.IPv4)
		}
	}
	if out, err := clients[0].cmd(ctx, "ping", "-c", "3", "-W", "2", st2.Self.IPv4).CombinedOutput(); err != nil {
		t.Fatalf("ping %s from client-1: %v\n%s", st2.Self.IPv4, err, out)
	}
	after := getStatus(1)
	if len(after.Peers) != 1 || after.Peers[0].RxBytes == 0 {
		t.Errorf("client-2 received nothing over the tunnel: %+v", after)
	}
	if out, err := clients[1].cmd(ctx, "ping", "-c", "3", "-W", "2", st1.Self.IPv4).CombinedOutput(); err != nil {
		t.Fatalf("ping back: %v\n%s", err, out)
	}
}

// testWriter forwards process output to the test log.
type testWriter struct {
	t    *testing.T
	name string
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("[%s] %s", w.name, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
