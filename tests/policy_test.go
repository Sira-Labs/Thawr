//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestPolicyEnforcedEndToEnd: two clients of different owners, a policy
// that opens one port, and the receiver-side filter (nftables with the
// kernel module, the userspace filter otherwise) letting only that port
// through; a reload flips the outcome within seconds. Needs root,
// iproute2 and nc.
func TestPolicyEnforcedEndToEnd(t *testing.T) {
	requireNetns(t)
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not found")
	}
	bin := thawrBinary(t)
	dir := shortTempDir(t)
	srvNs := newNetns(t, "srv")
	clients := []*netns{newNetns(t, "c1"), newNetns(t, "c2")}
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
	policyPath := filepath.Join(dir, "policy.yaml")
	writeFile(t, policyPath, emptyPolicy)
	writeFile(t, filepath.Join(dir, "server.yaml"), starServerConfig(dir))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
	for _, user := range []string{"alice", "bob"} {
		c := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "user", "create", user, "--role", "member")
		c.Env = append(c.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(dir, "pw"))
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("user create: %v\n%s", err, out)
		}
	}
	writeFile(t, policyPath, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:8080']\n    proto: tcp\n")
	if out, err := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "policy", "reload").CombinedOutput(); err != nil {
		t.Fatalf("policy reload: %v\n%s", err, out)
	}
	var daemons []*exec.Cmd
	for i, ns := range clients {
		owner := []string{"alice", "bob"}[i]
		var tok struct {
			Secret string `json:"secret"`
		}
		out, err := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "token", "create", "--owner", owner, "--json").CombinedOutput()
		if err != nil {
			t.Fatalf("token create: %v\n%s", err, out)
		}
		if err := json.Unmarshal(out, &tok); err != nil {
			t.Fatal(err)
		}
		name := owner + "-box"
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
	status := func(i int) clientStatus {
		var st clientStatus
		name := []string{"alice-box", "bob-box"}[i]
		out, err := clients[i].cmd(ctx, bin, "client", "status", "--json", "--socket", filepath.Join(dir, name+".sock")).Output()
		if err != nil {
			return st
		}
		_ = json.Unmarshal(out, &st)
		return st
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		a, b := status(0), status(1)
		if a.Connected() && b.Connected() && len(a.Peers) == 1 && len(b.Peers) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients not synced: %+v / %+v", a, b)
		}
		time.Sleep(500 * time.Millisecond)
	}
	bobIP := status(0).Peers[0].IPv4
	if _, _, err := pingPathOnce(ctx, clients[0], bin, filepath.Join(dir, "alice-box.sock"), "bob-box"); err != nil {
		t.Fatalf("no path to bob: %v", err)
	}

	// Listeners on bob: 8080 (allowed) and 9090 (denied).
	for _, port := range []string{"8080", "9090"} {
		l := clients[1].cmd(ctx, "nc", "-l", "-k", "-p", port)
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Process.Kill(); _ = l.Wait() }()
	}
	time.Sleep(500 * time.Millisecond)
	connect := func(port string) bool {
		out, err := clients[0].cmd(ctx, "nc", "-z", "-w", "2", bobIP, port).CombinedOutput()
		t.Logf("nc %s:%s: err=%v %s", bobIP, port, err, out)
		return err == nil
	}
	if !connect("8080") {
		t.Fatal("allowed port 8080 unreachable")
	}
	if connect("9090") {
		t.Fatal("denied port 9090 reachable")
	}
	if st := status(1); st.Filter == nil || st.Filter.Drops == 0 {
		t.Errorf("bob's filter counted no drops: %+v", st.Filter)
	}

	// Open 9090 with a reload; it must take effect within 5 s.
	writeFile(t, policyPath, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:8080,9090']\n    proto: tcp\n")
	if out, err := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "policy", "reload").CombinedOutput(); err != nil {
		t.Fatalf("reload: %v\n%s", err, out)
	}
	start := time.Now()
	for !connect("9090") {
		if time.Since(start) > 5*time.Second {
			t.Fatal("9090 still closed 5 s after reload")
		}
		time.Sleep(500 * time.Millisecond)
	}
	// An invalid file is rejected and changes nothing.
	writeFile(t, policyPath, "version: 1\nacls:\n  - action: deny\n")
	if out, err := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "policy", "reload").CombinedOutput(); err == nil {
		t.Fatalf("invalid reload succeeded:\n%s", out)
	}
	if !connect("9090") {
		t.Fatal("invalid reload changed the policy")
	}
	_ = http.StatusOK
}

// pingPathOnce runs `client ping` and returns the path state.
func pingPathOnce(ctx context.Context, ns *netns, bin, socket, peer string) (string, string, error) {
	out, err := ns.cmd(ctx, bin, "client", "ping", peer, "--json", "--count", "0", "--socket", socket).Output()
	var res struct {
		State    string `json:"state"`
		Endpoint string `json:"endpoint"`
	}
	_ = json.Unmarshal(out, &res)
	if err != nil && res.State == "" {
		return "", "", fmt.Errorf("client ping: %w", err)
	}
	return res.State, res.Endpoint, nil
}
