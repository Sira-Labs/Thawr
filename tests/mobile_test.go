//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// mobileMesh starts the server, two agent clients (alice-box, bob-box)
// and a "phone" namespace that joins with wg-quick on the config
// `admin peer add-mobile` exported for alice. Needs root, iproute2,
// wg-quick and nc.
type mobileMesh struct {
	bin, dir, socket string
	srv, phone       *netns
	clients          []*netns
	status           func(i int) clientStatus
	admin            func(args ...string) ([]byte, error)
	// phoneDNS is the DNS line the exported phone config carried.
	phoneDNS string
}

// stripDNSLine removes the "DNS = ..." line from a WireGuard config and
// returns it.
func stripDNSLine(conf string) (dnsLine, rest string) {
	var kept []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "DNS = ") {
			dnsLine = line
			continue
		}
		kept = append(kept, line)
	}
	return dnsLine, strings.Join(kept, "\n")
}

func newMobileMesh(t *testing.T, policy string) *mobileMesh {
	t.Helper()
	return newStarMesh(t, policy, true)
}

// newStarMesh is newMobileMesh with the phone optional: without it only
// root and iproute2 are needed (spec 010's client resolver test).
func newStarMesh(t *testing.T, policy string, withPhone bool) *mobileMesh {
	t.Helper()
	requireNetns(t)
	if withPhone {
		for _, tool := range []string{"wg-quick", "nc"} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Skipf("%s not found", tool)
			}
		}
	}
	bin := thawrBinary(t)
	dir := shortTempDir(t)
	srvNs := newNetns(t, "srv")
	clients := []*netns{newNetns(t, "c1"), newNetns(t, "c2")}
	var phone *netns
	nodes := clients
	if withPhone {
		phone = newNetns(t, "ph")
		nodes = append(nodes, phone)
	}
	srvNs.ipForward(t)
	for i, ns := range nodes {
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
	writeFile(t, filepath.Join(dir, "policy.yaml"), emptyPolicy)
	writeFile(t, filepath.Join(dir, "server.yaml"), starServerConfig(dir))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	srv := srvNs.cmd(ctx, bin, "server", "--config", filepath.Join(dir, "server.yaml"))
	stderr, err := srv.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Signal(syscall.SIGTERM); _ = srv.Wait() })
	fingerprint := fingerprintFromLogs(t, waitForReady(t, stderr))
	socket := filepath.Join(dir, "admin.sock")
	admin := func(args ...string) ([]byte, error) {
		return srvNs.cmd(ctx, bin, append([]string{"admin", "--socket", socket}, args...)...).CombinedOutput()
	}
	writeFile(t, filepath.Join(dir, "pw"), "integrationpassword\n")
	// alice is an admin: the first network-lock record must come from a
	// device an admin owns (spec 012); bob is a member.
	for user, role := range map[string]string{"alice": "admin", "bob": "member"} {
		c := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "user", "create", user, "--role", role)
		c.Env = append(c.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(dir, "pw"))
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("user create: %v\n%s", err, out)
		}
	}
	writeFile(t, filepath.Join(dir, "policy.yaml"), policy)
	if out, err := admin("policy", "reload"); err != nil {
		t.Fatalf("policy reload: %v\n%s", err, out)
	}
	for i, ns := range clients {
		owner := []string{"alice", "bob"}[i]
		var tok struct {
			Secret string `json:"secret"`
		}
		out, err := admin("token", "create", "--owner", owner, "--json")
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
		t.Cleanup(func() { _ = d.Process.Signal(syscall.SIGTERM); _ = d.Wait() })
	}
	m := &mobileMesh{bin: bin, dir: dir, socket: socket, srv: srvNs, phone: phone, clients: clients, admin: admin}
	m.status = func(i int) clientStatus {
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
		if a, b := m.status(0), m.status(1); a.Connected() && b.Connected() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients not connected: %+v / %+v", m.status(0), m.status(1))
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !withPhone {
		return m
	}
	// The phone: export the config for alice and bring it up with
	// wg-quick. public_addr is 0.0.0.0 in this harness, so the endpoint
	// is rewritten to the server's address on the phone's link.
	conf := filepath.Join(dir, "phone.conf")
	if out, err := admin("peer", "add-mobile", "--owner", "alice", "--name", "alice-phone", "--no-qr", "--out", conf); err != nil {
		t.Fatalf("add-mobile: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0o600 {
		t.Errorf("conf mode %o, want 600", fi.Mode().Perm())
	}
	fixed := string(raw)
	if !strings.Contains(fixed, "Endpoint = 10.9.0.1:51820") {
		t.Fatalf("exported config does not point at public_addr:\n%s", raw)
	}
	// wg-quick would hand the DNS line to resolvconf, which the harness
	// host may not have; the DNS test queries the hub resolver directly.
	m.phoneDNS, fixed = stripDNSLine(fixed)
	if !hostIPv6() {
		// wg-quick cannot add the IPv6 address on a kernel without IPv6.
		fixed = stripIPv6(fixed)
	}
	writeFile(t, conf, fixed)
	if out, err := phone.cmd(ctx, "wg-quick", "up", conf).CombinedOutput(); err != nil {
		t.Fatalf("wg-quick up: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = phone.cmd(context.Background(), "wg-quick", "down", conf).Run() })
	return m
}

// stripIPv6 removes the IPv6 address and prefix from a WireGuard
// config's Address and AllowedIPs lines (spec 015).
func stripIPv6(conf string) string {
	lines := strings.Split(conf, "\n")
	for i, line := range lines {
		key, value, ok := strings.Cut(line, " = ")
		if !ok || (key != "Address" && key != "AllowedIPs") {
			continue
		}
		var kept []string
		for _, v := range strings.Split(value, ", ") {
			if !strings.Contains(v, ":") {
				kept = append(kept, v)
			}
		}
		lines[i] = key + " = " + strings.Join(kept, ", ")
	}
	return strings.Join(lines, "\n")
}

func (m *mobileMesh) phonePing(ctx context.Context, ip string) error {
	out, err := m.phone.cmd(ctx, "ping", "-c", "2", "-W", "2", ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping %s: %w\n%s", ip, err, out)
	}
	return nil
}

// phoneReaches retries a ping from the phone until it is answered or
// the deadline passes: the hub adds a new static peer to its interface
// with the next netmap generation, and WireGuard retries a handshake
// only every 5 s.
func (m *mobileMesh) phoneReaches(ctx context.Context, ip string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		err := m.phonePing(ctx, ip)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (m *mobileMesh) phoneConnect(ctx context.Context, ip, port string) bool {
	return m.phone.cmd(ctx, "nc", "-z", "-w", "2", ip, port).Run() == nil
}

// TestMobilePeerViaHub: the phone reaches an agent peer of its owner
// through the hub, the agent lists it as via hub, and deleting the peer
// cuts it off within a second.
func TestMobilePeerViaHub(t *testing.T) {
	m := newMobileMesh(t, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['alice:*']\n")
	ctx := context.Background()
	var aliceBox, phoneIP string
	deadline := time.Now().Add(20 * time.Second)
	for {
		st := m.status(0)
		aliceBox = st.Self.IPv4
		for _, p := range st.Peers {
			if p.Name == "alice-phone" && p.Path == "hub" {
				phoneIP = p.IPv4
			}
		}
		if phoneIP != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("alice-box never listed the phone via hub: %+v", st.Peers)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err := m.phoneReaches(ctx, aliceBox, 20*time.Second); err != nil {
		t.Fatalf("phone → alice-box: %v", err)
	}
	// alice-box can answer the phone at its overlay address, too.
	if out, err := m.clients[0].cmd(ctx, "ping", "-c", "2", "-W", "2", phoneIP).CombinedOutput(); err != nil {
		t.Fatalf("alice-box → phone: %v\n%s", err, out)
	}
	if out, err := m.admin("peer", "list"); err != nil || !strings.Contains(string(out), "alice-phone") || !strings.Contains(string(out), "static") {
		t.Errorf("peer list: %v\n%s", err, out)
	}
	if out, err := m.admin("peer", "delete", "alice-phone"); err != nil {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	time.Sleep(time.Second)
	if err := m.phonePing(ctx, aliceBox); err == nil {
		t.Fatal("phone still reaches alice-box after its peer was deleted")
	}
	// Re-adding yields a fresh key: the old session cannot come back.
	if out, err := m.admin("peer", "add-mobile", "--owner", "alice", "--name", "alice-phone", "--no-qr", "--out", filepath.Join(m.dir, "again.conf")); err != nil {
		t.Fatalf("re-add: %v\n%s", err, out)
	}
	if err := m.phonePing(ctx, aliceBox); err == nil {
		t.Fatal("old phone key still works after re-adding the peer")
	}
}

// TestMobilePolicyEnforced: the phone reaches only what the policy
// allows for its owner: an open port on bob-box connects, while a
// closed one and a peer alice may not see are dropped by the hub before
// forwarding.
func TestMobilePolicyEnforced(t *testing.T) {
	m := newMobileMesh(t, "version: 1\nacls:\n  - action: accept\n    src: [alice]\n    dst: ['bob:8080']\n    proto: tcp\n")
	ctx := context.Background()
	var bobIP string
	deadline := time.Now().Add(20 * time.Second)
	for {
		if st := m.status(1); st.Connected() && st.Self.IPv4 != "" {
			bobIP = st.Self.IPv4
			if len(st.Peers) >= 1 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("bob-box never saw alice's peers: %+v", m.status(1))
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, port := range []string{"8080", "9090"} {
		l := m.clients[1].cmd(ctx, "nc", "-l", "-k", "-p", port)
		if err := l.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Process.Kill(); _ = l.Wait() }()
	}
	// The phone's first handshake waits for the hub to add it.
	deadline = time.Now().Add(20 * time.Second)
	for !m.phoneConnect(ctx, bobIP, "8080") {
		if time.Now().After(deadline) {
			t.Fatal("phone cannot reach the allowed port 8080 on bob-box")
		}
		time.Sleep(500 * time.Millisecond)
	}
	// The hub's forward filter carries every rule toward a peer whose
	// source is static, so it drops the denied port before forwarding
	// (spec 008); bob-box's filter never sees the packet.
	if m.phoneConnect(ctx, bobIP, "9090") {
		t.Fatal("phone reached the denied port 9090 on bob-box")
	}
	// A peer alice may not see is unreachable: the hub does not forward.
	c := m.srv.cmd(ctx, m.bin, "admin", "--socket", m.socket, "user", "create", "carol", "--role", "member")
	c.Env = append(c.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(m.dir, "pw"))
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("user create carol: %v\n%s", err, out)
	}
	if out, err := m.admin("peer", "add-mobile", "--owner", "carol", "--name", "carol-phone", "--no-qr", "--out", filepath.Join(m.dir, "carol.conf")); err != nil {
		t.Fatalf("carol-phone: %v\n%s", err, out)
	}
	raw, _ := os.ReadFile(filepath.Join(m.dir, "carol.conf"))
	carolIP := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "Address = ") {
			carolIP = strings.TrimSuffix(strings.TrimPrefix(line, "Address = "), "/32")
		}
	}
	if carolIP == "" {
		t.Fatalf("no address in carol's config:\n%s", raw)
	}
	if err := m.phonePing(ctx, carolIP); err == nil {
		t.Fatal("phone reached carol-phone, which alice's policy does not allow")
	}
}
