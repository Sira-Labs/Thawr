//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// natKind is how a client's NAT namespace translates.
type natKind string

const (
	// natRestricted is Linux masquerade as is: port-preserving,
	// address-and-port-restricted filtering (the common home router).
	natRestricted natKind = "restricted"
	// natFullCone adds a catch-all DNAT so any inbound datagram to a
	// mapped port reaches the client.
	natFullCone natKind = "fullcone"
	// natSymmetric masquerades with fully random ports per flow.
	natSymmetric natKind = "symmetric"
)

// requireNAT skips unless namespaces and nftables are available.
func requireNAT(t *testing.T) {
	t.Helper()
	requireNetns(t)
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nftables `nft` binary not found")
	}
}

// natSite is one client behind its own NAT.
type natSite struct {
	nat, client *netns
	lanIP       string // client address on its LAN
	wanIP       string // NAT address on the server-facing link
}

// serverIP is the server's address on the "internet" segment; every NAT
// namespace routes to it by default, so it is the public address.
const serverIP = "10.8.0.1"

// natTopology builds: server namespace; per client a NAT namespace
// (link to the server on 10.8.i.0/24) and a client namespace on a
// private LAN behind it. With sameLAN both clients share the first
// NAT's LAN through a bridge.
func natTopology(t *testing.T, kinds []natKind, sameLAN bool) (*netns, []natSite) {
	t.Helper()
	srv := newNetns(t, "srv")
	// The "internet" is one segment: a bridge in the server namespace
	// that every NAT's WAN side joins. The server is single-homed on it,
	// as a real one is: with an address per NAT link it would answer UDP
	// (STUN, WireGuard) from the address of the outgoing link, which no
	// NAT's conntrack entry expects.
	srv.ip(t, "link", "add", "inet0", "type", "bridge")
	srv.ip(t, "addr", "add", serverIP+"/16", "dev", "inet0")
	srv.ip(t, "link", "set", "inet0", "up")
	var sites []natSite
	for i, kind := range kinds {
		client := newNetns(t, fmt.Sprintf("c%d", i))
		var nat *netns
		lan := fmt.Sprintf("192.168.%d", 10+i)
		if sameLAN && i > 0 {
			nat = sites[0].nat
			lan = "192.168.10"
		} else {
			nat = newNetns(t, fmt.Sprintf("n%d", i))
			nat.ipForward(t)
			// NAT <-> internet link.
			ps, pn := fmt.Sprintf("p%ds", i), fmt.Sprintf("p%dn", i)
			ip(t, "link", "add", ps, "type", "veth", "peer", "name", pn)
			ip(t, "link", "set", ps, "netns", srv.name)
			ip(t, "link", "set", pn, "netns", nat.name)
			srv.ip(t, "link", "set", ps, "master", "inet0")
			srv.ip(t, "link", "set", ps, "up")
			nat.ip(t, "addr", "add", fmt.Sprintf("10.8.%d.2/16", i), "dev", pn)
			nat.ip(t, "link", "set", pn, "up")
			nat.ip(t, "route", "add", "default", "via", serverIP)
			if sameLAN {
				nat.ip(t, "link", "add", "br0", "type", "bridge")
				nat.ip(t, "addr", "add", lan+".1/24", "dev", "br0")
				nat.ip(t, "link", "set", "br0", "up")
			}
			applyNAT(t, nat, kind, pn, lan+".2")
		}
		// NAT <-> client link.
		ln, lc := fmt.Sprintf("l%dn", i), fmt.Sprintf("l%dc", i)
		ip(t, "link", "add", ln, "type", "veth", "peer", "name", lc)
		ip(t, "link", "set", ln, "netns", nat.name)
		ip(t, "link", "set", lc, "netns", client.name)
		if sameLAN {
			nat.ip(t, "link", "set", ln, "master", "br0")
		} else {
			nat.ip(t, "addr", "add", lan+".1/24", "dev", ln)
		}
		nat.ip(t, "link", "set", ln, "up")
		lanIP := fmt.Sprintf("%s.%d", lan, 2+i)
		if !sameLAN {
			lanIP = lan + ".2"
		}
		client.ip(t, "addr", "add", lanIP+"/24", "dev", lc)
		client.ip(t, "link", "set", lc, "up")
		client.ip(t, "route", "add", "default", "via", lan+".1")
		wan := fmt.Sprintf("10.8.%d.2", i)
		if sameLAN && i > 0 {
			wan = sites[0].wanIP
		}
		sites = append(sites, natSite{nat: nat, client: client, lanIP: lanIP, wanIP: wan})
	}
	return srv, sites
}

// applyNAT installs the nftables ruleset for kind in the NAT namespace.
func applyNAT(t *testing.T, nat *netns, kind natKind, wanIface, lanClient string) {
	t.Helper()
	masq := "masquerade"
	if kind == natSymmetric {
		masq = "masquerade fully-random"
	}
	// Re-applying replaces the tables: nft -f appends rules to an
	// existing chain, and the old masquerade would keep matching first.
	rules := `table ip nat
delete table ip nat
table ip filter
delete table ip filter
`
	rules += fmt.Sprintf(`table ip nat {
  chain postrouting { type nat hook postrouting priority srcnat; oifname %q %s; }
`, wanIface, masq)
	if kind == natFullCone {
		rules += fmt.Sprintf(`  chain prerouting { type nat hook prerouting priority dstnat; iifname %q udp dport 1024-65535 dnat to %s; }
`, wanIface, lanClient)
	}
	rules += "}\n"
	// Like a real router, the NAT drops unsolicited packets to itself on
	// its WAN side. Without this, a hole-punching packet that arrives a
	// moment before the local client's own leaves a confirmed conntrack
	// entry behind, the client's packet clashes with it, and masquerade
	// moves it to another port: the punch fails for an artefact of the
	// simulation.
	rules += fmt.Sprintf(`table ip filter {
  chain input { type filter hook input priority filter; policy accept; iifname %q ct state new drop; }
}
`, wanIface)
	cmd := nat.cmd(context.Background(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft in %s: %v\n%s\n%s", nat.name, err, out, rules)
	}
}

// clientStatus is the subset of `client status --json` the NAT tests
// read (docs/status.schema.json).
type clientStatus struct {
	Self struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	} `json:"self"`
	Server struct {
		State string `json:"state"`
	} `json:"server"`
	NAT struct {
		Type string `json:"type"`
	} `json:"nat"`
	Relay struct {
		Connected bool `json:"connected"`
		Peers     int  `json:"peers"`
	} `json:"relay"`
	Filter *struct {
		Rules int    `json:"rules"`
		Drops uint64 `json:"drops"`
	} `json:"filter"`
	Held []struct {
		Name       string `json:"name"`
		PinnedKey  string `json:"pinned_key"`
		OfferedKey string `json:"offered_key"`
		Reason     string `json:"reason"`
	} `json:"held"`
	Lock struct {
		Enabled    bool   `json:"enabled"`
		Signer     bool   `json:"signer"`
		Generation uint64 `json:"generation"`
		SelfSigned bool   `json:"self_signed"`
		Rejected   string `json:"rejected"`
	} `json:"lock"`
	Peers []struct {
		Name               string `json:"name"`
		IPv4               string `json:"ipv4"`
		IPv6               string `json:"ipv6"`
		PublicKey          string `json:"public_key"`
		Path               string `json:"path"`
		PathEndpoint       string `json:"path_endpoint"`
		Probes             int    `json:"probes"`
		EndpointCandidates []struct {
			Addr string `json:"addr"`
			Kind string `json:"kind"`
		} `json:"endpoint_candidates"`
		RxBytes uint64 `json:"rx_bytes"`
	} `json:"peers"`
}

// Connected reports whether the client has a live control connection.
func (s clientStatus) Connected() bool { return s.Server.State == "connected" }

// natMesh starts the server and two clients behind kinds and waits until
// both are synced with each other's candidates. It returns a status
// function, a ping-path function and the clients' namespaces.
func natMesh(t *testing.T, kinds []natKind, sameLAN bool) (status func(int) clientStatus, pingPath func(int) (string, string, error), sites []natSite) {
	t.Helper()
	bin := thawrBinary(t)
	dir := shortTempDir(t)
	srvNs, sites := natTopology(t, kinds, sameLAN)

	writeFile(t, filepath.Join(dir, "policy.yaml"), allowAllPolicy)
	writeFile(t, filepath.Join(dir, "server.yaml"), strings.NewReplacer("public_addr: 127.0.0.1", "public_addr: "+serverIP, "127.0.0.1", "0.0.0.0").Replace(serverConfig(dir)))
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

	writeFile(t, filepath.Join(dir, "pw"), "integrationpassword\n")
	userCmd := srvNs.cmd(ctx, bin, "admin", "--socket", socket, "user", "create", "alice", "--role", "member")
	userCmd.Env = append(userCmd.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(dir, "pw"))
	if out, err := userCmd.CombinedOutput(); err != nil {
		t.Fatalf("user create: %v\n%s", err, out)
	}
	for i, site := range sites {
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
		name := fmt.Sprintf("client-%d", i+1)
		d := site.client.cmd(ctx, bin, "client", "up", "--dns", "serve", "--server", "https://"+serverIP+":8443", "--token", tok.Secret,
			"--fingerprint", fingerprint, "--state-dir", filepath.Join(dir, name), "--socket", filepath.Join(dir, name+".sock"), "--name", name, "--log-level", "debug")
		d.Stdout, d.Stderr = testWriter{t, name}, testWriter{t, name}
		if err := d.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Process.Signal(syscall.SIGTERM); _ = d.Wait() })
	}
	status = func(i int) clientStatus {
		var st clientStatus
		out, err := sites[i].client.cmd(ctx, bin, "client", "status", "--json", "--socket", filepath.Join(dir, fmt.Sprintf("client-%d.sock", i+1))).Output()
		if err != nil {
			return st
		}
		_ = json.Unmarshal(out, &st)
		return st
	}
	pingPath = func(i int) (string, string, error) {
		other := fmt.Sprintf("client-%d", 2-i)
		out, err := sites[i].client.cmd(ctx, bin, "client", "ping", other, "--json", "--count", "0", "--socket", filepath.Join(dir, fmt.Sprintf("client-%d.sock", i+1))).Output()
		var res struct {
			State    string `json:"state"`
			Endpoint string `json:"endpoint"`
		}
		_ = json.Unmarshal(out, &res)
		return res.State, res.Endpoint, err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		s1, s2 := status(0), status(1)
		if s1.Connected() && s2.Connected() && len(s1.Peers) == 1 && len(s2.Peers) == 1 && len(s1.Peers[0].EndpointCandidates) > 0 && len(s2.Peers[0].EndpointCandidates) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("clients not synced with candidates: %+v / %+v", s1, s2)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return status, pingPath, sites
}

// TestNATTraversal covers the spec 004 acceptance topologies, with
// spec 005's relay where no direct path exists: `client ping` returns
// with the first usable path, which may be the relay while the other
// side is still punching back, so the test waits for the state the
// topology must settle on, within 10 s of the ping.
func TestNATTraversal(t *testing.T) {
	requireNAT(t)
	cases := []struct {
		name      string
		kinds     []natKind
		sameLAN   bool
		wantState string
		wantAddr  func(sites []natSite) string // prefix of the path endpoint
	}{
		{"restricted cone both sides", []natKind{natRestricted, natRestricted}, false, "direct", func(s []natSite) string { return s[1].wanIP + ":" }},
		{"full cone and symmetric", []natKind{natFullCone, natSymmetric}, false, "direct", func(s []natSite) string { return s[1].wanIP + ":" }},
		{"symmetric both sides", []natKind{natSymmetric, natSymmetric}, false, "relay", nil},
		{"same LAN", []natKind{natRestricted, natRestricted}, true, "direct", func(s []natSite) string { return s[1].lanIP + ":" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, pingPath, sites := natMesh(t, tc.kinds, tc.sameLAN)
			start := time.Now()
			if state, _, err := pingPath(0); err != nil {
				t.Fatalf("client ping: %v (state %s)", err, state)
			}
			var st clientStatus
			for {
				st = status(0)
				if len(st.Peers) == 1 && st.Peers[0].Path == tc.wantState {
					break
				}
				if time.Since(start) > 10*time.Second {
					t.Fatalf("path = %+v after %s, want %s", st.Peers, time.Since(start).Round(time.Second), tc.wantState)
				}
				time.Sleep(250 * time.Millisecond)
			}
			endpoint := st.Peers[0].PathEndpoint
			if tc.wantAddr != nil && !strings.HasPrefix(endpoint, tc.wantAddr(sites)) {
				t.Errorf("path endpoint %s, want prefix %s", endpoint, tc.wantAddr(sites))
			}
			if tc.wantState == "relay" {
				// No probe storm: at most one probe per 2 s window.
				took := time.Since(start)
				if st.Peers[0].Probes > int(took/(2*time.Second))+1 {
					t.Errorf("%d probes in %s", st.Peers[0].Probes, took)
				}
				if st.NAT.Type != "symmetric" {
					t.Errorf("client did not detect its symmetric NAT: %+v", st)
				}
			}
			peerIP := st.Peers[0].IPv4
			// Over the relay, client-2 answers once it has joined it.
			deadline := time.Now().Add(20 * time.Second)
			for sites[0].client.cmd(context.Background(), "ping", "-c", "1", "-W", "1", peerIP).Run() != nil {
				if time.Now().After(deadline) {
					t.Fatalf("no echo from %s over the %s path within 20 s", peerIP, tc.wantState)
				}
			}
			if out, err := sites[0].client.cmd(context.Background(), "ping", "-c", "3", "-W", "2", peerIP).CombinedOutput(); err != nil {
				t.Fatalf("ping %s over the %s path: %v\n%s", peerIP, tc.wantState, err, out)
			}
			if other := status(1); len(other.Peers) != 1 || other.Peers[0].Path != tc.wantState || other.Peers[0].RxBytes == 0 {
				t.Errorf("client-2 side: %+v", other)
			}
		})
	}
}
