//go:build integration && linux

package tests

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// installConfig is serverConfig on ports and an interface that do not
// collide with a real installation on the same host.
func installConfig(dir string) string {
	return strings.NewReplacer("8443", "18443", "3478", "13478", "3479", "13479", "51820", "51830").Replace(serverConfig(dir)) +
		"overlay:\n  interface: thawr7\n"
}

// requireSystemd skips unless this host runs systemd as PID 1 with root
// and neither thawr service is installed already.
func requireSystemd(t *testing.T) {
	t.Helper()
	requireNetns(t)
	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemctl not found")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("systemd is not PID 1 here")
	}
	for _, unit := range []string{"thawr-server", "thawr-client"} {
		if _, err := os.Stat("/etc/systemd/system/" + unit + ".service"); err == nil {
			t.Skipf("%s is installed on this host; not touching it", unit)
		}
	}
}

// TestInstallSystemd installs the server and a client as systemd
// services with the real binary: the server runs, refuses a client
// beside it (the hub is already a peer on its host) and purges clean;
// a client installed against a server running in the foreground keeps
// no secret in its unit, connects, and uninstall keeps its data until
// --purge. Spec 009 acceptance.
func TestInstallSystemd(t *testing.T) {
	requireSystemd(t)
	dir := shortTempDir(t)
	// The units set ProtectHome=yes, so a binary in a checkout under
	// /home (a CI runner's workspace) is invisible to the service; run
	// a copy from the test's directory instead.
	built, err := os.ReadFile(thawrBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "thawr")
	if err := os.WriteFile(bin, built, 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "server.yaml")
	writeFile(t, config, installConfig(dir))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "THAWR_PASSWORD_FILE="+filepath.Join(dir, "pw"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	stateDir := filepath.Join(dir, "client")
	clientSock := filepath.Join(dir, "client.sock")
	t.Cleanup(func() {
		_, _ = run("client", "uninstall", "--state-dir", stateDir, "--purge", "--yes")
		_, _ = run("server", "uninstall", "--config", config, "--purge", "--yes")
	})

	// The server as a service.
	out, err := run("server", "install", "--config", config, "--bin", bin)
	if err != nil || !strings.Contains(out, "thawr-server started") {
		t.Fatalf("server install: %v\n%s", err, out)
	}
	waitActive(t, ctx, "thawr-server")
	socket := filepath.Join(dir, "admin.sock")
	waitFor(t, 15*time.Second, "admin socket", func() bool { _, err := os.Stat(socket); return err == nil })
	if st := getStatus(t, socket); st["peer_count"] != float64(0) {
		t.Errorf("status: %v", st)
	}
	out, err = run("client", "install", "--state-dir", stateDir, "--bin", bin, "--server", "https://127.0.0.1:18443", "--token", "unused")
	if err == nil || !strings.Contains(out, "thawr-server is installed here") {
		t.Errorf("client install beside the server: %v\n%s", err, out)
	}
	if _, err := os.Stat("/etc/systemd/system/thawr-client.service"); err == nil {
		t.Error("refused client install left a unit behind")
	}
	if out, err := run("server", "uninstall", "--config", config, "--purge", "--yes"); err != nil {
		t.Fatalf("server purge: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); err == nil {
		t.Error("data_dir kept after --purge")
	}

	// The client as a service, against a server in the foreground.
	var srvLog syncBuffer
	srv := exec.CommandContext(ctx, bin, "server", "--config", config)
	srv.Stdout, srv.Stderr = &srvLog, &srvLog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Process.Signal(syscall.SIGTERM)
		_ = srv.Wait()
		if t.Failed() {
			t.Logf("foreground server:\n%s", srvLog.String())
		}
	})
	// The service's socket file may outlive it; wait for an answer.
	waitFor(t, 15*time.Second, "foreground server", func() bool { _, err := run("admin", "--socket", socket, "peer", "list"); return err == nil })
	writeFile(t, filepath.Join(dir, "pw"), "integrationpassword\n")
	if out, err := run("admin", "--socket", socket, "user", "create", "alice", "--role", "member"); err != nil {
		t.Fatalf("user create: %v\n%s", err, out)
	}
	tokOut, err := run("admin", "--socket", socket, "token", "create", "--owner", "alice", "--json")
	if err != nil {
		t.Fatalf("token create: %v\n%s", err, tokOut)
	}
	var tok struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(tokOut), &tok); err != nil {
		t.Fatal(err)
	}
	out, err = run("client", "install", "--state-dir", stateDir, "--socket", clientSock, "--interface", "thawr8", "--bin", bin,
		"--server", "https://127.0.0.1:18443", "--token", tok.Secret, "--accept-fingerprint")
	if err != nil || !strings.Contains(out, "thawr-client started") {
		t.Fatalf("client install: %v\n%s", err, out)
	}
	data, err := os.ReadFile("/etc/systemd/system/thawr-client.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{tok.Secret, "--token", "--server"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("client unit contains %q", bad)
		}
	}
	waitActive(t, ctx, "thawr-client")
	waitFor(t, 30*time.Second, "client connected", func() bool {
		_, err := run("client", "status", "--socket", clientSock)
		return err == nil
	})

	// Uninstall keeps the data; --purge --yes removes it.
	out, err = run("client", "uninstall", "--state-dir", stateDir, "--socket", clientSock)
	if err != nil || !strings.Contains(out, "data kept") {
		t.Fatalf("client uninstall: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err != nil {
		t.Errorf("state removed without --purge: %v", err)
	}
	if out, err := run("client", "uninstall", "--state-dir", stateDir, "--socket", clientSock, "--purge", "--yes"); err != nil {
		t.Fatalf("client purge: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err == nil {
		t.Error("state kept after --purge")
	}
	for _, unit := range []string{"thawr-server", "thawr-client"} {
		if _, err := os.Stat("/etc/systemd/system/" + unit + ".service"); err == nil {
			t.Errorf("%s unit still present", unit)
		}
		if out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).CombinedOutput(); strings.TrimSpace(string(out)) == "active" {
			t.Errorf("%s still active", unit)
		}
	}
}

func waitActive(t *testing.T, ctx context.Context, unit string) {
	t.Helper()
	waitFor(t, 20*time.Second, unit+" active", func() bool {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).CombinedOutput()
		return strings.TrimSpace(string(out)) == "active"
	})
}

func waitFor(t *testing.T, timeout time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
