//go:build integration && linux

package tests

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// requireNetns skips the test unless it can create network namespaces:
// Linux, root, and the iproute2 `ip` binary on PATH.
func requireNetns(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("network namespaces need Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("network namespaces need root (CAP_NET_ADMIN)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 `ip` binary not found")
	}
}

// netns is a throwaway network namespace with loopback up.
type netns struct {
	name string
}

// newNetns creates a namespace named after the test and deletes it on
// cleanup.
func newNetns(t *testing.T, suffix string) *netns {
	t.Helper()
	name := "thawr-" + strings.ToLower(strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())) + "-" + suffix
	if len(name) > 15 {
		name = name[len(name)-15:]
	}
	ip(t, "netns", "add", name)
	ns := &netns{name: name}
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "ip", "netns", "del", name).Run() })
	ns.ip(t, "link", "set", "lo", "up")
	return ns
}

// cmd builds a command that executes inside the namespace.
func (n *netns) cmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	full := append([]string{"netns", "exec", n.name, name}, args...)
	return exec.CommandContext(ctx, "ip", full...)
}

// ip runs an iproute2 command inside the namespace and returns its output.
func (n *netns) ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := n.cmd(context.Background(), "ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("in %s: ip %v: %v\n%s", n.name, args, err, out)
	}
	return string(out)
}

// ipForward turns on IPv4 forwarding inside the namespace.
func (n *netns) ipForward(t *testing.T) {
	t.Helper()
	if out, err := n.cmd(context.Background(), "sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		t.Fatalf("in %s: sysctl net.ipv4.ip_forward=1: %v\n%s", n.name, err, out)
	}
}

// ip runs an iproute2 command in the host namespace.
func ip(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.CommandContext(context.Background(), "ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v\n%s", args, err, out)
	}
}

// thawrBinary returns the path of the built binary, building it if
// needed so `go test -tags integration ./tests/...` is self-contained.
func thawrBinary(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin", "thawr")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "./cmd/thawr")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build thawr: %v\n%s", err, out)
	}
	return bin
}

// shortTempDir keeps Unix socket paths under the kernel's length limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "thawr-it")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// allowAllPolicy lets every peer reach every port of every other. The
// suites that test paths rather than policy run with it, since a
// server without a policy denies everything (spec 006); it names no
// user, so the server accepts it before any user exists.
const allowAllPolicy = "version: 1\nacls:\n  - action: accept\n    src: ['*']\n    dst: ['*:*']\n"

// emptyPolicy is valid before any user exists; a test whose policy
// names users starts with it and reloads its own once they exist.
const emptyPolicy = "version: 1\n"

func serverConfig(dir string) string {
	return fmt.Sprintf(`public_addr: 127.0.0.1
data_dir: %s/data
listen:
  https: "127.0.0.1:8443"
  stun: ["127.0.0.1:3478", "127.0.0.1:3479"]
  wireguard: "127.0.0.1:51820"
admin_socket: %s/admin.sock
policy_file: %s/policy.yaml
`, dir, dir, dir)
}
