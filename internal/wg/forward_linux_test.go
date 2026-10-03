//go:build integration && linux

package wg

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/nftables"
)

// TestAllowForwardThroughDockerChain creates a Docker-style FORWARD
// chain with a drop policy, checks that AllowForward inserts the accept
// rule at its top exactly once and that undo removes it. Needs root
// and the nft binary.
func TestAllowForwardThroughDockerChain(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft binary not found")
	}
	ctx := context.Background()
	nft := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	// The host may run Docker itself (CI runners do): its chains get the
	// rule too, so the test chain is counted on top of them.
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	existing, err := dropForwardChains(c)
	if err != nil {
		t.Fatal(err)
	}
	nft("add", "table", "ip", "thawrfwdtest")
	defer func() {
		_, _ = exec.CommandContext(ctx, "nft", "delete", "table", "ip", "thawrfwdtest").CombinedOutput()
	}()
	nft("add", "chain", "ip", "thawrfwdtest", "FORWARD", "{ type filter hook forward priority 0; policy drop; }")
	nft("add", "rule", "ip", "thawrfwdtest", "FORWARD", "oifname", "docker0", "accept")

	chains, undo, err := AllowForward("thawr0")
	if err != nil {
		t.Fatal(err)
	}
	if chains != len(existing)+1 {
		t.Errorf("chains touched: %d, want %d", chains, len(existing)+1)
	}
	listing := nft("list", "chain", "ip", "thawrfwdtest", "FORWARD")
	lines := strings.Split(strings.TrimSpace(listing), "\n")
	// The accept rule must precede Docker's own rules.
	var first string
	for _, l := range lines {
		if strings.Contains(l, "accept") {
			first = strings.TrimSpace(l)
			break
		}
	}
	if !strings.Contains(first, `iifname "thawr0" oifname "thawr0" accept`) {
		t.Errorf("accept rule not first:\n%s", listing)
	}
	// A second call is idempotent.
	again, undo2, err := AllowForward("thawr0")
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 || strings.Count(nft("list", "chain", "ip", "thawrfwdtest", "FORWARD"), "thawr0") != 2 {
		t.Errorf("second call changed %d chains; listing:\n%s", again, nft("list", "chain", "ip", "thawrfwdtest", "FORWARD"))
	}
	if err := undo2(); err != nil {
		t.Fatal(err)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if after := nft("list", "chain", "ip", "thawrfwdtest", "FORWARD"); strings.Contains(after, "thawr0") {
		t.Errorf("rule not removed:\n%s", after)
	}
}
