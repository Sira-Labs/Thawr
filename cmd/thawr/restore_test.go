package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/server"
)

func TestServerRestoreRequiresRoot(t *testing.T) {
	env := newInstallEnv(t)
	env.deps.isRoot = func() bool { return false }
	_, errOut, code := env.run(t, "server", "restore", "b.tar.gz")
	if code != exitConfigError || !strings.Contains(errOut, "needs root") {
		t.Errorf("code %d, %q", code, errOut)
	}
}

func TestServerRestoreRefusesGarbage(t *testing.T) {
	env := newInstallEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "b.tar.gz")
	if err := os.WriteFile(p, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := env.run(t, "server", "restore", p, "--config", filepath.Join(dir, "server.yaml"))
	if code != exitConfigError || !strings.Contains(errOut, "invalid backup archive") {
		t.Errorf("code %d, %q", code, errOut)
	}
}

func TestPrintRestore(t *testing.T) {
	var b bytes.Buffer
	err := printRestore(&b, server.RestoreResult{
		DataDir: "/var/lib/thawr", MovedAside: "/var/lib/thawr.pre-restore-20261002T040000Z", Peers: 7,
		SchemaArchive: 5, SchemaNow: 6, TLSFingerprint: "sha256:ab", PublicAddr: "vpn.example.org",
		ConfigPath: "/etc/thawr/server.yaml", PolicyPath: "/etc/thawr/policy.yaml", PolicyInBackup: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `restored /var/lib/thawr: 7 peers, schema 6 (migrated from 5)
previous data_dir kept at /var/lib/thawr.pre-restore-20261002T040000Z
tls fingerprint sha256:ab (unchanged; clients keep their pin)
config /etc/thawr/server.yaml kept
policy /etc/thawr/policy.yaml kept (the backup's copy was not used)
next: point vpn.example.org at this host, then start the server (thawr server, or the installed service)
`
	if b.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", b.String(), want)
	}
}
