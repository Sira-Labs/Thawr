package server

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/backup"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// startWithConfigFile runs a server whose Deps.ConfigPath names a real
// file, as `thawr server --config` does, and with a policy on disk.
func startWithConfigFile(t *testing.T) (*harness, string) {
	t.Helper()
	cfg, dir := testConfig(t)
	allowSelfPolicy(t, cfg)
	cfgPath := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(cfgPath, []byte("public_addr: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, cfg, func(d *Deps) { d.ConfigPath = cfgPath })
	h.start(t)
	return h, cfgPath
}

func TestBackupArchive(t *testing.T) {
	h, _ := startWithConfigFile(t)
	defer h.stop(t)
	cfg := h.srv.cfg

	code, body := adminGet(t, cfg.AdminSocket, "/api/v1/backup")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/backup: %d %s", code, body)
	}
	out := filepath.Join(t.TempDir(), "x")
	m, err := backup.Extract(bytes.NewReader(body), out)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var paths []string
	for _, f := range m.Files {
		paths = append(paths, f.Path)
	}
	for _, want := range []string{DBFile, ServerKeyFile, "tls/cert.pem", "tls/key.pem", BackupConfigPath, BackupPolicyPath} {
		if !slices.Contains(paths, want) {
			t.Errorf("archive lacks %s (has %v)", want, paths)
		}
	}
	if m.ThawrVersion != "test" || m.TLSMode != cfg.TLS.Mode || m.SchemaVersion == 0 || m.ServerKeyFingerprint == "" {
		t.Errorf("manifest %+v", m)
	}
	key, _ := os.ReadFile(filepath.Join(cfg.DataDir, ServerKeyFile))
	if got, _ := os.ReadFile(filepath.Join(out, ServerKeyFile)); !bytes.Equal(got, key) {
		t.Error("server.key in the archive differs from data_dir")
	}
	// The snapshot opens and carries the same schema.
	st, err := store.Open(context.Background(), filepath.Join(out, DBFile))
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	_ = st.Close()

	entries, err := h.srv.st.Audit().List(context.Background(), store.AuditQuery{Action: control.AuditBackupCreate})
	if err != nil || len(entries) != 1 || entries[0].Actor != control.LocalAdmin.Name || entries[0].Details["sha256"] == "" {
		t.Errorf("audit rows %+v, %v", entries, err)
	}
	// The temporary archive is gone once it was sent.
	left, _ := os.ReadDir(cfg.DataDir)
	for _, e := range left {
		if strings.HasPrefix(e.Name(), ".backup-") {
			t.Errorf("temporary backup dir left behind: %s", e.Name())
		}
	}
}
