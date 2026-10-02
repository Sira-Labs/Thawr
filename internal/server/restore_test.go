package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sira-labs/thawr/internal/backup"
	"github.com/sira-labs/thawr/internal/config"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// source is a server that was backed up and stopped.
type source struct {
	archive     string
	fingerprint string
	hubKey      string
	policy      []byte
}

// backedUpServer starts a server with a peer, writes a backup archive
// to disk and stops the server.
func backedUpServer(t *testing.T) source {
	t.Helper()
	h := startWithConfigFile(t)
	ctx := context.Background()
	if err := h.srv.st.Peers().Create(ctx, store.Peer{ID: "p1", Name: "laptop", Kind: store.KindHuman, Mode: store.ModeAgent,
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", IPv4: "100.64.0.2", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	f, err := h.srv.CreateBackup(ctx, control.LocalAdmin)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	data, err := os.ReadFile(f.Path)
	f.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	policy, _ := os.ReadFile(h.srv.cfg.PolicyFile)
	src := source{archive: archive, fingerprint: h.srv.tlsFingerprint, hubKey: h.srv.hubKey.PublicKey().String(), policy: policy}
	h.stop(t)
	return src
}

// freshHost is a config for an empty host: its own data_dir, socket and
// policy path, written to a config file.
func freshHost(t *testing.T) (*config.Config, string) {
	t.Helper()
	cfg, dir := testConfig(t)
	return cfg, writeConfigFile(t, cfg, dir)
}

func TestRestoreRoundTrip(t *testing.T) {
	src := backedUpServer(t)
	cfg, cfgPath := freshHost(t)

	res, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if res.Peers != 1 || res.TLSFingerprint != src.fingerprint || res.MovedAside != "" || res.ConfigWritten || !res.PolicyWritten {
		t.Errorf("result %+v", res)
	}
	if got, _ := os.ReadFile(cfg.PolicyFile); !bytes.Equal(got, src.policy) {
		t.Errorf("policy not restored: %q", got)
	}

	h := newHarness(t, cfg)
	h.start(t)
	defer h.stop(t)
	if h.srv.tlsFingerprint != src.fingerprint || h.srv.hubKey.PublicKey().String() != src.hubKey {
		t.Error("restored server presents another certificate or WireGuard key")
	}
	if _, err := h.srv.st.Peers().GetByName(context.Background(), "laptop"); err != nil {
		t.Errorf("peer missing after restore: %v", err)
	}
}

func TestRestoreUsesArchiveConfigOnFreshHost(t *testing.T) {
	src := backedUpServer(t)
	cfgPath := filepath.Join(t.TempDir(), "etc", "server.yaml")
	// The archive's config names the source's (temporary) data_dir, which
	// stands in for the fresh host's: empty it, then restore into it.
	m, err := os.Open(src.archive)
	if err != nil {
		t.Fatal(err)
	}
	staged := t.TempDir()
	man, err := backup.Extract(m, staged)
	_ = m.Close()
	if err != nil {
		t.Fatal(err)
	}
	archCfg, err := config.Load(filepath.Join(staged, filepath.FromSlash(BackupConfigPath)))
	if err != nil {
		t.Fatalf("archive config: %v (manifest %+v)", err, man)
	}
	if !strings.HasPrefix(archCfg.DataDir, os.TempDir()) {
		t.Fatalf("archive config names %s, not a temp dir; refusing to touch it", archCfg.DataDir)
	}
	if err := os.RemoveAll(archCfg.DataDir); err != nil {
		t.Fatal(err)
	}

	res, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !res.ConfigWritten || res.DataDir != archCfg.DataDir {
		t.Errorf("result %+v", res)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("config not written: %v", err)
	}
}

func TestRestoreRefuses(t *testing.T) {
	src := backedUpServer(t)
	data, _ := os.ReadFile(src.archive)

	t.Run("tampered archive", func(t *testing.T) {
		_, cfgPath := freshHost(t)
		bad := bytes.Clone(data)
		bad[len(bad)/2] ^= 0xff
		p := filepath.Join(t.TempDir(), "bad.tar.gz")
		_ = os.WriteFile(p, bad, 0o600)
		if _, err := Restore(context.Background(), RestoreOptions{Archive: p, ConfigPath: cfgPath}); err == nil {
			t.Fatal("restored a tampered archive")
		}
	})

	t.Run("newer schema", func(t *testing.T) {
		cfg, cfgPath := freshHost(t)
		dir := t.TempDir()
		f := filepath.Join(dir, "x")
		_ = os.WriteFile(f, []byte("x"), 0o600)
		var buf bytes.Buffer
		if _, err := backup.Write(&buf, backup.Manifest{SchemaVersion: 9999, ThawrVersion: "v9.0.0"}, []backup.Source{{Path: DBFile, From: f}}); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "new.tar.gz")
		_ = os.WriteFile(p, buf.Bytes(), 0o600)
		_, err := Restore(context.Background(), RestoreOptions{Archive: p, ConfigPath: cfgPath})
		if err == nil || !strings.Contains(err.Error(), "newer than this binary") {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Stat(cfg.DataDir); err == nil {
			t.Error("data_dir created for a refused archive")
		}
	})

	t.Run("non-empty data_dir", func(t *testing.T) {
		cfg, cfgPath := freshHost(t)
		_ = os.MkdirAll(cfg.DataDir, 0o700)
		_ = os.WriteFile(filepath.Join(cfg.DataDir, "keep.me"), []byte("x"), 0o600)
		_, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath})
		if !errors.Is(err, ErrDataDirNotEmpty) {
			t.Fatalf("got %v, want ErrDataDirNotEmpty", err)
		}
		if _, err := os.Stat(filepath.Join(cfg.DataDir, "keep.me")); err != nil {
			t.Error("existing data_dir was touched")
		}
	})

	t.Run("running server", func(t *testing.T) {
		cfg, cfgPath := freshHost(t)
		h := newHarness(t, cfg)
		h.start(t)
		defer h.stop(t)
		_, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath, Force: true})
		if !errors.Is(err, ErrServerRunning) {
			t.Fatalf("got %v, want ErrServerRunning", err)
		}
	})

	t.Run("data_dir locked", func(t *testing.T) {
		cfg, cfgPath := freshHost(t)
		_ = os.MkdirAll(cfg.DataDir, 0o700)
		lk, err := LockDataDir(cfg.DataDir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lk.Close() }()
		if _, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath, Force: true}); !errors.Is(err, ErrDataDirInUse) {
			t.Fatalf("got %v, want ErrDataDirInUse", err)
		}
	})
}

func TestRestoreForceKeepsOldDir(t *testing.T) {
	src := backedUpServer(t)
	cfg, cfgPath := freshHost(t)
	_ = os.MkdirAll(cfg.DataDir, 0o700)
	_ = os.WriteFile(filepath.Join(cfg.DataDir, "old.txt"), []byte("old"), 0o600)
	now := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	res, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath, Force: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("Restore --force: %v", err)
	}
	want := cfg.DataDir + ".pre-restore-20261002T040000Z"
	if res.MovedAside != want {
		t.Errorf("moved aside to %q, want %q", res.MovedAside, want)
	}
	if b, err := os.ReadFile(filepath.Join(want, "old.txt")); err != nil || string(b) != "old" {
		t.Errorf("old data_dir not kept: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, DBFile)); err != nil {
		t.Errorf("restored database missing: %v", err)
	}
}

func TestRestoreKeepsExistingPolicy(t *testing.T) {
	src := backedUpServer(t)
	cfg, cfgPath := freshHost(t)
	if err := os.WriteFile(cfg.PolicyFile, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Restore(context.Background(), RestoreOptions{Archive: src.archive, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	if res.PolicyWritten || !res.PolicyInBackup {
		t.Errorf("result %+v", res)
	}
	if b, _ := os.ReadFile(cfg.PolicyFile); string(b) != "version: 1\n" {
		t.Errorf("existing policy overwritten: %q", b)
	}
}

// TestRestoreFailureLeavesEmptyDataDir: a server key that does not
// belong to the database fails the restore, and data_dir is emptied so
// a retry needs no --force.
func TestRestoreFailureLeavesEmptyDataDir(t *testing.T) {
	src := backedUpServer(t)
	other := backedUpServer(t)
	// Rebuild the first archive with the second server's key.
	staged := t.TempDir()
	f, _ := os.Open(src.archive)
	if _, err := backup.Extract(f, staged); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	staged2 := t.TempDir()
	f2, _ := os.Open(other.archive)
	if _, err := backup.Extract(f2, staged2); err != nil {
		t.Fatal(err)
	}
	_ = f2.Close()
	var buf bytes.Buffer
	srcs := []backup.Source{
		{Path: DBFile, From: filepath.Join(staged, DBFile)},
		{Path: ServerKeyFile, From: filepath.Join(staged2, ServerKeyFile)},
		{Path: "tls/cert.pem", From: filepath.Join(staged, "tls", "cert.pem")},
		{Path: "tls/key.pem", From: filepath.Join(staged, "tls", "key.pem")},
	}
	if _, err := backup.Write(&buf, backup.Manifest{SchemaVersion: 1}, srcs); err != nil {
		t.Fatal(err)
	}
	mixed := filepath.Join(t.TempDir(), "mixed.tar.gz")
	_ = os.WriteFile(mixed, buf.Bytes(), 0o600)

	cfg, cfgPath := freshHost(t)
	if _, err := Restore(context.Background(), RestoreOptions{Archive: mixed, ConfigPath: cfgPath}); err == nil {
		t.Fatal("restored a database with another server's key")
	}
	empty, err := dirEmpty(cfg.DataDir)
	if err != nil || !empty {
		t.Errorf("data_dir not emptied after a failed restore (empty=%v, %v)", empty, err)
	}
}
