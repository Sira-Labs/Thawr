package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sira-labs/thawr/internal/backup"
	"github.com/sira-labs/thawr/internal/config"
	"github.com/sira-labs/thawr/internal/store"
)

// ErrServerRunning means a restore found a live server for its data_dir.
var ErrServerRunning = errors.New("server running")

// ErrDataDirNotEmpty means restore refused to replace an existing
// data_dir without --force.
var ErrDataDirNotEmpty = errors.New("data dir not empty")

// RestoreOptions configure Restore.
type RestoreOptions struct {
	// Archive is the backup file to restore.
	Archive string
	// ConfigPath is where the server reads its config. When no file is
	// there, the archive's copy is used and written there.
	ConfigPath string
	// Force moves a non-empty data_dir aside instead of refusing.
	Force bool
	// Now defaults to time.Now.
	Now func() time.Time
}

// RestoreResult reports what Restore did.
type RestoreResult struct {
	DataDir        string
	MovedAside     string // the previous data_dir, when Force moved it
	Peers          int
	SchemaArchive  int
	SchemaNow      int
	TLSFingerprint string // empty when tls.mode is file
	PublicAddr     string
	ConfigPath     string
	ConfigWritten  bool
	PolicyPath     string
	PolicyWritten  bool
	PolicyInBackup bool
}

// Restore turns a backup archive into a data_dir for a stopped server
// (spec 014): it verifies the whole archive before touching anything,
// refuses a running server and a newer schema, never deletes an existing
// data_dir (Force moves it aside), migrates an older database, checks
// that the server key matches the database, and writes the config and
// policy copies only where no file exists yet.
func Restore(ctx context.Context, opts RestoreOptions) (res RestoreResult, err error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	staging, err := os.MkdirTemp("", "thawr-restore-")
	if err != nil {
		return res, fmt.Errorf("restore: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	m, err := extractArchive(opts.Archive, staging)
	if err != nil {
		return res, err
	}
	res.SchemaArchive = m.SchemaVersion
	latest, err := store.LatestSchemaVersion()
	if err != nil {
		return res, err
	}
	if m.SchemaVersion > latest {
		return res, fmt.Errorf("restore: backup schema version %d is newer than this binary (%d); install the thawr release that made it (%s) or newer", m.SchemaVersion, latest, m.ThawrVersion)
	}

	cfg, err := restoreConfig(opts.ConfigPath, staging)
	if err != nil {
		return res, err
	}
	res.DataDir, res.ConfigPath, res.PolicyPath, res.PublicAddr = cfg.DataDir, opts.ConfigPath, cfg.PolicyFile, cfg.PublicAddr

	if adminSocketAnswers(ctx, cfg.AdminSocket) {
		return res, fmt.Errorf("restore: a thawr server answers on %s; stop it first: %w", cfg.AdminSocket, ErrServerRunning)
	}
	lk, moved, err := prepareDataDir(cfg.DataDir, opts.Force, opts.Now())
	if err != nil {
		return res, err
	}
	defer func() { _ = lk.Close() }()
	res.MovedAside = moved
	// data_dir was empty (or emptied) and is restore's alone: on failure
	// it is emptied again, so a retry needs no --force.
	defer func() {
		if err != nil {
			clearDataDir(cfg.DataDir)
		}
	}()

	for _, f := range m.Files {
		if strings.HasPrefix(f.Path, "config/") {
			continue
		}
		if err := copyRestored(filepath.Join(staging, filepath.FromSlash(f.Path)), filepath.Join(cfg.DataDir, filepath.FromSlash(f.Path))); err != nil {
			return res, err
		}
	}
	if err := checkRestored(ctx, cfg, &res); err != nil {
		return res, err
	}

	if res.ConfigWritten, err = writeIfAbsent(filepath.Join(staging, filepath.FromSlash(BackupConfigPath)), opts.ConfigPath); err != nil {
		return res, err
	}
	policy := filepath.Join(staging, filepath.FromSlash(BackupPolicyPath))
	res.PolicyInBackup = fileExists(policy)
	if res.PolicyWritten, err = writeIfAbsent(policy, cfg.PolicyFile); err != nil {
		return res, err
	}
	return res, nil
}

func extractArchive(path, dir string) (backup.Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return backup.Manifest{}, fmt.Errorf("restore: %w", err)
	}
	defer func() { _ = f.Close() }()
	m, err := backup.Extract(f, dir)
	if err != nil {
		return m, fmt.Errorf("restore: %s: %w", path, err)
	}
	return m, nil
}

// restoreConfig loads the config at path, or, on a fresh host without
// one, the copy inside the archive.
func restoreConfig(path, staging string) (*config.Config, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return config.Load(path)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("restore: config %s: %w", path, err)
	}
	data, err := os.ReadFile(filepath.Join(staging, filepath.FromSlash(BackupConfigPath)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("restore: no config at %s and the backup holds none; write the config first or pass --config", path)
	}
	if err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	cfg, err := config.Parse(data, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("restore: config in the backup: %w", err)
	}
	return cfg, nil
}

// adminSocketAnswers reports a live server: a socket file nobody serves
// is refused at once, so only a running server makes this true.
func adminSocketAnswers(ctx context.Context, socket string) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// prepareDataDir leaves an empty, locked data_dir: it creates a missing
// one, refuses a non-empty one unless force, and with force renames it
// to <dir>.pre-restore-<time> (never deleting it) and starts afresh.
func prepareDataDir(dir string, force bool, now time.Time) (lk io.Closer, moved string, err error) {
	if _, err := ensureDataDir(dir); err != nil {
		return nil, "", err
	}
	l, err := LockDataDir(dir)
	if err != nil {
		return nil, "", fmt.Errorf("restore: %w", err)
	}
	empty, err := dirEmpty(dir)
	if err != nil {
		_ = l.Close()
		return nil, "", err
	}
	if empty {
		return l, "", nil
	}
	if !force {
		_ = l.Close()
		return nil, "", fmt.Errorf("restore: %s is not empty; pass --force to move it aside (it is kept, not deleted): %w", dir, ErrDataDirNotEmpty)
	}
	moved = dir + ".pre-restore-" + now.UTC().Format("20060102T150405Z")
	// Rename while still holding the lock, so no server can take the
	// directory between the check and the move: on Unix a lock survives
	// the rename of its directory. Windows refuses to rename a directory
	// with an open handle inside, ours included; there the lock is
	// released and the rename tried once more, and a server that took
	// the lock in that moment keeps files open, so the retry fails
	// instead of moving a live database.
	err = os.Rename(dir, moved)
	if err != nil {
		if cerr := l.Close(); cerr != nil {
			return nil, "", fmt.Errorf("restore: %w", cerr)
		}
		l = nil
		err = os.Rename(dir, moved)
	}
	if err != nil {
		return nil, "", fmt.Errorf("restore: move %s aside: %w", dir, err)
	}
	if l != nil {
		// The lock moved with the old directory; it has done its job.
		_ = l.Close()
	}
	if _, err := ensureDataDir(dir); err != nil {
		return nil, moved, err
	}
	// A server started between the move and this lock owns the new
	// directory; restore stops here and writes nothing into it.
	l, err = LockDataDir(dir)
	if err != nil {
		return nil, moved, fmt.Errorf("restore: %w", err)
	}
	return l, moved, nil
}

// clearDataDir removes everything restore wrote, keeping the lock file.
func clearDataDir(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != LockFile {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// dirEmpty ignores the lock file restore itself holds.
func dirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("restore: read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.Name() != LockFile {
			return false, nil
		}
	}
	return true, nil
}

// copyRestored copies one verified file into data_dir with the modes the
// server gives its own files (0700 directories, 0600 files; on Windows
// they inherit data_dir's admin-only list).
func copyRestored(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return fmt.Errorf("restore: create %s: %w", filepath.Dir(to), err)
	}
	in, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("restore: create %s: %w", to, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("restore: write %s: %w", to, err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return fmt.Errorf("restore: write %s: %w", to, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("restore: write %s: %w", to, err)
	}
	return nil
}

// checkRestored opens the restored database as the server would: it
// migrates an older schema and requires server.key to be the key the
// database belongs to.
func checkRestored(ctx context.Context, cfg *config.Config, res *RestoreResult) error {
	st, err := store.Open(ctx, filepath.Join(cfg.DataDir, DBFile))
	if err != nil {
		return fmt.Errorf("restore: open restored database: %w", err)
	}
	defer func() { _ = st.Close() }()
	if res.SchemaNow, err = st.SchemaVersion(ctx); err != nil {
		return err
	}
	if _, _, err := loadOrCreateServerKey(ctx, filepath.Join(cfg.DataDir, ServerKeyFile), st.Meta()); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	// A config whose overlay.ipv6 differs from the backup's would stop
	// the server at its next start; say so now.
	stored6, err := recordedOverlayIPv6(ctx, st.Meta())
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := sameOverlayIPv6(cfg.Overlay.IPv6, stored6); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if res.Peers, err = st.Peers().Count(ctx); err != nil {
		return err
	}
	if cfg.TLS.Mode != config.TLSModeFile {
		dir := filepath.Join(cfg.DataDir, TLSDir)
		cert, err := tls.LoadX509KeyPair(filepath.Join(dir, TLSCertFile), filepath.Join(dir, TLSKeyFile))
		if err != nil {
			return fmt.Errorf("restore: the backup's TLS certificate: %w", err)
		}
		res.TLSFingerprint = tlsFingerprint(cert)
	}
	return nil
}

// writeIfAbsent copies from to dst when dst does not exist and from
// does; an existing dst is kept.
func writeIfAbsent(from, dst string) (bool, error) {
	if dst == "" || !fileExists(from) {
		return false, nil
	}
	if _, err := os.Lstat(dst); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("restore: %s: %w", dst, err)
	}
	data, err := os.ReadFile(from)
	if err != nil {
		return false, fmt.Errorf("restore: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // /etc/thawr is readable, the files carry no secrets
		return false, fmt.Errorf("restore: create %s: %w", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, data, 0o640); err != nil { //nolint:gosec // config and policy carry no secrets; 0640 as `server install` writes them
		return false, fmt.Errorf("restore: write %s: %w", dst, err)
	}
	return true, nil
}
