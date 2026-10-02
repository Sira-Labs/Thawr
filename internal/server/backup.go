package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sira-labs/thawr/internal/api"
	"github.com/sira-labs/thawr/internal/backup"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

// ACMEDir holds the ACME account key and certificates inside data_dir
// (spec 014); a backup includes it when present.
const ACMEDir = "acme"

// Archive paths of the config and policy copies in a backup.
const (
	BackupConfigPath = "config/server.yaml"
	BackupPolicyPath = "config/policy.yaml"
)

// CreateBackup writes a backup archive of the running server into a
// temporary directory inside data_dir and records backup.create. The
// caller streams BackupFile.Path and must call Cleanup. The archive
// holds server.key and the TLS key, so it is only offered on the admin
// socket.
func (s *Server) CreateBackup(ctx context.Context, by control.Principal) (api.BackupFile, error) {
	now := s.deps.Now().UTC()
	tmp, err := os.MkdirTemp(s.cfg.DataDir, ".backup-")
	if err != nil {
		return api.BackupFile{}, fmt.Errorf("server: backup dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	f, err := s.writeBackup(ctx, tmp, now)
	if err != nil {
		cleanup()
		return api.BackupFile{}, err
	}
	f.Cleanup = cleanup

	peers, err := s.st.Peers().Count(ctx)
	if err != nil {
		cleanup()
		return api.BackupFile{}, err
	}
	if err := s.auditor.Record(ctx, s.st, by, control.AuditBackupCreate, f.Name, map[string]string{
		"sha256": f.SHA256,
		"peers":  strconv.Itoa(peers),
	}); err != nil {
		cleanup()
		return api.BackupFile{}, err
	}
	s.log.Info("backup created", "name", f.Name, "size", f.Size, "sha256", f.SHA256, "by", by.Name)
	return f, nil
}

func (s *Server) writeBackup(ctx context.Context, tmp string, now time.Time) (api.BackupFile, error) {
	db := filepath.Join(tmp, DBFile)
	if err := s.st.BackupTo(ctx, db); err != nil {
		return api.BackupFile{}, err
	}
	schema, err := s.st.SchemaVersion(ctx)
	if err != nil {
		return api.BackupFile{}, err
	}
	keyFP, err := s.st.Meta().Get(ctx, store.MetaServerKeyFingerprint)
	if err != nil {
		return api.BackupFile{}, fmt.Errorf("server: backup: server key fingerprint: %w", err)
	}
	srcs, err := s.backupSources(db)
	if err != nil {
		return api.BackupFile{}, err
	}

	name := "thawr-backup-" + now.Format("20060102T150405Z") + ".tar.gz"
	archive := filepath.Join(tmp, name)
	out, err := os.OpenFile(archive, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return api.BackupFile{}, fmt.Errorf("server: backup: %w", err)
	}
	h := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(out, h)}
	_, err = backup.Write(cw, backup.Manifest{
		ThawrVersion:         s.deps.Version,
		SchemaVersion:        schema,
		Created:              now,
		ServerKeyFingerprint: keyFP,
		TLSMode:              s.cfg.TLS.Mode,
	}, srcs)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return api.BackupFile{}, fmt.Errorf("server: backup: %w", err)
	}
	return api.BackupFile{Name: name, Path: archive, Size: cw.n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// backupSources lists what goes into the archive besides the snapshot:
// the server key, the TLS files and ACME cache that live in data_dir,
// and copies of the config and policy files when readable.
func (s *Server) backupSources(snapshot string) ([]backup.Source, error) {
	dir := s.cfg.DataDir
	srcs := []backup.Source{
		{Path: DBFile, From: snapshot},
		{Path: ServerKeyFile, From: filepath.Join(dir, ServerKeyFile)},
	}
	for _, name := range []string{TLSCertFile, TLSKeyFile} {
		p := filepath.Join(dir, TLSDir, name)
		if fileExists(p) {
			srcs = append(srcs, backup.Source{Path: path.Join(TLSDir, name), From: p})
		}
	}
	acme := filepath.Join(dir, ACMEDir)
	if fileExists(acme) {
		err := filepath.WalkDir(acme, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			srcs = append(srcs, backup.Source{Path: filepath.ToSlash(rel), From: p})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("server: backup: %s: %w", acme, err)
		}
	}
	for _, c := range []struct{ archive, from string }{
		{BackupConfigPath, s.deps.ConfigPath},
		{BackupPolicyPath, s.cfg.PolicyFile},
	} {
		if c.from == "" {
			continue
		}
		if f, err := os.Open(c.from); err == nil {
			_ = f.Close()
			srcs = append(srcs, backup.Source{Path: c.archive, From: c.from})
		} else if !errors.Is(err, fs.ErrNotExist) {
			s.log.Warn("backup: copy skipped", "file", c.from, "err", err)
		}
	}
	return srcs, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
