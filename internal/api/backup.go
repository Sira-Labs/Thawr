package api

import (
	"context"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/sira-labs/thawr/internal/control"
)

// BackupSource creates server backups (spec 014).
type BackupSource interface {
	CreateBackup(ctx context.Context, by control.Principal) (BackupFile, error)
}

// BackupFile is a finished archive on disk. Cleanup removes it.
type BackupFile struct {
	Name    string
	Path    string
	Size    int64
	SHA256  string
	Cleanup func()
}

// BackupSHA256Header carries the archive's SHA-256 so the CLI can
// verify what it received.
const BackupSHA256Header = "X-Thawr-Backup-Sha256"

func (h *rest) handleBackup(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	f, err := h.deps.Backup.CreateBackup(r.Context(), p)
	if err != nil {
		h.deps.Logger.Error("backup", "err", err)
		writeError(w, http.StatusInternalServerError, "backup failed; the server log has the cause")
		return
	}
	defer f.Cleanup()
	in, err := os.Open(f.Path)
	if err != nil {
		h.deps.Logger.Error("backup: open archive", "err", err)
		writeError(w, http.StatusInternalServerError, "backup failed")
		return
	}
	defer func() { _ = in.Close() }()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+f.Name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(BackupSHA256Header, f.SHA256)
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, in); err != nil {
		h.deps.Logger.Warn("backup: send", "err", err)
	}
}
