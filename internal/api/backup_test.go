package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/sira-labs/thawr/internal/control"
)

type fakeBackup struct {
	t       *testing.T
	path    string
	by      control.Principal
	cleaned bool
}

func (f *fakeBackup) CreateBackup(_ context.Context, by control.Principal) (BackupFile, error) {
	f.by = by
	f.path = filepath.Join(f.t.TempDir(), "b.tar.gz")
	if err := os.WriteFile(f.path, []byte("archive"), 0o600); err != nil {
		return BackupFile{}, err
	}
	return BackupFile{Name: "thawr-backup-x.tar.gz", Path: f.path, Size: 7, SHA256: "abc", Cleanup: func() { f.cleaned = true }}, nil
}

// TestBackupRouteSocketOnly: the archive carries the server's private
// keys, so the HTTPS handler never serves it, not even to an admin.
func TestBackupRouteSocketOnly(t *testing.T) {
	fb := &fakeBackup{t: t}
	env := newRESTEnv(t, func(d *RESTDeps, _ *restEnv) { d.Backup = fb })

	_, admin := env.login("markus", "adminpassword")
	if rec := env.do(env.handler, admin, http.MethodGet, "/api/v1/backup", nil, false); rec.Code != http.StatusNotFound {
		t.Fatalf("HTTPS with an admin session: %d, want 404", rec.Code)
	}
	if fb.path != "" {
		t.Fatal("HTTPS request created a backup")
	}

	rec := env.do(env.local, session{}, http.MethodGet, "/api/v1/backup", nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin socket: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "archive" || rec.Header().Get(BackupSHA256Header) != "abc" ||
		rec.Header().Get("Content-Type") != "application/gzip" || rec.Header().Get("Content-Length") != "7" {
		t.Errorf("response: headers %v body %q", rec.Header(), rec.Body.String())
	}
	if !fb.cleaned {
		t.Error("archive not cleaned up after sending")
	}
	if !fb.by.Local {
		t.Errorf("principal %+v, want the local admin", fb.by)
	}
}
