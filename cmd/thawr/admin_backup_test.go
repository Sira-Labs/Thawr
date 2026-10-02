package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/sira-labs/thawr/internal/api"
)

// backupSocket serves body as the backup, announcing sum as its SHA-256.
func backupSocket(t *testing.T, body, sum string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/backup", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="../../thawr-backup-20261002T040000Z.tar.gz"`)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set(api.BackupSHA256Header, sum)
		_, _ = w.Write([]byte(body))
	})
	return fakeDaemonSocket(t, mux)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestAdminBackupWritesFile(t *testing.T) {
	sock := backupSocket(t, "archive bytes", sha("archive bytes"))
	dst := filepath.Join(t.TempDir(), "b.tar.gz")
	out, code, err := runCLI(t, "admin", "backup", "--out", dst, "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d: %v\n%s", code, err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "archive bytes" {
		t.Fatalf("file %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if !strings.Contains(out, "backup written to "+dst) || !strings.Contains(out, sha("archive bytes")) {
		t.Errorf("output %q", out)
	}
}

func TestAdminBackupStdout(t *testing.T) {
	sock := backupSocket(t, "archive bytes", sha("archive bytes"))
	out, code, err := runCLI(t, "admin", "backup", "--out", "-", "--socket", sock)
	if code != 0 || out != "archive bytes" {
		t.Fatalf("exit %d %v, out %q", code, err, out)
	}
}

// TestAdminBackupDefaultNameStaysLocal: the server's suggested name is
// reduced to a base name in the current directory.
func TestAdminBackupDefaultNameStaysLocal(t *testing.T) {
	sock := backupSocket(t, "x", sha("x"))
	dir := t.TempDir()
	t.Chdir(dir)
	if _, code, err := runCLI(t, "admin", "backup", "--socket", sock); code != 0 {
		t.Fatalf("exit %d: %v", code, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "thawr-backup-20261002T040000Z.tar.gz")); err != nil {
		t.Errorf("default file not in the current directory: %v", err)
	}
}

func TestAdminBackupChecksumMismatchLeavesNothing(t *testing.T) {
	sock := backupSocket(t, "archive bytes", sha("something else"))
	dir := t.TempDir()
	dst := filepath.Join(dir, "b.tar.gz")
	if _, code, err := runCLI(t, "admin", "backup", "--out", dst, "--socket", sock); code == 0 || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("exit %d, err %v", code, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files left behind: %v", entries)
	}
}
