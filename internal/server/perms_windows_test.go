package server

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestDataDirAndAdminSocketAdminsOnly: a new data_dir and the admin
// socket in it carry the protected access list, with no entry for
// Users, Authenticated Users or Everyone.
func TestDataDirAndAdminSocketAdminsOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "thawr")
	if _, err := ensureDataDir(dir); err != nil {
		t.Fatalf("ensure data_dir: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	got := sd.String()
	if !strings.HasPrefix(got, "D:P") {
		t.Errorf("data_dir inherits from its parent: %s", got)
	}
	for _, sid := range []string{";;;BU)", ";;;AU)", ";;;WD)"} {
		if strings.Contains(got, sid) {
			t.Errorf("data_dir keeps entry %s: %s", sid, got)
		}
	}
	sock := filepath.Join(dir, "admin.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Skipf("no AF_UNIX here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if err := secureSocket(sock, ln); err != nil {
		t.Fatalf("secure admin socket: %v", err)
	}
}
