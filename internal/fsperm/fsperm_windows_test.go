package fsperm

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestOpenLogSecuresPath: the root and log directory end up with the
// protected access list and the file is opened for appending.
func TestOpenLogSecuresPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Thawr")
	path := filepath.Join(root, "logs", "thawr-client.log")
	f, err := OpenLog(root, path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	if _, err := f.WriteString("line\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	for _, p := range []string{root, filepath.Dir(path)} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if got := sd.String(); !strings.HasPrefix(got, "D:P") || strings.Contains(got, ";;;BU)") || strings.Contains(got, ";;;WD)") {
			t.Errorf("%s: access list %s", p, got)
		}
	}
}

// TestOpenLogRefusesLinks: a logs directory or log file planted as a
// link is not followed.
func TestOpenLogRefusesLinks(t *testing.T) {
	elsewhere := t.TempDir()
	root := filepath.Join(t.TempDir(), "Thawr")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(root, "logs")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if _, err := OpenLog(root, filepath.Join(root, "logs", "thawr-client.log")); err == nil {
		t.Error("followed a linked logs directory")
	}

	root2 := filepath.Join(t.TempDir(), "Thawr")
	if err := os.MkdirAll(filepath.Join(root2, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(elsewhere, "victim.txt")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root2, "logs", "thawr-client.log")
	if err := os.Symlink(target, log); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLog(root2, log); err == nil {
		t.Error("followed a linked log file")
	}
	hard := filepath.Join(root2, "logs", "thawr-server.log")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLog(root2, hard); err == nil {
		t.Error("appended to a file with a second name")
	}
}

func TestOpenLogOutsideRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := OpenLog(root, filepath.Join(t.TempDir(), "x.log")); err == nil {
		t.Error("opened a log outside its root")
	}
}

// TestRestrictSocket: a listening AF_UNIX socket file, a reparse point
// the path-based calls cannot open, is secured through its handle.
func TestRestrictSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "c.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Skipf("no AF_UNIX here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	if err := RestrictToAdmins(sock); err != nil {
		t.Fatalf("restrict socket: %v", err)
	}
}
