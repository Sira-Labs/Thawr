package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// dacl returns path's access list in SDDL form.
func dacl(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read access list of %s: %v", path, err)
	}
	return sd.String()
}

// TestStateDirAdminsOnly: saving state restricts the state directory,
// and the key already in it, to SYSTEM, Administrators and the owner;
// no entry for Everyone, Users or Authenticated Users survives.
func TestStateDirAdminsOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Thawr")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, KeyFile)
	if err := os.WriteFile(key, []byte("not a real key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, State{Server: "https://s", Name: "box", IPv4: "100.64.0.9", PeerID: "p", NodeSecret: "thawr_ns_test"}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if got := dacl(t, dir); !strings.HasPrefix(got, "D:P") {
		t.Errorf("state directory inherits from its parent: %s", got)
	}
	for _, p := range []string{dir, key, filepath.Join(dir, StateFile)} {
		got := dacl(t, p)
		for _, sid := range []string{";;;SY)", ";;;BA)"} {
			if !strings.Contains(got, sid) {
				t.Errorf("%s: no entry %s in %s", p, sid, got)
			}
		}
		for _, sid := range []string{";;;WD)", ";;;BU)", ";;;AU)"} {
			if strings.Contains(got, sid) {
				t.Errorf("%s: entry %s left in %s", p, sid, got)
			}
		}
	}
}

func TestDefaultSocketInStateDir(t *testing.T) {
	t.Setenv(EnvStateDir, `C:\ProgramData\Thawr`)
	if got := DefaultSocket(); got != `C:\ProgramData\Thawr\client.sock` {
		t.Errorf("DefaultSocket() = %q", got)
	}
}
