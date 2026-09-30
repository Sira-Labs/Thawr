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

// TestStateDirOwner: the state directory ends up owned by
// Administrators when the test runs elevated (CI), else by this user.
func TestStateDirOwner(t *testing.T) {
	dir := t.TempDir()
	if err := restrictToAdmins(dir); err != nil {
		t.Fatalf("restrict: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Errorf("elevated: owner %s, want Administrators", owner)
		}
		return
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Errorf("not elevated: owner %s, want this user", owner)
	}
}

// TestPlantedTempFileNotReused: a state.json.tmp that allows everyone
// is replaced, not written into, so state.json does not inherit its
// access list.
func TestPlantedTempFileNotReused(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, StateFile+".tmp")
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	open, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, open, nil); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(dir, State{Server: "https://s", Name: "box", IPv4: "100.64.0.9", PeerID: "p", NodeSecret: "thawr_ns_test"}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if got := dacl(t, filepath.Join(dir, StateFile)); strings.Contains(got, ";;;WD)") {
		t.Errorf("state.json kept the planted access list: %s", got)
	}
}

// TestLinkedStateDirRefused: a state directory that is a link is not
// used for secrets.
func TestLinkedStateDirRefused(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "Thawr")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if err := restrictToAdmins(link); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("restrict a link = %v, want a refusal", err)
	}
}

func TestDefaultSocketInStateDir(t *testing.T) {
	t.Setenv(EnvStateDir, `C:\ProgramData\Thawr`)
	if got := DefaultSocket(); got != `C:\ProgramData\Thawr\client.sock` {
		t.Errorf("DefaultSocket() = %q", got)
	}
}
