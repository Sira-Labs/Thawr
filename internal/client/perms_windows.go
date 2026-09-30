package client

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// adminsOnlySDDL grants SYSTEM, Administrators and the object's owner
// full control, to the object and (as inheritable entries) to
// everything created in it, and blocks inheritance from the parent.
// Under %ProgramData% the parent grants every local user read access
// and more. The owner entry adds nobody new (an owner may always
// rewrite the list); it keeps a non-elevated test run able to clean up.
const adminsOnlySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// restrictToAdmins replaces path's access list with adminsOnlySDDL.
// Files already inside a directory take the new inheritable entries,
// unless they carry an explicit access list of their own.
func restrictToAdmins(path string) error {
	sd, err := windows.SecurityDescriptorFromString(adminsOnlySDDL)
	if err != nil {
		return fmt.Errorf("client: parse access list: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("client: read access list: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("client: restrict %s to administrators: %w", path, err)
	}
	return nil
}

// secureSocket limits the socket to SYSTEM and Administrators: an
// AF_UNIX connect needs write access to the socket file, and whatever
// the directory grants would otherwise let any local user stop the
// client or rotate its key. Windows has no thawr group to hand it to.
func secureSocket(path string) error {
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group access is intended
		return fmt.Errorf("client: chmod socket: %w", err)
	}
	return restrictToAdmins(path)
}
