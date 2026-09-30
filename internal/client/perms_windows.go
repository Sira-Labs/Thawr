package client

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// adminsOnlySDDL grants SYSTEM, Administrators and the object's owner
// full control, to the object and (as inheritable entries) to
// everything created in it, and blocks inheritance from the parent.
// Under %ProgramData% the parent grants every local user read access
// and more. restrictToAdmins makes Administrators the owner first, so
// the owner entry adds nobody on an installed client; it keeps a
// non-elevated test run, which owns its own directories, able to clean
// up.
const adminsOnlySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// restrictToAdmins secures path for secrets: it refuses a link, makes
// Administrators the owner, then replaces the access list with
// adminsOnlySDDL. The owner goes first because an owner may always
// rewrite the access list: a directory a standard user created before
// the first install would otherwise stay theirs. Files already inside
// take the new inheritable entries unless they carry an explicit list.
func restrictToAdmins(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("client: %s is a link or junction; refusing to keep secrets behind it", path)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("client: administrators SID: %w", err)
	}
	// Setting the list walks every file in a directory; a list already
	// in place is left alone, so only the first save pays for it.
	if alreadyRestricted(path, admins) {
		return nil
	}
	if err := secureOwner(path, admins); err != nil {
		return err
	}
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

// secureOwner makes Administrators the owner of path. An elevated
// process may do so; where the current owner shut Administrators out,
// the take-ownership privilege every administrator holds is enabled
// first. A process that is not an administrator cannot, and then
// accepts path only if SYSTEM, Administrators or the process's own user
// already owns it.
func secureOwner(path string, admins *windows.SID) error {
	setOwner := func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
	}
	err := setOwner()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && enablePrivilege("SeTakeOwnershipPrivilege") == nil {
		err = setOwner()
	}
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		return requireTrustedOwner(path, admins)
	}
	if err != nil {
		return fmt.Errorf("client: make administrators the owner of %s: %w", path, err)
	}
	return nil
}

// alreadyRestricted reports whether path is owned by Administrators and
// carries exactly adminsOnlySDDL. Any doubt answers false, so the list
// is set again.
func alreadyRestricted(path string, admins *windows.SID) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(admins) {
		return false
	}
	return strings.TrimPrefix(sd.String(), "O:BA") == adminsOnlySDDL
}

// requireTrustedOwner accepts path when SYSTEM, Administrators or the
// process's own user owns it.
func requireTrustedOwner(path string, admins *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("client: read owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("client: read owner of %s: %w", path, err)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.Equals(admins) {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("client: read process user: %w", err)
	}
	if owner.Equals(user.User.Sid) {
		return nil
	}
	return fmt.Errorf("client: %s is owned by %s, not by SYSTEM, Administrators or this user; remove it or run as administrator", path, owner.String())
}

// enablePrivilege turns on a privilege the process token holds but has
// disabled.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("client: open process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return fmt.Errorf("client: look up %s: %w", name, err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("client: enable %s: %w", name, err)
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
