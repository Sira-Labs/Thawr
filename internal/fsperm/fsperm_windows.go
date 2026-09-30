package fsperm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// adminsOnlySDDL grants SYSTEM, Administrators and the object's owner
// full control, to the object and (as inheritable entries) to
// everything created in it, and blocks inheritance from the parent.
// Under %ProgramData% the parent grants every local user read access
// and more. RestrictToAdmins makes Administrators the owner first, so
// the owner entry adds nobody on an installed client; it keeps a
// non-elevated test run, which owns its own directories, able to clean
// up.
const adminsOnlySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

// RestrictToAdmins secures path for secrets: it refuses a link, makes
// Administrators the owner, then replaces the access list with
// adminsOnlySDDL. The owner goes first because an owner may always
// rewrite the access list: a directory a standard user created before
// the first install would otherwise stay theirs. Files already inside
// take the new inheritable entries unless they carry an explicit list.
func RestrictToAdmins(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fsperm: %w", err)
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("fsperm: %s is a link or junction; refusing to keep secrets behind it", path)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("fsperm: administrators SID: %w", err)
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return restrictSocket(path, admins)
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
		return fmt.Errorf("fsperm: parse access list: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("fsperm: read access list: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("fsperm: restrict %s to administrators: %w", path, err)
	}
	return nil
}

// restrictSocket applies adminsOnlySDDL to an AF_UNIX socket file. The
// file is a reparse point that the path-based calls cannot open, so it
// is opened itself (FILE_FLAG_OPEN_REPARSE_POINT, which also never
// follows a link) and secured through the handle. The socket was just
// created by this process, so its owner is already this process's
// default owner; Administrators become the owner where the token
// allows it.
func restrictSocket(path string, admins *windows.SID) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("fsperm: %s: %w", path, err)
	}
	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("fsperm: open socket %s: %w", path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	sd, err := windows.SecurityDescriptorFromString(adminsOnlySDDL)
	if err != nil {
		return fmt.Errorf("fsperm: parse access list: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("fsperm: read access list: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, admins, nil, dacl, nil)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// Not an administrator: keep this process as the owner.
		err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	if err != nil {
		return fmt.Errorf("fsperm: restrict socket %s to administrators: %w", path, err)
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
		return fmt.Errorf("fsperm: make administrators the owner of %s: %w", path, err)
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
		return fmt.Errorf("fsperm: read owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("fsperm: read owner of %s: %w", path, err)
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.Equals(admins) {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("fsperm: read process user: %w", err)
	}
	if owner.Equals(user.User.Sid) {
		return nil
	}
	return fmt.Errorf("fsperm: %s is owned by %s, not by SYSTEM, Administrators or this user; remove it or run as administrator", path, owner.String())
}

// enablePrivilege turns on a privilege the process token holds but has
// disabled.
func enablePrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("fsperm: open process token: %w", err)
	}
	defer func() { _ = token.Close() }()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return fmt.Errorf("fsperm: look up %s: %w", name, err)
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	if err := windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("fsperm: enable %s: %w", name, err)
	}
	return nil
}

// OpenLog opens path, which must lie inside root, for appending as a
// privileged service. root and every directory between it and path are
// created if missing and secured with RestrictToAdmins, which refuses a
// link or junction; only then is the file opened, so a standard user
// who created root before the first install cannot redirect the
// service's writes elsewhere. A file that turns out to be a link or to
// have a second name is refused. Reading the log takes an elevated
// shell, as the whole of root does.
func OpenLog(root, path string) (*os.File, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("fsperm: log %s is not inside %s", path, root)
	}
	dir := root
	for _, elem := range append([]string{""}, strings.Split(filepath.Dir(rel), string(filepath.Separator))...) {
		if elem == "." {
			continue
		}
		dir = filepath.Join(dir, elem)
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("fsperm: create %s: %w", dir, err)
		}
		if err := RestrictToAdmins(dir); err != nil {
			return nil, err
		}
	}
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("fsperm: log %s is not a plain file", path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fsperm: open log: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fsperm: inspect log %s: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("fsperm: log %s is a link or has another name", path)
	}
	if err := RestrictToAdmins(path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
