//go:build !windows

package server

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
)

// adminGroup is the Unix group granted access to the admin socket when
// it exists on the host.
const adminGroup = "thawr"

// secureDataDir refuses a data_dir group or others may write to.
func secureDataDir(dir string, fi os.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("server: data_dir %s is group- or world-writable (%o); fix with chmod 700", dir, fi.Mode().Perm())
	}
	return nil
}

// checkSecretFileMode refuses a secret file readable by group or others.
func checkSecretFileMode(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("server: stat %s: %w", path, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("server: %s must be mode 0600, is %o", path, fi.Mode().Perm())
	}
	return nil
}

// secureSocket sets the admin socket to 0660 and, when the thawr group
// exists, hands group ownership to it.
func secureSocket(path string, _ net.Listener) error {
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group access to the admin socket is the spec
		return fmt.Errorf("server: chmod admin socket: %w", err)
	}
	g, err := user.LookupGroup(adminGroup)
	if err != nil {
		return nil // no such group: owner-only access
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("server: chown admin socket to group %s: %w", adminGroup, err)
	}
	return nil
}
