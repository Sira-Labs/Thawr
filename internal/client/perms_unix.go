//go:build !windows

package client

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// socketGroup is the Unix group granted access to the client socket
// when it exists on the host.
const socketGroup = "thawr"

// secureSocket sets the socket to 0660 and, when the thawr group
// exists, hands group ownership to it.
func secureSocket(path string) error {
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // group access is intended
		return fmt.Errorf("client: chmod socket: %w", err)
	}
	g, err := user.LookupGroup(socketGroup)
	if err != nil {
		return nil // no such group: owner-only access
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("client: chown socket to group %s: %w", socketGroup, err)
	}
	return nil
}

// restrictToAdmins is a no-op outside Windows: the state directory is
// created 0700 and each secret file 0600.
func restrictToAdmins(string) error { return nil }
