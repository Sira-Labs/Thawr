package server

import (
	"net"
	"os"

	"github.com/sira-labs/thawr/internal/fsperm"
)

// secureDataDir makes Administrators the owner of data_dir and limits
// it to SYSTEM, Administrators and the owner. It holds the server's
// keys and database; left alone it inherits the drive's access list,
// which on C:\ lets every local user create and read files, and a
// directory a standard user created before the first start would stay
// theirs.
func secureDataDir(dir string, _ os.FileInfo) error {
	return fsperm.RestrictToAdmins(dir)
}

// checkSecretFileMode is a no-op on Windows, which has no Unix mode bits;
// secret files inherit data_dir's access list.
func checkSecretFileMode(string) error { return nil }

// secureSocket limits the admin socket, which grants full admin without
// a login, to SYSTEM, Administrators and the owner; it may sit outside
// data_dir when admin_socket says so.
func secureSocket(path string, _ net.Listener) error {
	return fsperm.RestrictToAdmins(path)
}
