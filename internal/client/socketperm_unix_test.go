//go:build !windows

package client

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"testing"
)

// A socket this user may not open is reported as a permission problem,
// not as "nobody is running".
func TestCheckNotRunningPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	sock := shortSocket(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	err = CheckNotRunning(sock)
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("CheckNotRunning on a closed socket = %v, want a permission error", err)
	}
}
