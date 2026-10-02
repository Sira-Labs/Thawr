//go:build !windows

package client

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// tryLock takes an exclusive flock without waiting; held reports that
// another process has it.
func tryLock(f *os.File) (held bool, err error) {
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

func unlock(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }

// addrInUse reports a bind refused because the port is taken.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
