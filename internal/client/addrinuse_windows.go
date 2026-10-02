package client

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// tryLock takes an exclusive byte-range lock without waiting; held
// reports that another process has it.
func tryLock(f *os.File) (held bool, err error) {
	ov := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ov)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return true, nil
	}
	return false, err
}

func unlock(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// addrInUse reports a bind refused because the port is taken.
func addrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, windows.WSAEADDRINUSE)
}
