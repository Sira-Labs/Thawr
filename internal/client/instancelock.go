package client

import (
	"errors"
	"fmt"
	"os"
)

// instanceLock is a lock file next to the local socket, held for the
// daemon's lifetime. Dialing the socket tells whether a daemon already
// serves it, but two clients starting together both see nobody there;
// the lock is what makes exactly one of them the instance. The file is
// never removed: unlinking a lock file is how a third process ends up
// holding a different file under the same name.
type instanceLock struct{ f *os.File }

// lockInstance takes the lock for socket or fails with
// ErrAlreadyRunning when another process holds it.
func lockInstance(socket string) (*instanceLock, error) {
	if err := os.MkdirAll(dirOf(socket), 0o755); err != nil { //nolint:gosec // the socket dir is not secret
		return nil, fmt.Errorf("client: socket dir: %w", err)
	}
	path := socket + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("client: open %s: %w", path, err)
	}
	held, err := tryLock(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("client: lock %s: %w", path, err)
	}
	if held {
		_ = f.Close()
		return nil, fmt.Errorf("%w (lock %s)", ErrAlreadyRunning, path)
	}
	return &instanceLock{f: f}, nil
}

// Close releases the lock.
func (l *instanceLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := errors.Join(unlock(l.f), l.f.Close())
	l.f = nil
	return err
}
