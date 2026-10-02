package client

import (
	"errors"
	"fmt"
	"os"

	"github.com/sira-labs/thawr/internal/flock"
)

// instanceLock is a lock file next to the local socket, held for the
// daemon's lifetime. Dialing the socket tells whether a daemon already
// serves it, but two clients starting together both see nobody there;
// the lock is what makes exactly one of them the instance.
type instanceLock struct{ l *flock.Lock }

// lockInstance takes the lock for socket or fails with
// ErrAlreadyRunning when another process holds it.
func lockInstance(socket string) (*instanceLock, error) {
	if err := os.MkdirAll(dirOf(socket), 0o755); err != nil { //nolint:gosec // the socket dir is not secret
		return nil, fmt.Errorf("client: socket dir: %w", err)
	}
	path := socket + ".lock"
	l, err := flock.TryLock(path)
	if errors.Is(err, flock.ErrHeld) {
		return nil, fmt.Errorf("%w (lock %s)", ErrAlreadyRunning, path)
	}
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}
	return &instanceLock{l: l}, nil
}

// Close releases the lock.
func (l *instanceLock) Close() error {
	if l == nil {
		return nil
	}
	return l.l.Close()
}
