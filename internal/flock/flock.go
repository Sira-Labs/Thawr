// Package flock takes an exclusive, non-blocking lock on a file, held
// for as long as the process keeps it: flock on Unix, LockFileEx on
// Windows. The operating system drops it when the process dies, so a
// crash never leaves a stale lock behind.
//
// The lock file is never removed. Unlinking it would let a third
// process create and lock a new file under the same name while the
// first still holds the old one.
package flock

import (
	"errors"
	"fmt"
	"os"
)

// ErrHeld means another process holds the lock.
var ErrHeld = errors.New("held by another process")

// Lock is a held lock; Close releases it.
type Lock struct{ f *os.File }

// TryLock creates path (mode 0600) if needed and locks it, failing
// with an error wrapping ErrHeld when another process has it.
func TryLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("flock: open %s: %w", path, err)
	}
	held, err := tryLock(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock: lock %s: %w", path, err)
	}
	if held {
		_ = f.Close()
		return nil, fmt.Errorf("flock: %s: %w", path, ErrHeld)
	}
	return &Lock{f: f}, nil
}

// Close releases the lock. It is safe to call more than once.
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := errors.Join(unlock(l.f), l.f.Close())
	l.f = nil
	return err
}
