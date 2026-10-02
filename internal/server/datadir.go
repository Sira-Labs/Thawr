package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sira-labs/thawr/internal/flock"
)

// ensureDataDir creates dir with mode 0700 or verifies an existing one
// is not group- or world-writable; on Windows it secures dir either way
// (see secureDataDir).
func ensureDataDir(dir string) (created bool, err error) {
	fi, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, fmt.Errorf("server: create data_dir %s: %w", dir, err)
		}
		if fi, err = os.Stat(dir); err != nil {
			return false, fmt.Errorf("server: stat data_dir %s: %w", dir, err)
		}
		created = true
	case err != nil:
		return false, fmt.Errorf("server: stat data_dir %s: %w", dir, err)
	case !fi.IsDir():
		return false, fmt.Errorf("server: data_dir %s is not a directory", dir)
	}
	if err := secureDataDir(dir, fi); err != nil {
		return false, err
	}
	return created, nil
}

// writeSecretFile writes data to path with mode 0600, replacing any
// existing file atomically. The temporary file is always new and
// uniquely named, so one left over or planted cannot pass its owner and
// access list on through the rename.
func writeSecretFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("server: create temporary for %s: %w", path, err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("server: write %s: %w", path, werr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("server: rename %s: %w", path, err)
	}
	return nil
}

// LockDataDir takes the data_dir lock (LockFile) or fails with an error
// wrapping ErrDataDirInUse when another server or a restore holds it.
func LockDataDir(dir string) (*flock.Lock, error) {
	l, err := flock.TryLock(filepath.Join(dir, LockFile))
	if errors.Is(err, flock.ErrHeld) {
		return nil, fmt.Errorf("server: another thawr server is using %s: %w", dir, ErrDataDirInUse)
	}
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	return l, nil
}
