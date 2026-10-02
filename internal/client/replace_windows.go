package client

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// replaceTimeout bounds how long replaceFile retries a refused rename.
const replaceTimeout = 2 * time.Second

// replaceFile renames tmp over path. Windows refuses to replace a file
// another process holds open without FILE_SHARE_DELETE (a virus scanner
// or the search indexer reading the previous state.json, usually for a
// few milliseconds) with ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION,
// so the rename is retried for up to replaceTimeout, as Go's own
// toolchain does (cmd/go/internal/robustio). Any other error, or one
// that outlasts the timeout, is returned.
func replaceFile(tmp, path string) error {
	deadline := time.Now().Add(replaceTimeout)
	delay := time.Millisecond
	for {
		err := os.Rename(tmp, path)
		if err == nil || !replaceRefused(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		delay = min(2*delay, 100*time.Millisecond)
	}
}

func replaceRefused(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
