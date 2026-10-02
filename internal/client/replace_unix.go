//go:build !windows

package client

import "os"

// replaceFile renames tmp over path; a rename is atomic on Unix.
func replaceFile(tmp, path string) error { return os.Rename(tmp, path) }
