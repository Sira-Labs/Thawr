//go:build !windows

package fsperm

// RestrictToAdmins is a no-op outside Windows: callers create secret
// directories 0700 and files 0600, which already admit only root.
func RestrictToAdmins(string) error { return nil }
