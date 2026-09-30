//go:build !windows

package main

// redirectServiceOutput is a no-op outside Windows: systemd and launchd
// capture a service's output themselves.
func redirectServiceOutput([]string) error { return nil }
