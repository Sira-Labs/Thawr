// Package fsperm secures files and directories that hold secrets or are
// written by a privileged service. On Windows it makes Administrators
// the owner and replaces the access list with one for SYSTEM,
// Administrators and the owner only; elsewhere the callers' Unix modes
// already do that and its functions are no-ops.
package fsperm
