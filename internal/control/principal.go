package control

import "github.com/sira-labs/thawr/internal/store"

// Principal is who is acting: a logged-in user or the local admin socket.
type Principal struct {
	UserID string
	Name   string
	Role   string
	// Local is true for requests over the admin socket, which carry
	// full admin rights without a user record.
	Local bool
}

// LocalAdmin is the principal behind the admin socket.
var LocalAdmin = Principal{Name: "local", Role: store.RoleAdmin, Local: true}

// IsAdmin reports whether the principal has admin rights.
func (p Principal) IsAdmin() bool { return p.Role == store.RoleAdmin }
