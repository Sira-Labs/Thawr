package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sira-labs/thawr/internal/wg"
)

// File names inside the state directory.
const (
	StateFile = "state.json"
	KeyFile   = "node.key"
)

// EnvStateDir overrides the state directory.
const EnvStateDir = "THAWR_STATE_DIR"

// Errors of the state directory.
var (
	ErrNotEnrolled     = errors.New("client: not enrolled")
	ErrAlreadyEnrolled = errors.New("client: already enrolled")
)

// State is what the client persists after enrollment. NodeSecret is the
// bearer credential for the control channel and must stay in a 0600 file.
type State struct {
	Server       string    `json:"server"`
	Fingerprint  string    `json:"fingerprint"`
	PeerID       string    `json:"peer_id"`
	Name         string    `json:"name"`
	IPv4         string    `json:"ipv4"`
	OverlayCIDR  string    `json:"overlay_cidr"`
	NodeSecret   string    `json:"node_secret"`
	HubPublicKey string    `json:"hub_public_key"`
	HubEndpoint  string    `json:"hub_endpoint"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	// ListenPort is kept across restarts so endpoint candidates stay
	// stable; it changes only when another process holds it at start.
	ListenPort int `json:"listen_port,omitempty"`
	// LockSigner is the full lock public key given at enrolment that
	// must have signed the first lock record this device pins; empty
	// accepts whatever record the server offers first (spec 012).
	LockSigner string `json:"lock_signer,omitempty"`
	// AdvertiseRoutes are the prefixes this device offers to carry as a
	// subnet router or exit node (0.0.0.0/0), reported to the server at
	// every connect; ExitNodeID is the peer whose exit node this
	// device uses, empty for none, and ExitNode its last known name
	// (spec 013). The id keeps the choice on that peer across a rename;
	// state from before ids names the peer only and is resolved once.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
	ExitNode        string   `json:"exit_node,omitempty"`
	ExitNodeID      string   `json:"exit_node_id,omitempty"`
}

// adoptSelfName takes this device's name from nm, where the server
// reports it after an admin renamed the peer. It returns the previous
// name (empty when state had none) and whether st changed. The name
// serves DNS, status and the lock records this device signs, which the
// server checks against the current name.
func adoptSelfName(st *State, nm NetMap) (string, bool) {
	if nm.SelfName == "" || nm.SelfName == st.Name || (nm.SelfID != "" && nm.SelfID != st.PeerID) {
		return "", false
	}
	old := st.Name
	st.Name = nm.SelfName
	return old, true
}

// followExitNode keeps st's exit-node choice on the same peer: it
// resolves a choice stored by name only and takes up a rename. It
// reports whether st changed.
func followExitNode(st *State, peers []Peer) bool {
	for _, p := range peers {
		switch {
		case st.ExitNodeID != "" && p.ID == st.ExitNodeID:
			if p.Name == st.ExitNode {
				return false
			}
			st.ExitNode = p.Name
			return true
		case st.ExitNodeID == "" && st.ExitNode != "" && p.Name == st.ExitNode && p.ExitNode:
			st.ExitNodeID = p.ID
			return true
		}
	}
	return false
}

// DefaultDir returns the platform's state directory unless THAWR_STATE_DIR
// is set.
func DefaultDir() string {
	if d := os.Getenv(EnvStateDir); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Thawr"
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Thawr")
	default:
		return "/var/lib/thawr/client"
	}
}

// LoadState reads state.json or returns ErrNotEnrolled.
func LoadState(dir string) (State, error) {
	data, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return State{}, ErrNotEnrolled
	}
	if err != nil {
		return State{}, fmt.Errorf("client: read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, fmt.Errorf("client: parse %s: %w", StateFile, err)
	}
	if st.Server == "" || st.PeerID == "" || st.NodeSecret == "" {
		return State{}, fmt.Errorf("client: %s is incomplete", StateFile)
	}
	return st, nil
}

// SaveState writes state.json with mode 0600, creating dir (0700).
func SaveState(dir string, st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("client: encode state: %w", err)
	}
	return writeSecret(dir, StateFile, append(data, '\n'))
}

// LoadKey reads the node's WireGuard private key.
func LoadKey(dir string) (wg.Key, error) {
	data, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return wg.Key{}, ErrNotEnrolled
	}
	if err != nil {
		return wg.Key{}, fmt.Errorf("client: read key: %w", err)
	}
	return wg.ParseKey(strings.TrimSpace(string(data)))
}

// SaveKey writes node.key with mode 0600.
func SaveKey(dir string, key wg.Key) error {
	return writeSecret(dir, KeyFile, []byte(key.String()+"\n"))
}

// Forget removes the state, the node key and the lock key so the device
// can enrol again; pins.json stays.
func Forget(dir string) error {
	var errs []error
	for _, name := range []string{StateFile, KeyFile, LockKeyFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("client: remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func writeSecret(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("client: create %s: %w", dir, err)
	}
	// Every write re-applies the access list, so a state directory from
	// before it existed is fixed on the first save.
	if err := restrictToAdmins(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("client: write %s: %w", name, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("client: rename %s: %w", name, err)
	}
	return nil
}
