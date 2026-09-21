package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

// peerJSON mirrors the admin API's peer view.
type peerJSON struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Mode       string   `json:"mode"`
	Owner      string   `json:"owner"`
	Tags       []string `json:"tags"`
	PublicKey  string   `json:"public_key"`
	IPv4       string   `json:"ipv4"`
	Online     bool     `json:"online"`
	CreatedAt  string   `json:"created_at"`
	LastSeenAt string   `json:"last_seen_at,omitempty"`
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	// Signed is the network-lock state; nil while the lock is off.
	Signed      *bool `json:"signed,omitempty"`
	PathSummary struct {
		Direct int `json:"direct"`
		Relay  int `json:"relay"`
		Other  int `json:"other"`
	} `json:"path_summary"`
}

// peerDetailJSON mirrors the admin API's peer detail.
type peerDetailJSON struct {
	peerJSON
	Paths []struct {
		Peer      string `json:"peer"`
		State     string `json:"state"`
		Endpoint  string `json:"endpoint"`
		UpdatedAt string `json:"updated_at"`
	} `json:"paths"`
	Endpoints []struct {
		Addr string `json:"addr"`
		Kind string `json:"kind"`
	} `json:"endpoints"`
	Symmetric bool `json:"symmetric"`
	Filter    []struct {
		Src    string `json:"src"`
		Proto  string `json:"proto"`
		PortLo uint16 `json:"port_lo"`
		PortHi uint16 `json:"port_hi"`
	} `json:"filter"`
	// Routes are the prefixes the peer advertises (spec 013).
	Routes []routeJSON `json:"routes"`
}

func newAdminPeerCmd(flags *adminFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "peer", Short: "Manage registered peers"}
	var onlineOnly bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List peers with presence, reported paths, version and OS",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var peers []peerJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "GET", "/api/v1/peers", nil, &peers); err != nil {
				return err
			}
			if onlineOnly {
				kept := peers[:0]
				for _, p := range peers {
					if p.Online {
						kept = append(kept, p)
					}
				}
				peers = kept
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), peers)
			}
			now := time.Now()
			rows := make([][]string, 0, len(peers))
			for _, p := range peers {
				rows = append(rows, []string{p.Name, p.IPv4, p.Kind, p.Mode, dash(p.Owner), dash(strings.Join(p.Tags, ",")), onlineWord(p.Online),
					lastSeen(p.LastSeenAt, now), pathSummaryText(p), dash(p.Version), dash(p.OS), signedWord(p.Signed)})
			}
			return table(cmd.OutOrStdout(), []string{"NAME", "IP", "KIND", "MODE", "OWNER", "TAGS", "STATE", "LAST SEEN", "PATHS", "VERSION", "OS", "SIGNED"}, rows)
		},
	}
	list.Flags().BoolVar(&onlineOnly, "online", false, "only peers with a live sync stream")
	show := &cobra.Command{
		Use:   "show <name>",
		Short: "Show everything the server knows about a peer",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			var d peerDetailJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "GET", "/api/v1/peers/"+args[0], nil, &d); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), d)
			}
			return renderPeerDetail(cmd.OutOrStdout(), d, time.Now())
		},
	}
	rename := &cobra.Command{
		Use:   "rename <name> <new-name>",
		Short: "Rename a peer",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var p peerJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "PATCH", "/api/v1/peers/"+args[0], map[string]string{"name": args[1]}, &p); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "peer %s renamed to %s\n", args[0], p.Name)
			return err
		},
	}
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a peer; every client drops it on the next netmap",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := newAdminClient(flags.socket).do(cmd.Context(), "DELETE", "/api/v1/peers/"+args[0], nil, nil); err != nil {
				return err
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "peer %s deleted\n", args[0])
			return err
		},
	}
	cmd.AddCommand(list, show, newAdminAddMobileCmd(flags), rename, del, newAdminPeerRoutesCmd(flags))
	return cmd
}

// mobileJSON mirrors the answer to POST /peers/mobile.
type mobileJSON struct {
	Peer    peerJSON `json:"peer"`
	Config  string   `json:"config"`
	QRSVG   string   `json:"qr_svg,omitempty"`
	Warning string   `json:"warning"`
}

func newAdminAddMobileCmd(flags *adminFlags) *cobra.Command {
	var (
		owner, name, kind, out string
		tags                   []string
		noQR                   bool
	)
	cmd := &cobra.Command{
		Use:   "add-mobile",
		Short: "Create a phone peer and show its WireGuard config as a QR code (shown once)",
		Long: `Registers a static peer whose WireGuard key is generated on the server,
prints the config as a QR code for the official WireGuard app and, with
--out, writes the .conf (mode 0600) instead of printing it. The config is
shown once: the server keeps only the public key. The server decrypts a
phone's traffic (threat model T4).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if owner == "" || name == "" {
				return &exitError{code: exitConfigError, err: fmt.Errorf("--owner and --name are required")}
			}
			var m mobileJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "POST", "/api/v1/peers/mobile", map[string]any{
				"owner": owner, "name": name, "kind": kind, "tags": tags,
			}, &m); err != nil {
				return err
			}
			m.QRSVG = "" // the terminal renders its own
			if flags.json {
				return printJSON(cmd.OutOrStdout(), m)
			}
			return printMobile(cmd.OutOrStdout(), m, out, noQR)
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "user who owns the phone (required)")
	cmd.Flags().StringVar(&name, "name", "", "peer name, a DNS label (required)")
	cmd.Flags().StringVar(&kind, "kind", "human", "human, server or agent")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "tags like tag:phones (comma separated)")
	cmd.Flags().StringVar(&out, "out", "", "write the .conf to this file (mode 0600) instead of printing it")
	cmd.Flags().BoolVar(&noQR, "no-qr", false, "do not print the QR code")
	return cmd
}

// printMobile prints the warning, the QR code and the config, or writes
// the config to out.
func printMobile(w io.Writer, m mobileJSON, out string, noQR bool) error {
	if _, err := fmt.Fprintf(w, "Peer %s (%s) created for %s.\nWarning: %s\n\n", m.Peer.Name, m.Peer.IPv4, m.Peer.Owner, m.Warning); err != nil {
		return err
	}
	if !noQR {
		q, err := qrcode.New(m.Config, qrcode.Medium)
		if err != nil {
			return fmt.Errorf("render qr: %w", err)
		}
		if _, err := io.WriteString(w, q.ToSmallString(false)+"\n"); err != nil {
			return err
		}
	}
	if out != "" {
		if err := os.WriteFile(out, []byte(m.Config), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		_, err := fmt.Fprintf(w, "Config written to %s (mode 0600); delete it once the phone has scanned it.\n", out)
		return err
	}
	_, err := io.WriteString(w, m.Config)
	return err
}

func onlineWord(online bool) string {
	if online {
		return "online"
	}
	return "offline"
}

// lastSeen renders an RFC 3339 timestamp as an age, or "never".
func lastSeen(ts string, now time.Time) string {
	if ts == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return humanDuration(now.Sub(t)) + " ago"
}

// pathSummaryText renders "2 direct, 1 relay" from a peer's summary,
// or "-" when it reported nothing.
func pathSummaryText(p peerJSON) string {
	var parts []string
	if p.PathSummary.Direct > 0 {
		parts = append(parts, fmt.Sprintf("%d direct", p.PathSummary.Direct))
	}
	if p.PathSummary.Relay > 0 {
		parts = append(parts, fmt.Sprintf("%d relay", p.PathSummary.Relay))
	}
	if p.PathSummary.Other > 0 {
		parts = append(parts, fmt.Sprintf("%d other", p.PathSummary.Other))
	}
	return dash(strings.Join(parts, ", "))
}

// renderPeerDetail prints one peer as key: value lines followed by its
// candidates, reported paths and compiled filter.
func renderPeerDetail(w io.Writer, d peerDetailJSON, now time.Time) error {
	nat := "cone or none"
	if d.Symmetric {
		nat = "symmetric"
	}
	lines := [][2]string{
		{"name", d.Name}, {"ip", d.IPv4}, {"kind", d.Kind}, {"mode", d.Mode}, {"owner", dash(d.Owner)},
		{"tags", dash(strings.Join(d.Tags, ","))}, {"state", onlineWord(d.Online)}, {"last seen", lastSeen(d.LastSeenAt, now)},
		{"version", dash(d.Version)}, {"os", dash(d.OS)}, {"key", d.PublicKey}, {"created", d.CreatedAt}, {"nat", nat}, {"signed", signedWord(d.Signed)},
	}
	for _, l := range lines {
		if _, err := fmt.Fprintf(w, "%-10s %s\n", l[0]+":", l[1]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nCandidates (%d):\n", len(d.Endpoints)); err != nil {
		return err
	}
	for _, e := range d.Endpoints {
		if _, err := fmt.Fprintf(w, "  %s (%s)\n", e.Addr, e.Kind); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nPaths reported (%d):\n", len(d.Paths)); err != nil {
		return err
	}
	for _, p := range d.Paths {
		ep := ""
		if p.Endpoint != "" {
			ep = " " + p.Endpoint
		}
		if _, err := fmt.Fprintf(w, "  %s: %s%s (%s)\n", p.Peer, p.State, ep, lastSeen(p.UpdatedAt, now)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nFilter (%d rules, who may reach this peer):\n", len(d.Filter)); err != nil {
		return err
	}
	for _, f := range d.Filter {
		ports := fmt.Sprintf("%d", f.PortLo)
		if f.PortHi != f.PortLo {
			ports = fmt.Sprintf("%d-%d", f.PortLo, f.PortHi)
		}
		if _, err := fmt.Fprintf(w, "  %s -> %s %s\n", f.Src, f.Proto, ports); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nRoutes advertised (%d):\n", len(d.Routes)); err != nil {
		return err
	}
	for _, r := range d.Routes {
		state := "pending approval"
		if r.Approved {
			state = "approved by " + r.ApprovedBy
		}
		if _, err := fmt.Fprintf(w, "  %s (%s)\n", r.Prefix, state); err != nil {
			return err
		}
	}
	return nil
}

// signedWord renders the SIGNED column: yes, no, or "-" while the lock
// is off.
func signedWord(s *bool) string {
	switch {
	case s == nil:
		return "-"
	case *s:
		return "yes"
	default:
		return "no"
	}
}
