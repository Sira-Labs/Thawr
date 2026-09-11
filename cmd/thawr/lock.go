package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thedatadudech/thawr/internal/client"
)

// newClientLockCmd builds `thawr client lock` (spec 012): the network
// lock is run from a client device, never from the server.
func newClientLockCmd(stateDir, socket *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Network lock: sign peers with a key the server never holds",
		Long: `With the network lock on, every device applies only peers whose record
(id, name, WireGuard key) a signer signed with a lock key kept on a
device you control. A compromised server can then neither add a device
nor swap a key. init turns it on with this device as the first signer,
sign vouches for peers, key prepares another device to become a signer,
add-signer promotes it, disable turns the lock off with a signed
record. Exit codes: 0 done, 2 refused or unknown name, 3 client not
running.`,
	}
	run := func(cmd *cobra.Command, op func(lc *client.LocalClient) (client.LockResult, error), render func(io.Writer, client.LockResult) error) error {
		res, err := op(client.NewLocalClient(*socket))
		var le *client.LocalError
		switch {
		case errors.As(err, &le):
			// Unknown name, not a signer, lock off, refused by the
			// server: all "refused", exit 2.
			return &exitError{code: exitConfigError, err: errors.New(le.Message)}
		case err != nil:
			return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
		}
		return render(cmd.OutOrStdout(), res)
	}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Enable the lock with this device as the first signer and sign every peer it sees",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, func(lc *client.LocalClient) (client.LockResult, error) { return lc.LockInit(cmd.Context()) },
				func(w io.Writer, res client.LockResult) error {
					if _, err := fmt.Fprintf(w, "network lock enabled (generation %d); this device signs with %s\n", res.Generation, res.Signer); err != nil {
						return err
					}
					return renderSigned(w, res.Signed)
				})
		},
	}
	var signAll bool
	sign := &cobra.Command{
		Use:   "sign <name>...",
		Short: "Sign peers held as unsigned (\"hub\" for the server's hub, --all for every unsigned one)",
		Args:  usageArgs(cobra.ArbitraryArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signAll == (len(args) > 0) {
				return &exitError{code: exitConfigError, err: errors.New("name one or more peers, or --all")}
			}
			if signAll {
				args = []string{"all"}
			}
			for _, name := range args {
				err := run(cmd, func(lc *client.LocalClient) (client.LockResult, error) { return lc.LockSign(cmd.Context(), name) },
					func(w io.Writer, res client.LockResult) error {
						if len(res.Signed) == 0 {
							_, err := fmt.Fprintln(w, "nothing to sign")
							return err
						}
						return renderSigned(w, res.Signed)
					})
				if err != nil {
					return err
				}
			}
			return nil
		},
	}
	sign.Flags().BoolVar(&signAll, "all", false, "sign every unsigned peer and the hub")
	key := &cobra.Command{
		Use:   "key",
		Short: "Create this device's lock key so a signer can add it with add-signer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, func(lc *client.LocalClient) (client.LockResult, error) { return lc.LockKey(cmd.Context()) },
				func(w io.Writer, res client.LockResult) error {
					_, err := fmt.Fprintf(w, "lock public key %s (fingerprint %s)\nask a current signer to run: thawr client lock add-signer <this peer's name> %s\n", res.PublicKey, res.Signer, res.Signer)
					return err
				})
		},
	}
	addSigner := &cobra.Command{
		Use:   "add-signer <name> <lock-key-or-fingerprint>",
		Short: "Add a peer that ran `lock key` to the signer set",
		Long: `Adds a peer to the signer set. The second argument is the lock public
key or fingerprint that "thawr client lock key" printed on that device;
it must match what the server reports, so a server cannot slip its own
key into the signer set.`,
		Args: usageArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, func(lc *client.LocalClient) (client.LockResult, error) {
				return lc.LockAddSigner(cmd.Context(), args[0], args[1])
			},
				func(w io.Writer, res client.LockResult) error {
					fp := ""
					if len(res.Signed) > 0 {
						fp = " (" + res.Signed[0].Fingerprint + ")"
					}
					_, err := fmt.Fprintf(w, "added %s as signer%s; record generation %d\n", args[0], fp, res.Generation)
					return err
				})
		},
	}
	disable := &cobra.Command{
		Use:   "disable",
		Short: "Turn the lock off with a signed record; only a signer can turn it on again",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, func(lc *client.LocalClient) (client.LockResult, error) { return lc.LockDisable(cmd.Context()) },
				func(w io.Writer, res client.LockResult) error {
					_, err := fmt.Fprintf(w, "network lock disabled (generation %d); a signer can enable it again with: thawr client lock init\n", res.Generation)
					return err
				})
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the lock record this device pinned, its signers and what is held as unsigned",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := client.NewLocalClient(*socket).Status(cmd.Context())
			if err != nil {
				return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
			}
			return renderLockStatus(cmd.OutOrStdout(), st)
		},
	}
	for _, c := range []*cobra.Command{initCmd, sign, key, addSigner, disable, status} {
		addClientCommonFlags(c, stateDir, socket)
	}
	cmd.AddCommand(initCmd, status, sign, key, addSigner, disable)
	return cmd
}

// renderSigned lists signed entries with the fingerprint to compare
// against `thawr client status` on that device.
func renderSigned(w io.Writer, signed []client.LockSigned) error {
	for _, s := range signed {
		if _, err := fmt.Fprintf(w, "signed %s (%s)\n", s.Name, s.Fingerprint); err != nil {
			return err
		}
	}
	if len(signed) > 0 {
		_, err := fmt.Fprintln(w, "compare each fingerprint with `thawr client status` on that device before relying on it")
		return err
	}
	return nil
}

// renderLockStatus prints the lock part of a status document.
func renderLockStatus(w io.Writer, st client.Status) error {
	l := st.Lock
	if !l.Enabled {
		line := "lock: off"
		if l.Generation > 0 {
			line += fmt.Sprintf(" (disabled at generation %d)", l.Generation)
		}
		if l.HasKey {
			line += " · this device has a lock key"
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
		return rejectedLine(w, l)
	}
	role := "this device does not sign"
	if l.Signer {
		role = "this device is a signer"
	} else if l.HasKey {
		role = "this device has a lock key but is not a signer yet"
	}
	if _, err := fmt.Fprintf(w, "lock: on (generation %d) · %s\n", l.Generation, role); err != nil {
		return err
	}
	for _, s := range l.Signers {
		name := s.Name
		if name == "" {
			name = s.PeerID
		}
		if _, err := fmt.Fprintf(w, "  signer %s (%s)\n", name, s.Fingerprint); err != nil {
			return err
		}
	}
	if !l.SelfSigned {
		if _, err := fmt.Fprintf(w, "this device is unsigned; other devices hold it until a signer runs: thawr client lock sign %s\n", st.Self.Name); err != nil {
			return err
		}
	}
	var unsigned []string
	for _, h := range st.Held {
		if h.Reason == client.HeldUnsigned {
			unsigned = append(unsigned, h.Name)
		}
	}
	if len(unsigned) > 0 {
		if _, err := fmt.Fprintf(w, "unsigned, held: %s (sign with: thawr client lock sign %s)\n", strings.Join(unsigned, " "), strings.Join(unsigned, " ")); err != nil {
			return err
		}
	}
	return rejectedLine(w, l)
}

func rejectedLine(w io.Writer, l client.LockStatus) error {
	if l.Rejected == "" {
		return nil
	}
	_, err := fmt.Fprintf(w, "warning: %s\n", l.Rejected)
	return err
}

// lockJSON mirrors GET /api/v1/lock.
type lockJSON struct {
	Enabled    bool   `json:"enabled"`
	Generation uint64 `json:"generation"`
	Signers    []struct {
		Peer        string `json:"peer"`
		Key         string `json:"key"`
		Fingerprint string `json:"fingerprint"`
	} `json:"signers"`
	Unsigned []string `json:"unsigned"`
}

// newAdminLockCmd builds `thawr admin lock`: the server's view of the
// lock, read-only (the server never signs).
func newAdminLockCmd(flags *adminFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Show the network lock: signers and peers without a signature",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var l lockJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "GET", "/api/v1/lock", nil, &l); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), l)
			}
			w := cmd.OutOrStdout()
			if !l.Enabled {
				line := "lock: off"
				if l.Generation > 0 {
					line += fmt.Sprintf(" (disabled at generation %d)", l.Generation)
				}
				_, err := fmt.Fprintln(w, line)
				return err
			}
			if _, err := fmt.Fprintf(w, "lock: on (generation %d)\n", l.Generation); err != nil {
				return err
			}
			for _, s := range l.Signers {
				if _, err := fmt.Fprintf(w, "  signer %s (%s)\n", s.Peer, s.Fingerprint); err != nil {
					return err
				}
			}
			if len(l.Unsigned) > 0 {
				_, err := fmt.Fprintf(w, "unsigned: %s\n", strings.Join(l.Unsigned, " "))
				return err
			}
			_, err := fmt.Fprintln(w, "every peer is signed")
			return err
		},
	}
}
