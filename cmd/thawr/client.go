package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/thedatadudech/thawr/internal/client"
	"github.com/thedatadudech/thawr/internal/config"
	"github.com/thedatadudech/thawr/internal/lock"
	"github.com/thedatadudech/thawr/internal/server"
)

// envClientSocket overrides the client's local control socket.
const envClientSocket = "THAWR_CLIENT_SOCKET"

func defaultClientSocket() string {
	if s := os.Getenv(envClientSocket); s != "" {
		return s
	}
	return client.DefaultSocket
}

// clientUpFlags are shared by `client up` and `client install`.
type clientUpFlags struct {
	serverURL, token, fingerprint, name, iface, logLevel, dnsMode, lockSigner string
	acceptFingerprint                                                         bool
}

func addClientUpFlags(cmd *cobra.Command, f *clientUpFlags) {
	cmd.Flags().StringVar(&f.serverURL, "server", "", "server URL for enrollment, e.g. https://vpn.example.com")
	cmd.Flags().StringVar(&f.token, "token", "", "one-time enrollment token")
	cmd.Flags().StringVar(&f.fingerprint, "fingerprint", "", "server TLS fingerprint (sha256:...) from the join command")
	cmd.Flags().BoolVar(&f.acceptFingerprint, "accept-fingerprint", false, "trust whatever certificate the server presents now (prints it)")
	cmd.Flags().StringVar(&f.name, "name", "", "peer name to request instead of the hostname")
	cmd.Flags().StringVar(&f.lockSigner, "lock-signer", "", "full lock public key (from `thawr client lock status` on a signer) that must have signed the first lock record; nothing is applied until it arrives (spec 012)")
	cmd.Flags().StringVar(&f.iface, "interface", config.DefaultInterface(), "WireGuard interface name")
	cmd.Flags().StringVar(&f.logLevel, "log-level", "info", "debug, info, warn or error")
	cmd.Flags().StringVar(&f.dnsMode, "dns", client.DNSOn, "<name>.thawr resolver: on (serve and register with the OS), serve (resolver only) or off")
}

// validateDNSMode turns a bad --dns value into a usage error.
func validateDNSMode(mode string) error {
	if !client.ValidDNSMode(mode) {
		return &exitError{code: exitConfigError, err: fmt.Errorf("--dns must be on, serve or off, not %q", mode)}
	}
	return nil
}

// enrollIfNeeded enrols the device when stateDir holds no enrollment,
// using --server and --token; an enrolled device ignores a token.
func enrollIfNeeded(ctx context.Context, deps cliDeps, logger *slog.Logger, f clientUpFlags, stateDir string) error {
	st, err := client.LoadState(stateDir)
	switch {
	case errors.Is(err, client.ErrNotEnrolled):
		if f.serverURL == "" || f.token == "" {
			return &exitError{code: exitConfigError, err: errors.New("not enrolled: --server and --token are required")}
		}
		st, err := deps.enroll(ctx, client.Options{
			Server: f.serverURL, Token: f.token, Fingerprint: f.fingerprint, AcceptFingerprint: f.acceptFingerprint,
			Name: f.name, StateDir: stateDir, Version: version, LockSigner: f.lockSigner,
		})
		if err != nil {
			var fpErr *client.FingerprintError
			if errors.As(err, &fpErr) {
				return &exitError{code: exitConfigError, err: err}
			}
			return err
		}
		logger.Info("enrolled", "name", st.Name, "ipv4", st.IPv4, "server", st.Server)
		return nil
	case err != nil:
		return err
	case f.token != "":
		logger.Warn("already enrolled; ignoring --token")
	}
	return applyLockSigner(stateDir, st, f.lockSigner)
}

// applyLockSigner honours --lock-signer on an already enrolled device:
// the persisted value may be repeated, an empty one may be set while
// no lock record is pinned yet, anything else is refused rather than
// silently ignored, so the person never believes a constraint is in
// force that is not.
func applyLockSigner(stateDir string, st client.State, want string) error {
	want = strings.TrimSpace(want)
	if want != "" {
		if _, err := lock.ParsePublicKey(want); err != nil {
			return &exitError{code: exitConfigError, err: fmt.Errorf("--lock-signer must be the full lock public key from `thawr client lock status` on a signer: %w", err)}
		}
	}
	switch {
	case want == "" || want == st.LockSigner:
		return nil
	case st.LockSigner != "":
		return &exitError{code: exitConfigError, err: fmt.Errorf("--lock-signer %s: this device already expects %s; run `thawr client down --forget` and enrol again to change it", want, st.LockSigner)}
	}
	pins, err := client.LoadPins(stateDir)
	if err != nil {
		return err
	}
	if pins.Lock() != nil {
		return &exitError{code: exitConfigError, err: errors.New("--lock-signer: this device already pinned a lock record; the flag only applies before the first record")}
	}
	st.LockSigner = want
	return client.SaveState(stateDir, st)
}

func newClientCmd(deps cliDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Enrol this device and run the node client",
	}
	var (
		upf              clientUpFlags
		stateDir, socket string
	)
	up := &cobra.Command{
		Use:   "up",
		Short: "Enrol this device if needed, then run the client in the foreground",
		Long: `Runs the node client: brings up the WireGuard interface, restores the
cached netmap, and keeps the interface in sync with the server until
SIGINT or SIGTERM. When the device is not enrolled yet, --server and
--token enrol it first.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateDNSMode(upf.dnsMode); err != nil {
				return err
			}
			logger := server.NewLogger(logConfig(upf.logLevel), cmd.ErrOrStderr())
			if err := enrollIfNeeded(cmd.Context(), deps, logger, upf, stateDir); err != nil {
				return err
			}
			d, err := client.NewDaemon(client.DaemonOptions{StateDir: stateDir, Socket: socket, Interface: upf.iface, Logger: logger, Version: version,
				DNS: client.DNSOptions{Mode: upf.dnsMode}})
			if err != nil {
				return err
			}
			ctx, stop := lifecycleContext(cmd.Context())
			defer stop()
			return d.Run(ctx)
		},
	}
	addClientUpFlags(up, &upf)
	addClientCommonFlags(up, &stateDir, &socket)

	var forget bool
	down := &cobra.Command{
		Use:   "down",
		Short: "Stop the running client; with --forget also remove the enrollment state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lc := client.NewLocalClient(socket)
			if err := lc.Down(cmd.Context()); err != nil {
				if !forget {
					return fmt.Errorf("client is not running (%w)", err)
				}
			} else {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "client stopping")
			}
			if !forget {
				return nil
			}
			st, err := client.LoadState(stateDir)
			if errors.Is(err, client.ErrNotEnrolled) {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "not enrolled")
				return err
			}
			if err != nil {
				return err
			}
			if err := client.Forget(stateDir); err != nil {
				return err
			}
			_ = os.Remove(stateDirFile(stateDir, client.NetMapFile))
			_ = os.Remove(stateDirFile(stateDir, client.PinsFile))
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "forgot enrollment as %s (%s); the server still lists the peer until an admin deletes it\n", st.Name, st.IPv4)
			return err
		},
	}
	down.Flags().BoolVar(&forget, "forget", false, "remove node.key, state.json, the netmap cache and the pinned keys")
	addClientCommonFlags(down, &stateDir, &socket)

	var asJSON, watch bool
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the control connection, every peer's path and the filter counters",
		Long: `Prints one table with the control connection, the local WireGuard
interface and NAT verdict, one row per visible peer with the path in use,
and the filter counters. Exit codes: 0 connected, 1 running but the
server is unreachable, 2 usage error, 3 client not running.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lc := client.NewLocalClient(socket)
			if watch {
				return watchStatus(cmd.Context(), cmd.OutOrStdout(), lc, asJSON)
			}
			st, err := lc.Status(cmd.Context())
			if err != nil {
				return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
			}
			if err := printStatus(cmd.OutOrStdout(), st, asJSON); err != nil {
				return err
			}
			if st.Server.State != client.ServerConnected {
				return &exitError{code: exitNotConnected, err: errors.New("client is running but not connected to the server")}
			}
			return nil
		},
	}
	status.Flags().BoolVar(&asJSON, "json", false, "print the status document as JSON (docs/status.schema.json)")
	status.Flags().BoolVar(&watch, "watch", false, "redraw every 2 s until Ctrl-C")
	addClientCommonFlags(status, &stateDir, &socket)

	rotate := &cobra.Command{
		Use:   "rotate-key",
		Short: "Generate a new WireGuard key and register it with the server",
		Long: `Generates a new WireGuard key, registers it with the server and
reconfigures the interface. With the network lock off, every other
device pins this device's key and shows it as "key changed" until
someone runs "thawr client trust <this name>" there. With the lock on,
a signer's new key is signed on the way and applied everywhere at once;
any other device's new key is held as "unsigned" until a signer runs
"thawr client lock sign <this name>".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lc := client.NewLocalClient(socket)
			if err := lc.RotateKey(cmd.Context()); err != nil {
				return err
			}
			name := "<this peer>"
			st, err := lc.Status(cmd.Context())
			if err != nil {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "key rotated; the lock state could not be read (%v). With the network lock on, a signer must run: thawr client lock sign %s; without it, other devices run: thawr client trust %s\n", err, name, name)
				return err
			}
			if st.Self.Name != "" {
				name = st.Self.Name
			}
			if st.Lock.Enabled && st.Lock.Signer {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "key rotated and signed; other devices switch to it without a trust step")
				return err
			}
			if st.Lock.Enabled {
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "key rotated; other devices hold this peer as unsigned until a signer runs: thawr client lock sign %s\n", name)
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "key rotated; other devices show this peer as \"key changed\" until they run: thawr client trust %s\n", name)
			return err
		},
	}
	addClientCommonFlags(rotate, &stateDir, &socket)

	var trustAll bool
	trust := &cobra.Command{
		Use:   "trust <name>...",
		Short: "Accept the changed key of held peers (\"hub\" for the server's hub)",
		Long: `A peer whose WireGuard key differs from the one this device pinned is
held out of the tunnel and shown as "key changed" in status. trust
accepts the offered key, pins it and lets the peer back in. Use it after
a peer ran rotate-key, or after checking with the peer's owner why the
key changed. Exit codes: 0 accepted, 2 nothing held under that name, 3
client not running.`,
		Args: usageArgs(cobra.ArbitraryArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if trustAll == (len(args) > 0) {
				return &exitError{code: exitConfigError, err: errors.New("name one or more held peers, or --all")}
			}
			if trustAll {
				args = []string{"all"}
			}
			lc := client.NewLocalClient(socket)
			for _, name := range args {
				res, err := lc.Trust(cmd.Context(), name)
				var le *client.LocalError
				switch {
				case errors.As(err, &le) && le.Status == http.StatusNotFound:
					return &exitError{code: exitConfigError, err: fmt.Errorf("%s: %s", name, le.Message)}
				case errors.As(err, &le):
					return fmt.Errorf("trust %s: %s", name, le.Message)
				case err != nil:
					return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
				}
				for _, h := range res.Trusted {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "trusted %s (%s → %s)\n", h.Name, fingerprint(h.PinnedKey), fingerprint(h.OfferedKey)); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
	trust.Flags().BoolVar(&trustAll, "all", false, "accept every held key")
	addClientCommonFlags(trust, &stateDir, &socket)

	var pingCount int
	var pingJSON bool
	ping := &cobra.Command{
		Use:   "ping <peer>",
		Short: "Establish a path to a peer, send ICMP echoes and report the path in use",
		Long: `Marks traffic intent toward the named peer so the client probes its
candidates now, prints every path change, sends --count echoes with the
system ping to the peer's overlay address and ends with the settled
path. Exit codes: 0 path in use and echo answered, 1 no path or no
reply, 2 unknown peer, 3 client not running. --count 0 skips the echoes.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPing(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), pingOptions{socket: socket, peer: args[0], count: pingCount, asJSON: pingJSON})
		},
	}
	ping.Flags().IntVar(&pingCount, "count", 3, "ICMP echoes to send; 0 only establishes the path")
	ping.Flags().BoolVar(&pingJSON, "json", false, "print the settled path as JSON")
	addClientCommonFlags(ping, &stateDir, &socket)

	cmd.AddCommand(up, down, status, rotate, trust, newClientLockCmd(&stateDir, &socket), ping, newClientInstallCmd(deps), newClientUninstallCmd(deps))
	return cmd
}

func addClientCommonFlags(cmd *cobra.Command, stateDir, socket *string) {
	cmd.Flags().StringVar(stateDir, "state-dir", client.DefaultDir(), "state directory ($"+client.EnvStateDir+")")
	cmd.Flags().StringVar(socket, "socket", defaultClientSocket(), "local control socket ($"+envClientSocket+")")
}

func stateDirFile(dir, name string) string { return dir + string(os.PathSeparator) + name }

// Client exit codes (spec 007).
const (
	exitNotConnected = 1
	exitNotRunning   = 3
)

func logConfig(level string) config.Log { return config.Log{Level: level, Format: "text"} }

// watchInterval is how often --watch redraws.
const watchInterval = 2 * time.Second

func printStatus(w io.Writer, st client.Status, asJSON bool) error {
	if asJSON {
		return printJSON(w, st)
	}
	return renderStatus(w, st)
}

// watchStatus redraws the status until ctx ends (Ctrl-C exits 0) or the
// daemon goes away (exit 3).
func watchStatus(ctx context.Context, w io.Writer, lc *client.LocalClient, asJSON bool) error {
	ctx, stop := lifecycleContext(ctx)
	defer stop()
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		st, err := lc.Status(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
		}
		if _, err := io.WriteString(w, "\x1b[2J\x1b[H"); err != nil {
			return err
		}
		if err := printStatus(w, st, asJSON); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
