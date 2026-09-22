package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thedatadudech/thawr/internal/client"
	"github.com/thedatadudech/thawr/internal/server"
	"github.com/thedatadudech/thawr/internal/svc"
)

// Service names registered with the platform's service manager.
const (
	serviceServer = "thawr-server"
	serviceClient = "thawr-client"
)

// cliDeps are the process-level dependencies of the install commands,
// replaced by fakes in tests.
type cliDeps struct {
	newManager func(svc.Options) (svc.Manager, error)
	isRoot     func() bool
	executable func() (string, error)
	homeDir    func() (string, error)
	enroll     func(context.Context, client.Options) (client.State, error)
	mkdirAll   func(string, os.FileMode) error
}

func productionDeps() cliDeps {
	return cliDeps{newManager: svc.New, isRoot: isRoot, executable: os.Executable, homeDir: os.UserHomeDir, enroll: client.Enroll, mkdirAll: os.MkdirAll}
}

// ensureServerDirs creates the data directory and the admin socket's
// directory before the service is registered: the systemd unit mounts
// the file system read-only except for these paths, and systemd refuses
// to start a unit whose ReadWritePaths do not exist.
func ensureServerDirs(deps cliDeps, dataDir, adminSocket string) error {
	if err := deps.mkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data_dir %s: %w", dataDir, err)
	}
	if dir := filepath.Dir(adminSocket); filepath.Clean(dir) != filepath.Clean(dataDir) {
		if err := deps.mkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create admin socket directory %s: %w", dir, err)
		}
	}
	return nil
}

// installFlags are shared by both install commands.
type installFlags struct {
	bin     string
	noStart bool
}

func addInstallFlags(cmd *cobra.Command, f *installFlags) {
	cmd.Flags().StringVar(&f.bin, "bin", "", "binary the service runs (default: this executable)")
	cmd.Flags().BoolVar(&f.noStart, "no-start", false, "register the service without starting it")
}

func requireRoot(deps cliDeps) error {
	if !deps.isRoot() {
		return &exitError{code: exitConfigError, err: errors.New("run as root (sudo)")}
	}
	return nil
}

// openManager returns the platform's service manager; platforms without
// one exit 2.
func openManager(deps cliDeps, errOut io.Writer) (svc.Manager, error) {
	m, err := deps.newManager(svc.Options{Logger: server.NewLogger(logConfig("info"), errOut)})
	if errors.Is(err, svc.ErrUnsupported) {
		return nil, &exitError{code: exitConfigError, err: err}
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

// resolveBinary picks the executable the service will run: --bin, or
// this process's binary with symlinks resolved. It must be absolute and
// executable; the running binary is refused inside a home directory,
// where a service cannot rely on it staying put.
func resolveBinary(deps cliDeps, explicit string) (string, error) {
	path := explicit
	if path == "" {
		exe, err := deps.executable()
		if err != nil {
			return "", fmt.Errorf("locate this executable: %w (pass --bin)", err)
		}
		if path, err = filepath.EvalSymlinks(exe); err != nil {
			return "", fmt.Errorf("resolve %s: %w", exe, err)
		}
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("--bin %q must be an absolute path", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("--bin: %w", err)
	}
	if fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0) {
		return "", fmt.Errorf("%s is not an executable file", path)
	}
	if explicit == "" {
		if home, err := deps.homeDir(); err == nil && home != "" {
			// Both sides through EvalSymlinks: Windows may hand out 8.3
			// short names for one and long names for the other.
			if real, err := filepath.EvalSymlinks(home); err == nil {
				home = real
			}
			if strings.HasPrefix(path, filepath.Clean(home)+string(os.PathSeparator)) {
				return "", fmt.Errorf("%s is under your home directory; move it to /usr/local/bin (or pass --bin)", path)
			}
		}
	}
	return path, nil
}

// installService registers s unless it already exists, starts it unless
// told not to, and prints what happened.
func installService(ctx context.Context, w io.Writer, m svc.Manager, s svc.Service, noStart bool) error {
	state, err := m.Status(ctx, s.Name)
	if err != nil {
		return err
	}
	if state != svc.Absent {
		_, err := fmt.Fprintf(w, "%s is already installed (%s); run `thawr %s uninstall` first to change it\n", s.Name, state, strings.TrimPrefix(s.Name, "thawr-"))
		return err
	}
	files, err := m.Install(ctx, s)
	if err != nil {
		return fmt.Errorf("install %s: %w", s.Name, err)
	}
	for _, f := range files {
		if _, err := fmt.Fprintf(w, "wrote %s\n", f); err != nil {
			return err
		}
	}
	if noStart {
		_, err := fmt.Fprintf(w, "%s registered to start at boot (not started)\nlogs: %s\n", s.Name, m.Logs(s.Name))
		return err
	}
	if err := m.Start(ctx, s.Name); err != nil {
		return fmt.Errorf("start %s: %w", s.Name, err)
	}
	_, err = fmt.Fprintf(w, "%s started and enabled at boot\nlogs: %s\n", s.Name, m.Logs(s.Name))
	return err
}

// refuseHubHost rejects a client on a host that runs the server: both
// would claim the overlay route, and whichever interface comes up first
// swallows the other's traffic. The hub is already a peer on this host.
func refuseHubHost(ctx context.Context, m svc.Manager) error {
	state, err := m.Status(ctx, serviceServer)
	if err != nil {
		return err
	}
	if state == svc.Absent {
		return nil
	}
	return &exitError{code: exitConfigError, err: fmt.Errorf("%s is installed here: a host running the server is already a peer (the hub) and cannot also run a client; install the client on another machine", serviceServer)}
}

// uninstallService stops and unregisters name, then, with purge, deletes
// the paths purgePaths names. A purge without --yes fails before
// anything is touched.
func uninstallService(ctx context.Context, w io.Writer, m svc.Manager, name string, purge, yes bool, purgePaths []string, doPurge func() error) error {
	if purge && !yes {
		return &exitError{code: exitConfigError, err: fmt.Errorf("--purge would delete %s; re-run with --yes to confirm", strings.Join(purgePaths, ", "))}
	}
	state, err := m.Status(ctx, name)
	if err != nil {
		return err
	}
	if state == svc.Running {
		if err := m.Stop(ctx, name); err != nil {
			return fmt.Errorf("stop %s: %w", name, err)
		}
	}
	if state != svc.Absent {
		if err := m.Uninstall(ctx, name); err != nil {
			return fmt.Errorf("uninstall %s: %w", name, err)
		}
		if _, err := fmt.Fprintf(w, "%s removed\n", name); err != nil {
			return err
		}
	} else if _, err := fmt.Fprintf(w, "%s was not installed\n", name); err != nil {
		return err
	}
	if !purge {
		_, err := fmt.Fprintf(w, "data kept in %s\n", strings.Join(purgePaths, ", "))
		return err
	}
	if err := doPurge(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "deleted %s\n", strings.Join(purgePaths, ", "))
	return err
}

func newServerInstallCmd(deps cliDeps) *cobra.Command {
	var (
		configPath, publicAddr string
		f                      installFlags
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the server as a system service that starts at boot",
		Long: `Writes a minimal config when --public-addr is given and none exists,
validates it like --check, then registers thawr-server with systemd,
launchd or the Windows service manager and starts it. Requires root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			bin, err := resolveBinary(deps, f.bin)
			if err != nil {
				return &exitError{code: exitConfigError, err: err}
			}
			if err := ensureServerConfig(cmd.OutOrStdout(), configPath, publicAddr); err != nil {
				return err
			}
			cfg, _, err := checkServer(configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := ensureServerDirs(deps, cfg.DataDir, cfg.AdminSocket); err != nil {
				return err
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return installService(cmd.Context(), cmd.OutOrStdout(), m, svc.Service{
				Name: serviceServer, Description: "Thawr control server", Exec: bin,
				Args:           []string{"server", "--config", configPath},
				ReadWritePaths: uniquePaths(cfg.DataDir, filepath.Dir(cfg.AdminSocket)),
				Reload:         true,
			}, f.noStart)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultServerConfig(), "path to the server YAML config ($"+envConfig+")")
	cmd.Flags().StringVar(&publicAddr, "public-addr", "", "write a minimal config with this public_addr when none exists")
	addInstallFlags(cmd, &f)
	return cmd
}

// ensureServerConfig writes `public_addr: <addr>` to path when the file
// does not exist; it never overwrites and requires --public-addr for a
// missing file.
func ensureServerConfig(w io.Writer, path, publicAddr string) error {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		if publicAddr != "" {
			return &exitError{code: exitConfigError, err: fmt.Errorf("%s exists; edit public_addr there instead of passing --public-addr", path)}
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("config: %w", err)
	case publicAddr == "":
		return &exitError{code: exitConfigError, err: fmt.Errorf("%s does not exist; pass --public-addr to create it", path)}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.WriteFile(path, []byte("public_addr: "+publicAddr+"\n"), 0o640); err != nil { //nolint:gosec // readable by the thawr group on purpose; contains no secret
		return fmt.Errorf("config: %w", err)
	}
	_, err = fmt.Fprintf(w, "wrote %s\n", path)
	return err
}

func newServerUninstallCmd(deps cliDeps) *cobra.Command {
	var (
		configPath string
		purge, yes bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and unregister the server service; --purge also deletes data_dir",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			cfg, _, err := checkServer(configPath, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			return uninstallService(cmd.Context(), cmd.OutOrStdout(), m, serviceServer, purge, yes, []string{cfg.DataDir}, func() error {
				return os.RemoveAll(cfg.DataDir)
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultServerConfig(), "path to the server YAML config ($"+envConfig+")")
	cmd.Flags().BoolVar(&purge, "purge", false, "also delete data_dir (database, keys, TLS files)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm --purge")
	return cmd
}

func newClientInstallCmd(deps cliDeps) *cobra.Command {
	var (
		upf              clientUpFlags
		stateDir, socket string
		f                installFlags
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Enrol if needed, then run the client as a system service that starts at boot",
		Long: `Enrols the device first when --server and --token are given, exactly as
client up does, and only then registers thawr-client with systemd,
launchd or the Windows service manager. The token is consumed before
the service definition is written, which therefore never contains it.
Requires root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			bin, err := resolveBinary(deps, f.bin)
			if err != nil {
				return &exitError{code: exitConfigError, err: err}
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if err := refuseHubHost(cmd.Context(), m); err != nil {
				return err
			}
			if err := validateDNSMode(upf.dnsMode); err != nil {
				return err
			}
			logger := server.NewLogger(logConfig(upf.logLevel), cmd.ErrOrStderr())
			if err := enrollIfNeeded(cmd.Context(), deps, logger, upf, stateDir); err != nil {
				return err
			}
			upf.advertiseSet = cmd.Flags().Changed("advertise-routes") || cmd.Flags().Changed("advertise-exit-node")
			if err := applyAdvertise(stateDir, upf); err != nil {
				return err
			}
			return installService(cmd.Context(), cmd.OutOrStdout(), m, svc.Service{
				Name: serviceClient, Description: "Thawr node client", Exec: bin,
				Args:           []string{"client", "up", "--state-dir", stateDir, "--socket", socket, "--interface", upf.iface, "--log-level", upf.logLevel, "--dns", upf.dnsMode},
				ReadWritePaths: uniquePaths(stateDir, filepath.Dir(socket)),
			}, f.noStart)
		},
	}
	addClientUpFlags(cmd, &upf)
	addClientCommonFlags(cmd, &stateDir, &socket)
	addInstallFlags(cmd, &f)
	return cmd
}

func newClientUninstallCmd(deps cliDeps) *cobra.Command {
	var (
		stateDir, socket string
		purge, yes       bool
	)
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and unregister the client service; --purge also forgets the enrollment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			files := []string{stateDirFile(stateDir, client.StateFile), stateDirFile(stateDir, client.KeyFile), stateDirFile(stateDir, client.NetMapFile)}
			return uninstallService(cmd.Context(), cmd.OutOrStdout(), m, serviceClient, purge, yes, files, func() error {
				if err := client.Forget(stateDir); err != nil {
					return err
				}
				if err := os.Remove(stateDirFile(stateDir, client.NetMapFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("remove netmap cache: %w", err)
				}
				return nil
			})
		},
	}
	addClientCommonFlags(cmd, &stateDir, &socket)
	cmd.Flags().BoolVar(&purge, "purge", false, "also remove node.key, state.json and the netmap cache")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm --purge")
	return cmd
}

// uniquePaths drops empty and duplicate entries, keeping order.
func uniquePaths(paths ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || p == "." || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
