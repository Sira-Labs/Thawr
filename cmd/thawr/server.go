package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/config"
	"github.com/sira-labs/thawr/internal/server"
)

// Exit codes of `thawr server`.
const (
	exitConfigError = 2
)

// envConfig names the config file when --config is not given.
const envConfig = "THAWR_CONFIG"

const defaultConfigPath = "/etc/thawr/server.yaml"

// exitError carries a process exit code out of a cobra command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func newServerCmd(deps cliDeps) *cobra.Command {
	var (
		configPath string
		check      bool
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the control server (registry, STUN, relay, admin UI)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServer(cmd, configPath, check)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultServerConfig(), "path to the server YAML config ($"+envConfig+")")
	cmd.Flags().BoolVar(&check, "check", false, "validate config, TLS files and policy, then exit")
	cmd.AddCommand(newServerInstallCmd(deps), newServerUninstallCmd(deps))
	return cmd
}

func defaultServerConfig() string {
	if def := os.Getenv(envConfig); def != "" {
		return def
	}
	return defaultConfigPath
}

// checkServer loads the config and builds the server without running
// it, as `thawr server --check` does. Failures carry exit code 2.
func checkServer(configPath string, errOut io.Writer) (*config.Config, *server.Server, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		var verr *config.ValidationError
		if errors.As(err, &verr) {
			return nil, nil, &exitError{code: exitConfigError, err: fmt.Errorf("invalid config %s:\n  %s", configPath, strings.Join(verr.Problems, "\n  "))}
		}
		return nil, nil, &exitError{code: exitConfigError, err: err}
	}
	logger := server.NewLogger(cfg.Log, errOut)
	srv, err := server.New(cfg, server.Deps{Logger: logger, Version: version})
	if err != nil {
		return nil, nil, &exitError{code: exitConfigError, err: err}
	}
	if err := srv.Check(); err != nil {
		return nil, nil, &exitError{code: exitConfigError, err: err}
	}
	return cfg, srv, nil
}

func runServer(cmd *cobra.Command, configPath string, check bool) error {
	cfg, srv, err := checkServer(configPath, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	if check {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "config %s ok\n", configPath)
		return err
	}
	logger := server.NewLogger(cfg.Log, cmd.ErrOrStderr())

	ctx, stop := lifecycleContext(cmd.Context())
	defer stop()
	reload := make(chan struct{}, 1)
	stopReload := notifyReload(reload)
	defer stopReload()

	logger.Info("starting thawr server", "version", version, "config", configPath)
	return srv.Run(ctx, reload)
}
