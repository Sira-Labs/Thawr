package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/client"
	"github.com/sira-labs/thawr/internal/svc"
)

// startHint is the way back after the client stopped: the service when
// one is installed, the foreground otherwise.
const startHint = "start the installed service with `sudo thawr client start`, or run `sudo thawr client up` in the foreground"

// newClientStartCmd starts the installed client service, the way back
// after `client down` or `client stop`: neither launchd nor systemd
// restarts a service that exited cleanly.
func newClientStartCmd(deps cliDeps) *cobra.Command {
	var stateDir, socket string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the installed client service (after `client down` or `client stop`)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			state, err := m.Status(cmd.Context(), serviceClient)
			if err != nil {
				return err
			}
			switch state {
			case svc.Absent:
				return &exitError{code: exitConfigError, err: fmt.Errorf("%s is not installed; install it with `sudo thawr client install --server … --token …`, or run `sudo thawr client up` in the foreground", serviceClient)}
			case svc.Running:
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s is already running\n", serviceClient)
				return err
			}
			// A foreground `client up` holds the socket; the service would
			// start and exit at once with "already running".
			if err := client.CheckNotRunning(socket); errors.Is(err, client.ErrAlreadyRunning) {
				return &exitError{code: exitConfigError, err: fmt.Errorf("%w; a foreground `thawr client up` is running: stop it (Ctrl-C or `sudo thawr client down`) first", err)}
			}
			if err := m.Start(cmd.Context(), serviceClient); err != nil {
				return fmt.Errorf("start %s: %w", serviceClient, err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s started\nlogs: %s\n", serviceClient, m.Logs(serviceClient))
			return err
		},
	}
	addClientCommonFlags(cmd, &stateDir, &socket)
	return cmd
}

// newClientStopCmd stops the installed client service; it stays
// registered and starts again at boot or with `client start`.
func newClientStopCmd(deps cliDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the installed client service; it starts again at boot or with `client start`",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			m, err := openManager(deps, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			state, err := m.Status(cmd.Context(), serviceClient)
			if err != nil {
				return err
			}
			switch state {
			case svc.Absent:
				return &exitError{code: exitConfigError, err: fmt.Errorf("%s is not installed; a foreground `thawr client up` stops with Ctrl-C or `sudo thawr client down`", serviceClient)}
			case svc.Stopped:
				_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s is not running\n", serviceClient)
				return err
			}
			if err := m.Stop(cmd.Context(), serviceClient); err != nil {
				return fmt.Errorf("stop %s: %w", serviceClient, err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s stopped; it starts again at boot or with `sudo thawr client start`\n", serviceClient)
			return err
		},
	}
}
