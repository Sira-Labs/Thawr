package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/backup"
	"github.com/sira-labs/thawr/internal/server"
)

func newServerRestoreCmd(deps cliDeps) *cobra.Command {
	var (
		configPath string
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "restore FILE",
		Short: "Restore a backup from 'thawr admin backup' into data_dir (server stopped)",
		Long: `Restores a backup written by 'thawr admin backup' so this host runs the
same network: the same peers, policy and audit log, the same WireGuard
key and the same pinned TLS certificate, so enrolled devices reconnect
without any step on their side once public_addr resolves to this host.

The whole archive is verified before anything is written. Restore
refuses while a server runs on this data_dir, refuses a backup from a
newer release, and refuses a non-empty data_dir unless --force, which
moves it to <data_dir>.pre-restore-<time> (nothing is deleted). An
older database is migrated. The config and policy copies in the backup
are written only where no file exists yet; on a fresh host the
backup's config is used. Requires root.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(deps); err != nil {
				return err
			}
			res, err := server.Restore(cmd.Context(), server.RestoreOptions{Archive: args[0], ConfigPath: configPath, Force: force})
			if err != nil {
				code := 1
				switch {
				case errors.Is(err, backup.ErrInvalid), errors.Is(err, server.ErrDataDirNotEmpty),
					errors.Is(err, server.ErrServerRunning), errors.Is(err, server.ErrDataDirInUse):
					code = exitConfigError
				}
				return &exitError{code: code, err: err}
			}
			return printRestore(cmd.OutOrStdout(), res)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", defaultServerConfig(), "path to the server YAML config ($"+envConfig+"); the backup's copy is written here when absent")
	cmd.Flags().BoolVar(&force, "force", false, "move a non-empty data_dir aside instead of refusing")
	return cmd
}

func printRestore(w io.Writer, r server.RestoreResult) error {
	schema := fmt.Sprintf("schema %d", r.SchemaNow)
	if r.SchemaArchive != r.SchemaNow {
		schema = fmt.Sprintf("schema %d (migrated from %d)", r.SchemaNow, r.SchemaArchive)
	}
	lines := []string{
		fmt.Sprintf("restored %s: %s, %s", r.DataDir, plural(r.Peers, "peer"), schema),
	}
	if r.MovedAside != "" {
		lines = append(lines, "previous data_dir kept at "+r.MovedAside)
	}
	if r.TLSFingerprint != "" {
		lines = append(lines, "tls fingerprint "+r.TLSFingerprint+" (unchanged; clients keep their pin)")
	}
	lines = append(lines, "config "+r.ConfigPath+" "+writtenOrKept(r.ConfigWritten))
	switch {
	case r.PolicyWritten:
		lines = append(lines, "policy "+r.PolicyPath+" written from the backup")
	case r.PolicyInBackup:
		lines = append(lines, "policy "+r.PolicyPath+" kept (the backup's copy was not used)")
	}
	lines = append(lines,
		"next: point "+r.PublicAddr+" at this host, then start the server (thawr server, or the installed service)")
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return nil
}

func writtenOrKept(written bool) string {
	if written {
		return "written from the backup"
	}
	return "kept"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
