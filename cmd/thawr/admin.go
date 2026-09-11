package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// adminFlags are shared by every admin subcommand.
type adminFlags struct {
	socket string
	json   bool
}

func newAdminCmd() *cobra.Command {
	var flags adminFlags
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Manage users, tokens, peers, policy and the audit log over the local admin socket",
	}
	cmd.PersistentFlags().StringVar(&flags.socket, "socket", defaultAdminSocket(), "admin socket path ($"+envAdminSocket+")")
	cmd.PersistentFlags().BoolVar(&flags.json, "json", false, "print JSON instead of a table")
	cmd.AddCommand(newAdminUserCmd(&flags), newAdminTokenCmd(&flags), newAdminPeerCmd(&flags), newAdminPolicyCmd(&flags), newAdminAuditCmd(&flags), newAdminLockCmd(&flags))
	return cmd
}

// printJSON writes v pretty-printed.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table renders rows with aligned columns.
func table(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(header, "\t")); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(r, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
