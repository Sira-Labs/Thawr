package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/control/policy"
)

// policyCheckJSON is the answer of POST /api/v1/policy/check.
type policyCheckJSON struct {
	OK bool `json:"ok"`
	control.PolicyReport
}

func newAdminPolicyCmd(flags *adminFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Check, reload and show the ACL policy"}
	check := &cobra.Command{
		Use:   "check <file>",
		Short: "Validate a policy file against the running server without installing it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return &exitError{code: exitConfigError, err: fmt.Errorf("read policy: %w", err)}
			}
			var rep policyCheckJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "POST", "/api/v1/policy/check", map[string]string{"yaml": string(data)}, &rep); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), rep)
			}
			out := cmd.OutOrStdout()
			for _, w := range rep.Warnings {
				_, _ = fmt.Fprintln(out, "warning:", w)
			}
			for _, e := range rep.Errors {
				_, _ = fmt.Fprintln(out, "error:", e)
			}
			if !rep.OK {
				return &exitError{code: exitConfigError, err: fmt.Errorf("%s: %d error(s)", args[0], len(rep.Errors))}
			}
			_, err = fmt.Fprintf(out, "%s: ok, %s\n", args[0], summaryLine(rep.Summary))
			return err
		},
	}
	reload := &cobra.Command{
		Use:   "reload",
		Short: "Re-read the server's policy file; an invalid file keeps the running policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var rep control.PolicyReport
			if err := newAdminClient(flags.socket).do(cmd.Context(), "POST", "/api/v1/policy/reload", nil, &rep); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), rep)
			}
			for _, w := range rep.Warnings {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "warning:", w)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "policy reloaded (%s): %s\n", rep.Hash, summaryLine(rep.Summary))
			return err
		},
	}
	show := &cobra.Command{
		Use:   "show",
		Short: "Print the effective policy, its hash and summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var rep control.PolicyReport
			if err := newAdminClient(flags.socket).do(cmd.Context(), "GET", "/api/v1/policy", nil, &rep); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), rep)
			}
			out := cmd.OutOrStdout()
			hash := rep.Hash
			if hash == "" {
				hash = "none (empty default-deny policy)"
			}
			_, _ = fmt.Fprintf(out, "# hash: %s\n# %s\n", hash, summaryLine(rep.Summary))
			for _, w := range rep.Warnings {
				_, _ = fmt.Fprintln(out, "# warning:", w)
			}
			if rep.Source != "" {
				_, _ = fmt.Fprint(out, strings.TrimRight(rep.Source, "\n")+"\n")
			}
			return nil
		},
	}
	cmd.AddCommand(check, reload, show)
	return cmd
}

func summaryLine(s policy.Summary) string {
	return fmt.Sprintf("%d rules, %d peers, %d visible pairs", s.Rules, s.Peers, s.VisiblePairs)
}
