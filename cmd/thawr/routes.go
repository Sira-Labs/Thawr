package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sira-labs/thawr/internal/client"
)

// newClientExitNodeCmd builds `thawr client exit-node` (spec 013):
// route this device's internet traffic through an approved exit node.
func newClientExitNodeCmd(socket *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exit-node <name> | off | status",
		Short: "Route this device's internet traffic through a peer that is an approved exit node",
		Long: `Selects an exit node: the named peer must advertise 0.0.0.0/0, an admin
must have approved it, and the policy must grant this device
"internet". off restores normal routing; status shows the selection.
The choice survives restarts. Exit codes: 0 done, 2 refused or unknown
name, 3 client not running.`,
		Args: usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			lc := client.NewLocalClient(*socket)
			if args[0] == "status" {
				st, err := lc.Status(cmd.Context())
				if err != nil {
					return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
				}
				return renderExitNode(cmd.OutOrStdout(), st.ExitNode)
			}
			res, err := lc.SetExitNode(cmd.Context(), args[0])
			var le *client.LocalError
			switch {
			case errors.As(err, &le):
				return &exitError{code: exitConfigError, err: errors.New(le.Message)}
			case err != nil:
				return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
			}
			return renderExitNode(cmd.OutOrStdout(), res)
		},
	}
	return cmd
}

// renderExitNode prints the exit-node selection in one line.
func renderExitNode(w io.Writer, e client.ExitNodeStatus) error {
	var err error
	switch e.State {
	case client.ExitStateActive:
		_, err = fmt.Fprintf(w, "exit node: %s (active)\n", e.Name)
	case client.ExitStateUnavailable:
		_, err = fmt.Fprintf(w, "exit node: %s (unavailable: not in the current netmap, held, or no longer approved; traffic leaves the normal way)\n", e.Name)
	default:
		_, err = fmt.Fprintln(w, "exit node: off")
	}
	return err
}

// routesLine renders the status header's Routes line, empty when the
// device neither uses nor offers any route.
func routesLine(st client.Status) string {
	var parts []string
	for _, r := range st.Routes {
		if r.Prefix == "0.0.0.0/0" {
			continue
		}
		parts = append(parts, r.Prefix+" via "+r.Via)
	}
	switch st.ExitNode.State {
	case client.ExitStateActive:
		parts = append(parts, "exit node: "+st.ExitNode.Name)
	case client.ExitStateUnavailable:
		parts = append(parts, "exit node: "+st.ExitNode.Name+" (unavailable)")
	}
	var adv []string
	for _, a := range st.Advertised {
		if a.Approved {
			adv = append(adv, a.Prefix+" (approved)")
		} else {
			adv = append(adv, fmt.Sprintf("%s (pending approval: thawr admin peer routes approve %s %s)", a.Prefix, st.Self.Name, a.Prefix))
		}
	}
	if len(adv) > 0 {
		parts = append(parts, "advertising "+strings.Join(adv, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Routes: " + strings.Join(parts, " · ") + "\n"
}

// routeJSON mirrors the admin API's route view.
type routeJSON struct {
	Prefix       string `json:"prefix"`
	Approved     bool   `json:"approved"`
	ApprovedBy   string `json:"approved_by,omitempty"`
	ApprovedAt   string `json:"approved_at,omitempty"`
	AdvertisedAt string `json:"advertised_at"`
}

// newAdminPeerRoutesCmd builds `thawr admin peer routes` (spec 013).
func newAdminPeerRoutesCmd(flags *adminFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "routes", Short: "List, approve and revoke the prefixes a peer advertises"}
	list := &cobra.Command{
		Use:   "list <name>",
		Short: "List the prefixes a peer advertises with their approval",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			var routes []routeJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "GET", "/api/v1/peers/"+args[0]+"/routes", nil, &routes); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), routes)
			}
			return renderRoutes(cmd.OutOrStdout(), routes)
		},
	}
	var all bool
	set := func(use, short string, approved bool) *cobra.Command {
		c := &cobra.Command{
			Use:   use,
			Short: short,
			Args:  usageArgs(cobra.RangeArgs(1, 2)),
			RunE: func(cmd *cobra.Command, args []string) error {
				ac := newAdminClient(flags.socket)
				var prefixes []string
				switch {
				case all && len(args) == 1:
					var routes []routeJSON
					if err := ac.do(cmd.Context(), "GET", "/api/v1/peers/"+args[0]+"/routes", nil, &routes); err != nil {
						return err
					}
					for _, r := range routes {
						if r.Approved != approved {
							prefixes = append(prefixes, r.Prefix)
						}
					}
				case !all && len(args) == 2:
					prefixes = []string{args[1]}
				default:
					return &exitError{code: exitConfigError, err: errors.New("name a prefix, or --all")}
				}
				var routes []routeJSON
				for _, p := range prefixes {
					if err := ac.do(cmd.Context(), "PUT", "/api/v1/peers/"+args[0]+"/routes/"+p, map[string]bool{"approved": approved}, &routes); err != nil {
						return err
					}
				}
				if len(prefixes) == 0 {
					_, err := fmt.Fprintln(cmd.OutOrStdout(), "nothing to change")
					return err
				}
				if flags.json {
					return printJSON(cmd.OutOrStdout(), routes)
				}
				return renderRoutes(cmd.OutOrStdout(), routes)
			},
		}
		c.Flags().BoolVar(&all, "all", false, "every advertised prefix of the peer")
		return c
	}
	cmd.AddCommand(list,
		set("approve <name> <prefix> | --all", "Approve an advertised prefix; clients with a matching policy rule route it from the next netmap", true),
		set("revoke <name> <prefix> | --all", "Revoke an approval; the route leaves every client with the next netmap", false))
	return cmd
}

// renderRoutes prints advertised prefixes as a table.
func renderRoutes(w io.Writer, routes []routeJSON) error {
	rows := make([][]string, 0, len(routes))
	for _, r := range routes {
		state := "pending"
		if r.Approved {
			state = "approved by " + r.ApprovedBy
		}
		rows = append(rows, []string{r.Prefix, state, r.AdvertisedAt})
	}
	return table(w, []string{"PREFIX", "STATE", "ADVERTISED"}, rows)
}
