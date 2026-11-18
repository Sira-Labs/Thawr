package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
)

// relayJSON is one relay node as the admin API returns it.
type relayJSON struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Version        string `json:"version,omitempty"`
	Online         bool   `json:"online"`
	Since          string `json:"since,omitempty"`
	RegisteredAt   string `json:"registered_at"`
	LastSeenAt     string `json:"last_seen_at,omitempty"`
	Sessions       int    `json:"sessions"`
	Frames         uint64 `json:"frames"`
	Bytes          uint64 `json:"bytes"`
	Drops          uint64 `json:"drops"`
}

// relayTokenJSON is a freshly created relay token; Secret appears once.
type relayTokenJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	ExpiresAt string `json:"expires_at"`
	Secret    string `json:"secret"`
}

// relayState renders "online since <time>" or "offline since <time>";
// a relay that has not attached since the server started is "offline".
func relayState(r relayJSON) string {
	state := "offline"
	if r.Online {
		state = "online"
	}
	if r.Since != "" {
		state += " since " + r.Since
	}
	return state
}

func newAdminRelayCmd(flags *adminFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "relay", Short: "Manage standalone relay nodes"}
	var name, ttl string
	token := &cobra.Command{
		Use:   "token",
		Short: "Create a one-time token that registers one relay node (shown once)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var t relayTokenJSON
			if err := newAdminClient(flags.socket).do(cmd.Context(), "POST", "/api/v1/relays/tokens",
				map[string]string{"name": name, "expires": ttl}, &t); err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), t)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "Token id:     %s  (expires %s, single use)\nRelay name:   %s\nRelay token:  %s\n",
				t.ID, t.ExpiresAt, dash(t.Name), t.Secret)
			return err
		},
	}
	token.Flags().StringVar(&name, "name", "", "name the relay will have (default: the relay chooses)")
	token.Flags().StringVar(&ttl, "ttl", "1h", "validity, e.g. 30m, 1h (max 24h)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List relay nodes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			relays, err := listRelays(cmd.Context(), flags)
			if err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), relays)
			}
			rows := make([][]string, 0, len(relays))
			for _, r := range relays {
				rows = append(rows, []string{r.Name, r.URL, relayState(r), strconv.Itoa(r.Sessions), dash(r.Version)})
			}
			return table(cmd.OutOrStdout(), []string{"NAME", "URL", "STATE", "SESSIONS", "VERSION"}, rows)
		},
	}
	show := &cobra.Command{
		Use:   "show <name>",
		Short: "Show one relay node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := findRelay(cmd.Context(), flags, args[0])
			if err != nil {
				return err
			}
			if flags.json {
				return printJSON(cmd.OutOrStdout(), r)
			}
			return table(cmd.OutOrStdout(), []string{"Name:", r.Name}, [][]string{
				{"Id:", r.ID},
				{"URL:", r.URL},
				{"TLS fingerprint:", r.TLSFingerprint},
				{"State:", relayState(r)},
				{"Version:", dash(r.Version)},
				{"Registered:", r.RegisteredAt},
				{"Last seen:", dash(r.LastSeenAt)},
				{"Sessions:", strconv.Itoa(r.Sessions)},
				{"Frames:", strconv.FormatUint(r.Frames, 10)},
				{"Bytes:", strconv.FormatUint(r.Bytes, 10)},
				{"Drops:", strconv.FormatUint(r.Drops, 10)},
			})
		},
	}
	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a relay node: its secret and tickets stop working and no device is sent to it any more",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := findRelay(cmd.Context(), flags, args[0])
			if err != nil {
				return err
			}
			if err := newAdminClient(flags.socket).do(cmd.Context(), "DELETE", "/api/v1/relays/"+r.ID, nil, nil); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "relay %s deleted\n", r.Name)
			return err
		},
	}
	cmd.AddCommand(token, list, show, del)
	return cmd
}

func listRelays(ctx context.Context, flags *adminFlags) ([]relayJSON, error) {
	var relays []relayJSON
	if err := newAdminClient(flags.socket).do(ctx, "GET", "/api/v1/relays", nil, &relays); err != nil {
		return nil, err
	}
	return relays, nil
}

// findRelay resolves a relay name through the list; the API addresses
// relays by id.
func findRelay(ctx context.Context, flags *adminFlags, name string) (relayJSON, error) {
	relays, err := listRelays(ctx, flags)
	if err != nil {
		return relayJSON{}, err
	}
	for _, r := range relays {
		if r.Name == name {
			return r, nil
		}
	}
	return relayJSON{}, fmt.Errorf("relay %q: not found", name)
}
