package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/sira-labs/thawr/internal/client"
)

// pingPoll is how often the path is re-read while ICMP echoes run.
const pingPoll = 200 * time.Millisecond

// pingOptions parameterises runPing.
type pingOptions struct {
	socket string
	peer   string
	count  int
	asJSON bool
}

// runPing asks the daemon to establish a path to the peer (which
// forces probing on an idle one), prints every path change it sees,
// sends count ICMP echoes with the system ping and ends with the
// settled path. Exit 0 needs a usable path (direct, relay or via the
// hub) and, when echoes were sent, at least one reply.
func runPing(ctx context.Context, out, errOut io.Writer, o pingOptions) error {
	lc := client.NewLocalClient(o.socket)
	before, err := lc.Status(ctx)
	if err != nil {
		return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
	}
	last := peerPath(before, o.peer)
	res, err := lc.Ping(ctx, o.peer)
	if err != nil {
		var le *client.LocalError
		if errors.As(err, &le) {
			return &exitError{code: exitConfigError, err: err}
		}
		return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
	}
	settled := pathColumn(client.PeerStatus{Path: res.State, PathEndpoint: res.Endpoint})
	if !o.asJSON {
		if _, err := fmt.Fprintf(out, "path: %s → %s\n", dash(last), settled); err != nil {
			return err
		}
	}
	last = settled

	replied := true
	if ip := peerIPv4(before, o.peer); o.count > 0 && ip != "" {
		replied, last, err = echo(ctx, out, errOut, lc, o, ip, last)
		if err != nil {
			return err
		}
	}

	final, err := lc.Status(ctx)
	if err != nil {
		return &exitError{code: exitNotRunning, err: fmt.Errorf("thawr client is not running (%w)", err)}
	}
	state, endpoint := "", ""
	for _, p := range final.Peers {
		if p.Name == o.peer {
			state, endpoint = p.Path, p.PathEndpoint
		}
	}
	if now := peerPath(final, o.peer); now != last && !o.asJSON {
		if _, err := fmt.Fprintf(out, "path: %s → %s\n", last, now); err != nil {
			return err
		}
	}
	if o.asJSON {
		if err := printJSON(out, client.PathResult{Peer: o.peer, State: state, Endpoint: endpoint}); err != nil {
			return err
		}
	}
	if state != "direct" && state != "relay" && state != client.PathHub {
		return &exitError{code: exitNotConnected, err: fmt.Errorf("no path to %s (%s)", o.peer, dash(state))}
	}
	if !replied {
		return &exitError{code: exitNotConnected, err: fmt.Errorf("no echo reply from %s over %s", o.peer, state)}
	}
	return nil
}

// echo runs the system ping against ip while polling the path, printing
// changes as they happen. It reports whether any echo was answered and
// the last path printed.
func echo(ctx context.Context, out, errOut io.Writer, lc *client.LocalClient, o pingOptions, ip, last string) (replied bool, lastPath string, err error) {
	bin, err := exec.LookPath("ping")
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "thawr: no ping binary found; path checked, no echo sent")
		return true, last, nil
	}
	countFlag := "-c"
	if runtime.GOOS == "windows" {
		countFlag = "-n"
	}
	cmd := exec.CommandContext(ctx, bin, countFlag, strconv.Itoa(o.count), ip) //nolint:gosec // fixed binary, numeric count, validated address
	cmd.Stdout, cmd.Stderr = out, errOut
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	ticker := time.NewTicker(pingPoll)
	defer ticker.Stop()
	for {
		select {
		case runErr := <-done:
			var ee *exec.ExitError
			if runErr != nil && !errors.As(runErr, &ee) {
				return false, last, fmt.Errorf("run ping: %w", runErr)
			}
			return runErr == nil, last, nil
		case <-ticker.C:
			st, err := lc.Status(ctx)
			if err != nil {
				continue
			}
			if now := peerPath(st, o.peer); now != last {
				if _, err := fmt.Fprintf(out, "path: %s → %s\n", last, now); err != nil {
					return false, last, err
				}
				last = now
			}
		}
	}
}

// peerPath renders the peer's PATH column, or "" when it is unknown.
func peerPath(st client.Status, name string) string {
	for _, p := range st.Peers {
		if p.Name == name {
			return pathColumn(p)
		}
	}
	return ""
}

func peerIPv4(st client.Status, name string) string {
	for _, p := range st.Peers {
		if p.Name == name {
			return p.IPv4
		}
	}
	return ""
}
