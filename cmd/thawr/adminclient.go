package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sira-labs/thawr/internal/config"
)

// envAdminSocket overrides the admin socket path.
const envAdminSocket = "THAWR_ADMIN_SOCKET"

// adminClient talks to the server's local admin API over the Unix socket.
type adminClient struct {
	http *http.Client
	// long has no overall timeout, for streamed downloads (backup).
	long *http.Client
}

func newAdminClient(socket string) *adminClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &adminClient{
		http: &http.Client{Timeout: 30 * time.Second, Transport: tr},
		long: &http.Client{Transport: tr},
	}
}

func defaultAdminSocket() string {
	if s := os.Getenv(envAdminSocket); s != "" {
		return s
	}
	return filepath.Join(config.DefaultDataDir, "admin.sock")
}

// apiError is a non-2xx response from the server.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return e.Message }

// do sends a JSON request and decodes the JSON response into out.
func (c *adminClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	resp, err := c.send(ctx, c.http, method, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// stream sends a GET without the 30-second timeout and size cap of do
// and returns the response for the caller to read and close.
func (c *adminClient) stream(ctx context.Context, path string) (*http.Response, error) {
	return c.send(ctx, c.long, http.MethodGet, path, nil)
}

// send performs a request, explains a socket that did not answer, and
// turns a non-2xx response into an *apiError (closing its body).
func (c *adminClient) send(ctx context.Context, hc *http.Client, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://thawr"+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return nil, adminDialError(opErr, err)
		}
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, &apiError{Status: resp.StatusCode, Message: e.Error}
	}
	return resp, nil
}

// adminDialError explains why the admin socket did not answer. `thawr
// admin` talks to the server's local socket only, so on a laptop it
// finds nothing; that is the usual case, so it comes first.
func adminDialError(opErr *net.OpError, err error) error {
	socket := ""
	if opErr.Addr != nil {
		socket = opErr.Addr.String()
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &exitError{code: exitConfigError, err: fmt.Errorf("no thawr server admin socket at %s. `thawr admin` talks to the server on its own host: run it there (for example over ssh), or pass --socket when data_dir or admin_socket differ", socket)}
	case errors.Is(err, fs.ErrPermission):
		return &exitError{code: exitConfigError, err: fmt.Errorf("no permission to use the admin socket %s; %s", socket, elevateHint())}
	}
	return fmt.Errorf("cannot reach the thawr server admin socket (%w); is `thawr server` running?", err)
}
