package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

func newAdminClient(socket string) *adminClient {
	return &adminClient{http: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
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
	req, err := http.NewRequestWithContext(ctx, method, "http://thawr"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) {
			return fmt.Errorf("cannot reach the thawr server admin socket (%w); is `thawr server` running and are you allowed to access it?", err)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return &apiError{Status: resp.StatusCode, Message: e.Error}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
