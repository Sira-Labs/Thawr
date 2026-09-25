package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"testing/fstest"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	thawrv1 "github.com/sira-labs/thawr/internal/api/proto/thawr/v1"
	"github.com/sira-labs/thawr/internal/control"
	"github.com/sira-labs/thawr/internal/store"
)

type fakeEnroller struct {
	err  error
	last control.EnrollRequest
}

func (f *fakeEnroller) Enroll(_ context.Context, req control.EnrollRequest) (control.EnrollResult, error) {
	f.last = req
	if f.err != nil {
		return control.EnrollResult{}, f.err
	}
	return control.EnrollResult{
		Peer:       store.Peer{ID: "p1", Name: "laptop", IPv4: "100.64.0.2"},
		NodeSecret: "node-secret",
		Generation: 7,
	}, nil
}

func testHub() HubInfo {
	return HubInfo{PublicKey: "hubkey", Endpoint: "vpn.example.com:51820", Overlay: netip.MustParsePrefix("100.64.0.0/10")}
}

func bufconnClient(t *testing.T, srv *grpc.Server) thawrv1.ControlClient {
	t.Helper()
	ln := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return ln.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return thawrv1.NewControlClient(conn)
}

func TestEnrollRPCMapsFields(t *testing.T) {
	fe := &fakeEnroller{}
	srv, err := NewGRPC(GRPCDeps{Enroller: fe, Hub: testHub(), Version: "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	client := bufconnClient(t, srv)
	resp, err := client.Enroll(context.Background(), &thawrv1.EnrollRequest{
		Token: "thawr_x", PublicKey: "pk", Hostname: "host", Os: "linux", Arch: "arm64", ClientVersion: "0.1.0", Name: "n",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if fe.last.Token != "thawr_x" || fe.last.PublicKey != "pk" || fe.last.Hostname != "host" || fe.last.OS != "linux" ||
		fe.last.Arch != "arm64" || fe.last.ClientVersion != "0.1.0" || fe.last.Name != "n" {
		t.Errorf("request not mapped: %+v", fe.last)
	}
	if fe.last.RemoteIP == "" {
		t.Error("remote ip not extracted from peer info")
	}
	if resp.GetPeerId() != "p1" || resp.GetName() != "laptop" || resp.GetIpv4() != "100.64.0.2" || resp.GetNodeSecret() != "node-secret" ||
		resp.GetOverlayCidr() != "100.64.0.0/10" || resp.GetHubPublicKey() != "hubkey" || resp.GetHubEndpoint() != "vpn.example.com:51820" ||
		resp.GetServerVersion() != "1.2.3" || resp.GetNetmapGeneration() != 7 {
		t.Errorf("response not mapped: %+v", resp)
	}
}

func TestEnrollRPCErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		code codes.Code
		msg  string
	}{
		{control.ErrInvalidToken, codes.PermissionDenied, "invalid token"},
		{errors.Join(control.ErrValidation, errors.New("public_key bad")), codes.InvalidArgument, ""},
		{control.ErrRateLimited, codes.ResourceExhausted, "too many attempts"},
		{control.ErrVersion, codes.FailedPrecondition, ""},
		{control.ErrExhausted, codes.ResourceExhausted, "no free overlay address"},
		{errors.New("db exploded"), codes.Internal, "internal error"},
	}
	for _, c := range cases {
		t.Run(c.code.String(), func(t *testing.T) {
			srv, err := NewGRPC(GRPCDeps{Enroller: &fakeEnroller{err: c.err}, Hub: testHub()})
			if err != nil {
				t.Fatal(err)
			}
			client := bufconnClient(t, srv)
			_, err = client.Enroll(context.Background(), &thawrv1.EnrollRequest{Token: "t"})
			st, ok := status.FromError(err)
			if !ok || st.Code() != c.code {
				t.Fatalf("got %v, want code %s", err, c.code)
			}
			if c.msg != "" && st.Message() != c.msg {
				t.Errorf("message %q, want %q", st.Message(), c.msg)
			}
			if st.Code() == codes.Internal && st.Message() != "internal error" {
				t.Errorf("internal error leaked: %q", st.Message())
			}
		})
	}
}

func TestNewGRPCRequiresEnroller(t *testing.T) {
	if _, err := NewGRPC(GRPCDeps{}); err == nil {
		t.Error("expected error without enroller")
	}
}

// TestCombineServesBothOnTLS runs gRPC and REST through one TLS HTTP/2
// server, as the production listener does.
func TestCombineServesBothOnTLS(t *testing.T) {
	grpcSrv, err := NewGRPC(GRPCDeps{Enroller: &fakeEnroller{}, Hub: testHub()})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := NewREST(RESTDeps{Status: fakeStatus{st: Status{Version: "x"}}, UI: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("Thawr")}}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(Combine(grpcSrv, rest))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	httpClient := ts.Client()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("REST over TLS: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("REST status %d", resp.StatusCode)
	}

	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.NewClient(ts.Listener.Addr().String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	out, err := thawrv1.NewControlClient(conn).Enroll(context.Background(), &thawrv1.EnrollRequest{Token: "t"})
	if err != nil {
		t.Fatalf("gRPC over TLS via Combine: %v", err)
	}
	if out.GetName() != "laptop" {
		t.Errorf("unexpected response %+v", out)
	}
}
