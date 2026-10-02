package metrics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	var b strings.Builder
	err := Write(&b, []Family{
		{Name: "thawr_peers", Help: "Peers by kind.", Type: Gauge, Samples: []Sample{
			{Labels: []Label{{"kind", "human"}}, Value: 3},
			{Labels: []Label{{"kind", "agent"}}, Value: 0},
		}},
		{Name: "thawr_build_info", Help: "Build, value 1.\nSecond line \\ here.", Type: Gauge, Samples: []Sample{
			{Labels: []Label{{"version", `v0.2.0 "rc" \x`}}, Value: 1},
		}},
		{Name: "thawr_relay_bytes_total", Help: "Bytes relayed.", Type: Counter, Samples: []Sample{{Value: 1.5e10}}},
		{Name: "thawr_weird", Help: "Edge values.", Type: Gauge, Samples: []Sample{{Value: math.Inf(1)}, {Value: math.NaN()}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP thawr_build_info Build, value 1.\nSecond line \\ here.
# TYPE thawr_build_info gauge
thawr_build_info{version="v0.2.0 \"rc\" \\x"} 1
# HELP thawr_peers Peers by kind.
# TYPE thawr_peers gauge
thawr_peers{kind="human"} 3
thawr_peers{kind="agent"} 0
# HELP thawr_relay_bytes_total Bytes relayed.
# TYPE thawr_relay_bytes_total counter
thawr_relay_bytes_total 1.5e+10
# HELP thawr_weird Edge values.
# TYPE thawr_weird gauge
thawr_weird +Inf
thawr_weird NaN
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestWriteRejects(t *testing.T) {
	for _, f := range []Family{
		{Name: "bad-name", Type: Gauge},
		{Name: "ok", Type: "histogram"},
		{Name: "ok", Type: Gauge, Samples: []Sample{{Labels: []Label{{"bad-label", "x"}}}}},
	} {
		if err := Write(io.Discard, []Family{f}); err == nil {
			t.Errorf("Write accepted %+v", f)
		}
	}
}

func TestHandler(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := Handler(func(context.Context) ([]Family, error) {
		return []Family{{Name: "x", Help: "x.", Type: Gauge, Samples: []Sample{{Value: 1}}}}, nil
	}, quiet)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ContentType || !strings.Contains(rec.Body.String(), "x 1\n") {
		t.Errorf("GET: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	failing := Handler(func(context.Context) ([]Family, error) { return nil, errors.New("db down") }, quiet)
	rec = httptest.NewRecorder()
	failing.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("failing collector: %d %q", rec.Code, rec.Body.String())
	}
}
