// Package metrics writes the Prometheus text exposition format 0.0.4
// (spec 014) without a client library: the server builds the families on
// each scrape from counters it already keeps, and Write renders them.
// Label values come from fixed sets chosen by the caller; nothing here
// ever names a peer, a user, a key or an address.
package metrics

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Metric types.
const (
	Counter = "counter"
	Gauge   = "gauge"
)

// ContentType is the exposition format's media type.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

var nameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
var labelRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Label is one name/value pair.
type Label struct {
	Name, Value string
}

// Sample is one value of a family, with its labels.
type Sample struct {
	Labels []Label
	Value  float64
}

// Family is a metric with its help text, type and samples.
type Family struct {
	Name    string
	Help    string
	Type    string
	Samples []Sample
}

// Write renders families sorted by name. It fails on an invalid metric
// or label name, so a typo never reaches a scraper.
func Write(w io.Writer, fams []Family) error {
	sorted := append([]Family(nil), fams...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, f := range sorted {
		if !nameRe.MatchString(f.Name) {
			return fmt.Errorf("metrics: invalid name %q", f.Name)
		}
		if f.Type != Counter && f.Type != Gauge {
			return fmt.Errorf("metrics: %s: invalid type %q", f.Name, f.Type)
		}
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Type)
		for _, s := range f.Samples {
			b.WriteString(f.Name)
			if len(s.Labels) > 0 {
				b.WriteByte('{')
				for i, l := range s.Labels {
					if !labelRe.MatchString(l.Name) {
						return fmt.Errorf("metrics: %s: invalid label %q", f.Name, l.Name)
					}
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, "%s=\"%s\"", l.Name, escapeValue(l.Value))
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(formatValue(s.Value))
			b.WriteByte('\n')
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Collector produces the families for one scrape.
type Collector func(ctx context.Context) ([]Family, error)

// Handler serves GET /metrics from collect; other methods get 405.
func Handler(collect Collector, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fams, err := collect(r.Context())
		if err != nil {
			log.Error("metrics: collect", "err", err)
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		if err := Write(&b, fams); err != nil {
			log.Error("metrics: write", "err", err)
			http.Error(w, "metrics unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, b.String())
	})
}
