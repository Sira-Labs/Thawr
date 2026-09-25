package server

import (
	"io"
	"log/slog"
	"strings"

	"github.com/sira-labs/thawr/internal/config"
)

// NewLogger builds the slog logger described by cfg, writing to w.
func NewLogger(cfg config.Log, w io.Writer) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
