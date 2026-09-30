//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// lifecycleContext ends the returned context on SIGINT or SIGTERM. The
// returned function takes the work's result, which only the Windows
// service variant reports.
func lifecycleContext(ctx context.Context) (context.Context, func(error)) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return ctx, func(error) { stop() }
}
