package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
)

// stopReportTimeout bounds how long the process waits, after its work
// ended, for the control manager to take the Stopped report.
const stopReportTimeout = 10 * time.Second

// lifecycleContext ends the returned context on Ctrl-C in a console, or
// on a stop or shutdown request when running as a Windows service.
//
// The returned function must be called with the work's result before
// the process exits. As a service it reports Stopped to the control
// manager first: a service process that exits while still reported as
// Running counts as a crash, and the manager restarts it, so `thawr
// client down` would not stick. A failed run reports a non-zero exit
// code, which the manager treats as a failure to recover from.
func lifecycleContext(ctx context.Context) (context.Context, func(error)) {
	if isService, err := svc.IsWindowsService(); err != nil || !isService {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
		return ctx, func(error) { stop() }
	}
	ctx, cancel := context.WithCancel(ctx)
	h := newServiceHandler(cancel)
	ran := make(chan struct{})
	go func() {
		defer close(ran)
		// A dispatcher error means the control manager will not talk
		// to us, so stop rather than hang.
		if err := svc.Run("thawr", h); err != nil {
			cancel()
		}
	}()
	return ctx, func(err error) {
		cancel()
		h.finish(serviceExitCode(err))
		select {
		case <-ran:
		case <-time.After(stopReportTimeout):
		}
	}
}

// serviceExitCode is the service-specific exit code for the work's
// result: 0 for a clean stop, 1 for a failure.
func serviceExitCode(err error) uint32 {
	if err == nil || errors.Is(err, context.Canceled) {
		return 0
	}
	return 1
}

// serviceHandler reports Running, cancels the process context on Stop
// or Shutdown, and reports Stopped only once the work has ended.
type serviceHandler struct {
	cancel func()
	// done carries the exit code once the work has ended.
	done chan uint32
}

func newServiceHandler(cancel func()) *serviceHandler {
	return &serviceHandler{cancel: cancel, done: make(chan uint32, 1)}
}

// finish hands the exit code to Execute. It never blocks: if the
// dispatcher never ran, nobody reads it.
func (h *serviceHandler) finish(code uint32) {
	select {
	case h.done <- code:
	default:
	}
}

// Execute implements svc.Handler.
func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case code := <-h.done:
			// The work ended on its own (`client down`, a failure) or
			// after a stop request; returning reports Stopped.
			return true, code
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopReportTimeout / time.Millisecond)}
				h.cancel()
			}
		}
	}
}
