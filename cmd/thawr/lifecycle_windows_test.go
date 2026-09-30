package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// runHandler starts Execute and consumes its StartPending and Running
// reports.
func runHandler(t *testing.T, h *serviceHandler) (chan svc.ChangeRequest, chan svc.Status, chan uint32) {
	t.Helper()
	requests := make(chan svc.ChangeRequest)
	status := make(chan svc.Status, 8)
	exit := make(chan uint32, 1)
	go func() {
		_, code := h.Execute(nil, requests, status)
		exit <- code
	}()
	for _, want := range []svc.State{svc.StartPending, svc.Running} {
		if got := (<-status).State; got != want {
			t.Fatalf("state %v, want %v", got, want)
		}
	}
	return requests, status, exit
}

// TestServiceHandlerWorkEnds: `client down` ends the work without a
// stop request; the handler returns, which reports Stopped, instead of
// leaving the process to exit while it is reported Running.
func TestServiceHandlerWorkEnds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want uint32
	}{{nil, 0}, {context.Canceled, 0}, {errors.New("boom"), 1}} {
		h := newServiceHandler(func() {})
		_, _, exit := runHandler(t, h)
		h.finish(serviceExitCode(tc.err))
		select {
		case code := <-exit:
			if code != tc.want {
				t.Errorf("err %v: exit code %d, want %d", tc.err, code, tc.want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("err %v: handler did not return", tc.err)
		}
	}
}

// TestServiceHandlerStopWaitsForWork: a stop request cancels the work
// and reports StopPending; Stopped follows only once the work ended.
func TestServiceHandlerStopWaitsForWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	h := newServiceHandler(cancel)
	requests, status, exit := runHandler(t, h)

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if got := (<-status).State; got != svc.StopPending {
		t.Fatalf("state after stop %v, want StopPending", got)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel the work")
	}
	select {
	case <-exit:
		t.Fatal("handler reported Stopped before the work ended")
	default:
	}
	cur := svc.Status{State: svc.StopPending}
	requests <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: cur}
	if got := <-status; got.State != svc.StopPending {
		t.Errorf("interrogate while stopping: %v", got.State)
	}
	h.finish(0)
	select {
	case code := <-exit:
		if code != 0 {
			t.Errorf("exit code %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after the work ended")
	}
}
