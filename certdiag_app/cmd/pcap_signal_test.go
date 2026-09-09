package cmd

import (
	"os"
	"testing"
	"time"
)

// TestStopOnSignal verifies a received signal closes the stop channel.
func TestStopOnSignal(t *testing.T) {
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	defer close(done)
	stop := make(chan struct{})
	go stopOnSignal(sig, done, stop)

	sig <- os.Interrupt
	select {
	case <-stop:
	case <-time.After(2 * time.Second):
		t.Fatal("stop channel not closed after signal")
	}
}

// TestStopOnSignalDoneExits verifies the watcher exits via done without
// closing stop, so a capture ending by --count/--duration does not leak the
// goroutine blocked on the signal channel.
func TestStopOnSignalDoneExits(t *testing.T) {
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		stopOnSignal(sig, done, stop)
		close(exited)
	}()

	close(done)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not exit when done closed")
	}
	select {
	case <-stop:
		t.Fatal("stop closed without a signal")
	default:
	}
}
