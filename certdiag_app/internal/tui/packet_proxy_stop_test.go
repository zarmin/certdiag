package tui

import (
	"runtime"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

func settleGoroutines(target int) int {
	last := runtime.NumGoroutine()
	for i := 0; i < 200; i++ {
		runtime.GC()
		last = runtime.NumGoroutine()
		if last <= target {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	return last
}

func TestStopProxy_DoesNotLeakWaitForSessionGoroutine(t *testing.T) {
	pa := newPacketAnalyzerModel()
	pa.proxyListen = "127.0.0.1:0"
	pa.proxyTarget = "127.0.0.1:0"
	pa.proxyTracker = &session.Tracker{}

	baseline := settleGoroutines(0)

	const cycles = 10
	for i := 0; i < cycles; i++ {
		msg, ok := pa.startProxy()().(ProxyStartMsg)
		if !ok || msg.Err != nil {
			t.Fatalf("startProxy cycle %d: ok=%v err=%v", i, ok, msg.Err)
		}
		pa.proxy = msg.Proxy
		pa.state = packetProxyRunning

		// Schedule the blocking receiver exactly as handleProxyStart does.
		// Capture the cmd on this goroutine so it binds the current stopCh.
		wfs := pa.waitForSession()
		go wfs()

		pa.stopProxy()
	}

	after := settleGoroutines(baseline)
	if after > baseline {
		t.Fatalf("goroutine leak: baseline=%d after=%d (%d stranded waitForSession receivers)",
			baseline, after, after-baseline)
	}
}
