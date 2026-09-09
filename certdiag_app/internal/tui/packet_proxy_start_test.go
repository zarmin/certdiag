package tui

import (
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

func TestStartProxy_MsgCarriesProxyAndUpdateApplies(t *testing.T) {
	pa := newPacketAnalyzerModel()
	pa.proxyListen = "127.0.0.1:0"
	pa.proxyTarget = "127.0.0.1:0"
	pa.proxyTracker = &session.Tracker{}

	cmd := pa.startProxy()
	if pa.proxy != nil {
		t.Fatalf("startProxy must not set m.proxy from the command goroutine")
	}

	msg, ok := cmd().(ProxyStartMsg)
	if !ok {
		t.Fatalf("startProxy cmd returned %T, want ProxyStartMsg", msg)
	}
	if msg.Err != nil {
		t.Fatalf("startProxy returned error: %v", msg.Err)
	}
	if msg.Proxy == nil {
		t.Fatalf("ProxyStartMsg must carry the started proxy")
	}
	defer msg.Proxy.Stop()

	m := RootModel{packetAnalyzer: pa}
	m2, _ := m.handleProxyStart(msg)
	rm := m2.(RootModel)
	if rm.packetAnalyzer.proxy != msg.Proxy {
		t.Fatalf("Update did not assign m.proxy from the message")
	}
	if rm.packetAnalyzer.state != packetProxyRunning {
		t.Fatalf("state = %v, want packetProxyRunning", rm.packetAnalyzer.state)
	}
}

func TestStartProxy_ErrorDoesNotSetProxy(t *testing.T) {
	pa := newPacketAnalyzerModel()
	pa.proxyListen = "127.0.0.1:99999" // invalid port -> Start fails
	pa.proxyTarget = "127.0.0.1:0"
	pa.proxyTracker = &session.Tracker{}

	msg, ok := pa.startProxy()().(ProxyStartMsg)
	if !ok {
		t.Fatalf("startProxy cmd returned %T, want ProxyStartMsg", msg)
	}
	if msg.Err == nil {
		t.Fatalf("expected an error from Start on invalid listen addr")
	}
	if msg.Proxy != nil {
		t.Fatalf("error message must not carry a proxy")
	}

	m := RootModel{packetAnalyzer: pa}
	m2, _ := m.handleProxyStart(msg)
	rm := m2.(RootModel)
	if rm.packetAnalyzer.proxy != nil {
		t.Fatalf("error path must leave m.proxy nil")
	}
	if rm.packetAnalyzer.state == packetProxyRunning {
		t.Fatalf("error path must not leave state at packetProxyRunning")
	}
}

func TestStartProxy_CmdGoroutineDoesNotRaceWithReads(t *testing.T) {
	pa := newPacketAnalyzerModel()
	pa.proxyListen = "127.0.0.1:0"
	pa.proxyTarget = "127.0.0.1:0"
	pa.proxyTracker = &session.Tracker{}

	cmd := pa.startProxy()

	var wg sync.WaitGroup
	var msg tea.Msg
	wg.Add(1)
	go func() {
		defer wg.Done()
		msg = cmd()
	}()

	// Concurrently read the fields the old code wrote from the goroutine.
	for i := 0; i < 1000; i++ {
		_ = pa.state
		_ = pa.proxy
	}
	wg.Wait()

	if pm, ok := msg.(ProxyStartMsg); ok && pm.Proxy != nil {
		pm.Proxy.Stop()
	}
}
