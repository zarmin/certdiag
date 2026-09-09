package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/proxy"
)

func TestDumpConfirm_EscFromProxyRunningRestoresProxy(t *testing.T) {
	pa := &packetAnalyzerModel{state: packetDumpConfirm, height: 24, width: 120}
	pa.proxy = &proxy.Proxy{}
	pa.dumpDir = t.TempDir()
	m := RootModel{packetAnalyzer: pa}

	m2, _ := m.handlePacketAnalyzerKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := m2.(RootModel).packetAnalyzer.state
	if got != packetProxyRunning {
		t.Fatalf("Esc from dump-confirm with running proxy: state=%v, want packetProxyRunning", got)
	}
}

func TestDumpConfirm_EnterFromProxyRunningRestoresProxy(t *testing.T) {
	pa := &packetAnalyzerModel{state: packetDumpConfirm, height: 24, width: 120}
	pa.proxy = &proxy.Proxy{}
	pa.dumpDir = t.TempDir()
	m := RootModel{packetAnalyzer: pa}

	m2, _ := m.handlePacketAnalyzerKey(tea.KeyMsg{Type: tea.KeyEnter})
	got := m2.(RootModel).packetAnalyzer.state
	if got != packetProxyRunning {
		t.Fatalf("Enter from dump-confirm with running proxy: state=%v, want packetProxyRunning", got)
	}
}

func TestDumpConfirm_EscFromSessionsRestoresSessions(t *testing.T) {
	pa := &packetAnalyzerModel{state: packetDumpConfirm, height: 24, width: 120}
	pa.proxyListen = "127.0.0.1:0"
	pa.dumpDir = t.TempDir()
	m := RootModel{packetAnalyzer: pa}

	m2, _ := m.handlePacketAnalyzerKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := m2.(RootModel).packetAnalyzer.state
	if got != packetSessions {
		t.Fatalf("Esc from dump-confirm without proxy: state=%v, want packetSessions", got)
	}
}
