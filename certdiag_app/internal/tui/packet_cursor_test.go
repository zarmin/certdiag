package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

// TestPacketAnalyzer_PgDownEmptyKeepsCursorNonNegative verifies the root-cause
// fix: PgDown on an empty session list must not drive the cursor to -1.
func TestPacketAnalyzer_PgDownEmptyKeepsCursorNonNegative(t *testing.T) {
	m := RootModel{
		packetAnalyzer: &packetAnalyzerModel{state: packetProxyRunning, height: 24, width: 120},
	}
	m2, _ := m.handlePacketAnalyzerKey(tea.KeyMsg{Type: tea.KeyPgDown})
	pa := m2.(RootModel).packetAnalyzer
	if pa.cursor < 0 {
		t.Fatalf("cursor went negative after PgDown on empty list: %d", pa.cursor)
	}
	t.Logf("cursor after PgDown on empty list: %d", pa.cursor)
}

// TestPacketAnalyzer_RenderNegativeCursorNoPanic verifies the defensive fix:
// rendering with a stale negative cursor and a session present must not panic.
func TestPacketAnalyzer_RenderNegativeCursorNoPanic(t *testing.T) {
	m := &packetAnalyzerModel{state: packetProxyRunning, height: 24, width: 120}
	m.cursor = -1 // stale negative cursor
	m.sessions = []*session.Session{{ClientAddr: "1.2.3.4:5555", ServerAddr: "93.184.216.34:443"}}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("viewSessionList panicked with negative cursor: %v", r)
		}
	}()

	_ = m.viewSessionList()
	if m.cursor < 0 || m.offset < 0 {
		t.Errorf("cursor/offset not clamped: cursor=%d offset=%d", m.cursor, m.offset)
	}
}
