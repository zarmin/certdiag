package tui

import (
	"testing"
)

// TestStatusGen_StaleTickIgnored reproduces the overlapping notify timer bug:
// status A schedules a clear tick, then status B is shown before A's tick fires.
// The stale tick (gen A) must NOT clear B; only the current-gen tick clears it.
func TestStatusGen_StaleTickIgnored(t *testing.T) {
	initStyles()

	m := RootModel{}

	m.notify(notifyInfo, "A")
	genA := m.statusGen

	m.notify(notifyInfo, "B")
	genB := m.statusGen

	if genA == genB {
		t.Fatalf("expected statusGen to advance between notifications, got %d twice", genA)
	}

	updated, _ := m.Update(statusClearMsg{gen: genA})
	m = updated.(RootModel)
	if m.statusMessage != "B" {
		t.Fatalf("stale clear tick cleared newer status: got %q, want %q", m.statusMessage, "B")
	}

	updated, _ = m.Update(statusClearMsg{gen: genB})
	m = updated.(RootModel)
	if m.statusMessage != "" {
		t.Fatalf("current clear tick did not clear status: got %q", m.statusMessage)
	}
	if m.statusTransient {
		t.Fatal("statusTransient still set after current clear tick")
	}
}
