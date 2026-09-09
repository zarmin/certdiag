package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func maxLineWidth(lines []string) int {
	m := 0
	for _, l := range lines {
		if w := runeWidth(l); w > m {
			m = w
		}
	}
	return m
}

func TestCheckView_ResizeUpdatesDimensions(t *testing.T) {
	m := makeLoadedModel(t)

	m = sendKey(m, "W")
	if m.state != stateCheckView {
		t.Fatalf("expected stateCheckView, got %d", m.state)
	}

	res, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 60})
	rm := res.(RootModel)

	if rm.checkView.width != 200 {
		t.Errorf("checkView width = %d, want 200", rm.checkView.width)
	}
	if rm.checkView.height != 60 {
		t.Errorf("checkView height = %d, want 60", rm.checkView.height)
	}
}

func TestCheckCatalog_ResizeRetruncatesLines(t *testing.T) {
	m := makeLoadedModel(t)

	// Shrink first so the catalog is created at a narrow, pre-truncated width.
	res, _ := m.Update(tea.WindowSizeMsg{Width: 50, Height: 20})
	m = res.(RootModel)

	m = sendKey(m, "W")
	m = sendKey(m, "c")
	if m.state != stateCheckCatalog || m.checkCatalog == nil {
		t.Fatalf("expected open catalog, got state=%d catalog=%v", m.state, m.checkCatalog)
	}

	narrowMax := maxLineWidth(m.checkCatalog.lines)
	if narrowMax > 50 {
		t.Fatalf("narrow catalog line exceeds width 50: got %d", narrowMax)
	}

	res, _ = m.Update(tea.WindowSizeMsg{Width: 200, Height: 60})
	rm := res.(RootModel)

	if rm.checkCatalog.width != 200 {
		t.Errorf("catalog width = %d, want 200", rm.checkCatalog.width)
	}
	if rm.checkCatalog.height != 60 {
		t.Errorf("catalog height = %d, want 60", rm.checkCatalog.height)
	}

	wideMax := maxLineWidth(rm.checkCatalog.lines)
	if wideMax <= narrowMax {
		t.Errorf("catalog lines not re-truncated after resize: narrowMax=%d wideMax=%d", narrowMax, wideMax)
	}
}
