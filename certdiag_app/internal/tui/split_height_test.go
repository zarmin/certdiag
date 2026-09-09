package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func splitAuthoritativeDetailH(m RootModel) int {
	_, infoBarHeight := m.splitInfoBar()
	treeH := m.height / 2
	return m.height - treeH - 1 - infoBarHeight
}

// TestSplit_DetailBudgetMatchesRenderer: the detail budget follows the real
// footer height, whether the bar is the usual one row (80 columns) or has to
// wrap because not even its tail fits (20 columns).
func TestSplit_DetailBudgetMatchesRenderer(t *testing.T) {
	for _, tc := range []struct {
		width     int
		wantWraps bool
	}{{80, false}, {20, true}} {
		m := makeTestRootModel()
		m.width, m.height = tc.width, 40
		m.state = stateSplit
		m.focus = focusDetail

		_, infoBarHeight := m.splitInfoBar()
		if (infoBarHeight >= 2) != tc.wantWraps {
			t.Fatalf("width %d: infoBarHeight=%d, wraps=%v, want wraps=%v", tc.width, infoBarHeight, infoBarHeight >= 2, tc.wantWraps)
		}

		if got, want := m.detailPanelHeight(), splitAuthoritativeDetailH(m); got != want {
			t.Fatalf("width %d: detailPanelHeight()=%d, renderer detailH=%d (budget must match renderer)", tc.width, got, want)
		}

		m.updateTreeViewportHeight()
		if got, want := m.tree.viewportHeight, m.height/2-3; got != want {
			t.Fatalf("width %d: split tree viewportHeight=%d, renderer uses %d", tc.width, got, want)
		}
	}
}

func TestSplit_LastDetailLineReachable(t *testing.T) {
	m := makeTestRootModel()
	m.width, m.height = 80, 40
	m.state = stateSplit
	m.focus = focusDetail

	_, infoBarHeight := m.splitInfoBar()
	if infoBarHeight != 1 {
		t.Fatalf("expected a one-row hint bar at width %d, got %d rows", m.width, infoBarHeight)
	}

	innerW := detailInnerWidth(m.width, m.height)
	d := &detailModel{width: innerW, height: m.height, cursorLine: -1}
	const nLines = 40
	for i := 0; i < nLines; i++ {
		d.contentLines = append(d.contentLines, detailLine{text: fmt.Sprintf("detailline%02d", i)})
	}
	m.detail = d

	detailH := m.detailPanelHeight()
	if len(d.contentLines) <= d.visibleLines(detailH) {
		t.Fatalf("content not taller than panel: lines=%d visible=%d", len(d.contentLines), d.visibleLines(detailH))
	}

	for i := 0; i < nLines+5; i++ {
		res, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
		m = res.(RootModel)
	}

	view := m.viewSplitScreen()

	lastLine := d.contentLines[nLines-1].text
	if !strings.Contains(view, lastLine) {
		t.Fatalf("last detail line %q not reachable after scrolling to bottom (scrollOffset=%d, detailH=%d, renderer detailH=%d)",
			lastLine, d.scrollOffset, detailH, splitAuthoritativeDetailH(m))
	}

	if got := physicalLines(view); got > m.height {
		t.Fatalf("split view overruns terminal: %d lines > height %d", got, m.height)
	}
}
