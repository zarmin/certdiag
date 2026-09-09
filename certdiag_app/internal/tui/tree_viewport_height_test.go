package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func physicalLines(s string) int {
	return strings.Count(s, "\n") + 1
}

// TestTreeViewFitsTerminalHeight: at 80x24 the footer is one row (the hint bar
// trims itself instead of wrapping) and the tree viewport is derived from it.
func TestTreeViewFitsTerminalHeight(t *testing.T) {
	m := makeLoadedModel(t)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}

	const width = 80
	const height = 24

	result, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m = result.(RootModel)

	hints, status := m.treeFooterHints()
	_, footerH := RenderHintBar(width, hints, status...)
	if footerH != 1 {
		t.Fatalf("expected a one-row hint bar at width %d, got %d rows", width, footerH)
	}

	if want := height - 2 - footerH; m.tree.viewportHeight != want {
		t.Fatalf("viewportHeight = %d, want %d (height-2-footerH, derived from RenderHintBar)", m.tree.viewportHeight, want)
	}

	if got := physicalLines(m.View()); got > height {
		t.Fatalf("no-error view overruns terminal: %d lines > height %d", got, height)
	}

	m.err = errors.New("boom")
	if got := physicalLines(m.View()); got > height {
		t.Fatalf("error view overruns terminal: %d lines > height %d", got, height)
	}
}
