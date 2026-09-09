package tui

import (
	"strings"
	"testing"
)

// RenderHintBar: one row, body trimmed by priority, tail and status kept.

func TestHintBar_TreeFooterIsOneRowAt80Columns(t *testing.T) {
	m := makeLoadedModel(t)
	hints, status := m.treeFooterHints()
	bar, h := RenderHintBar(80, hints, status...)
	if h != 1 {
		t.Fatalf("height %d, want 1:\n%s", h, bar)
	}
	if !strings.HasSuffix(strings.TrimRight(bar, " "), "[?] Help  [q] Quit") {
		t.Errorf("the tail must survive trimming, got:\n%s", bar)
	}
	if !strings.Contains(bar, "[Enter] Details") {
		t.Errorf("the first hint has the highest priority and must survive, got:\n%s", bar)
	}
	wide, _ := RenderHintBar(400, hints, status...)
	for _, hint := range hints {
		if !strings.Contains(wide, formatHint(hint)) {
			t.Errorf("at 400 columns every hint fits, missing %q", formatHint(hint))
		}
	}
}

func TestHintBar_TailAndStatusOutliveTheBody(t *testing.T) {
	hints := []Hint{{"Enter", "Details"}, {"/", "Search"}, {"W", "Checks"}, {"?", "Help"}, {"q", "Quit"}}
	status := []StatusHint{{"(incomplete scan)"}}
	bar, h := RenderHintBar(46, hints, status...)
	if h != 1 {
		t.Fatalf("height %d, want 1:\n%s", h, bar)
	}
	for _, want := range []string{"[?] Help", "[q] Quit", "(incomplete scan)"} {
		if !strings.Contains(bar, want) {
			t.Errorf("missing %q in:\n%s", want, bar)
		}
	}
	if strings.Contains(bar, "[W] Checks") {
		t.Errorf("the last body hint goes first, got:\n%s", bar)
	}
	tiny, h := RenderHintBar(12, hints, status...)
	if h < 2 {
		t.Errorf("when not even the tail fits the bar wraps, got %d row(s):\n%s", h, tiny)
	}
}
