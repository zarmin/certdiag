package filepicker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// (A) reloadDir must clamp the scroll offset after the listing shrinks so the
// viewport does not go blank. Scroll to the bottom of a long (hidden) listing,
// then hide the hidden entries and assert scroll is within the valid range.
func TestReloadDir_ClampsScrollAfterShrink(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 30; i++ {
		os.MkdirAll(filepath.Join(dir, fmt.Sprintf(".d%02d", i)), 0755)
	}
	os.MkdirAll(filepath.Join(dir, "visible"), 0755)

	cfg := &config{dialogType: TypeOpenDir, showHidden: true}
	m := makeTestModelWithConfig(t, cfg, dir)

	m = sendKey(m, "end") // cursor + scroll near the bottom of the long list
	if m.scroll == 0 {
		t.Fatalf("precondition: expected a non-zero scroll after End, got %d (entries=%d)", m.scroll, len(m.entries))
	}

	m.showHidden = false
	m.reloadDir()

	listH := m.listHeight()
	maxScroll := len(m.entries) - listH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.scroll > maxScroll {
		t.Fatalf("scroll not clamped: scroll=%d, maxScroll=%d, entries=%d, listH=%d", m.scroll, maxScroll, len(m.entries), listH)
	}

	// The viewport must not be blank: the remaining entries should render.
	view := m.View()
	if !strings.Contains(view, "visible") {
		t.Fatalf("viewport blank after shrink: 'visible' entry not rendered (scroll=%d)", m.scroll)
	}
}

// (B) The tab-complete longest-common-prefix must be a valid (case-insensitive)
// prefix of every candidate, not garbage built from a first/last comparison that
// skips a middle element under case-insensitive comparison.
func TestLongestCommonPrefix_CaseInsensitive(t *testing.T) {
	isPrefix := func(p, s string) bool {
		return strings.HasPrefix(strings.ToLower(s), strings.ToLower(p))
	}

	tests := []struct {
		name string
		in   []string
		want string
	}{
		// findings counterexample: sorted case-sensitively as [Ba, aB, bc];
		// the true case-insensitive common prefix is "".
		{"caseInsensitiveExtremeInMiddle", []string{"Ba", "aB", "bc"}, ""},
		{"sameCaseNormal", []string{"foobar", "foobaz", "fooqux"}, "foo"},
		{"caseOnlyDiff", []string{"Test", "test", "TEST"}, "Test"},
		{"single", []string{"OnlyOne"}, "OnlyOne"},
	}

	for _, tt := range tests {
		got := longestCommonPrefix(tt.in)
		if got != tt.want {
			t.Errorf("%s: longestCommonPrefix(%v)=%q, want %q", tt.name, tt.in, got, tt.want)
		}
		for _, s := range tt.in {
			if !isPrefix(got, s) {
				t.Errorf("%s: result %q is not a prefix of %q", tt.name, got, s)
			}
		}
	}
}

// (C) ctrl+h (0x08, delivered by BS-sending terminals) must behave as Backspace
// in the search and path inputs, not toggle hidden files.
func TestCtrlH_ActsAsBackspace(t *testing.T) {
	dir := setupTestDir(t)

	// Search input
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "/") // enter search mode
	m = sendKey(m, "f")
	m = sendKey(m, "i")
	if m.searchQuery != "fi" {
		t.Fatalf("setup: searchQuery=%q, want %q", m.searchQuery, "fi")
	}
	hiddenBefore := m.showHidden
	m = sendKey(m, "ctrl+h")
	if m.searchQuery != "f" {
		t.Errorf("ctrl+h did not delete a search char: searchQuery=%q, want %q", m.searchQuery, "f")
	}
	if m.showHidden != hiddenBefore {
		t.Errorf("ctrl+h toggled hidden files instead of acting as backspace")
	}

	// Path input
	m2 := makeTestModel(t, TypeOpenFile, dir)
	m2 = sendKey(m2, "ctrl+p")
	if m2.modal != modalPath {
		t.Fatalf("ctrl+p should open the path modal")
	}
	base := m2.pathMod.input.Value()
	m2 = sendKey(m2, "x")
	if m2.pathMod.input.Value() != base+"x" {
		t.Fatalf("setup: path input=%q, want %q", m2.pathMod.input.Value(), base+"x")
	}
	m2 = sendKey(m2, "ctrl+h")
	if m2.pathMod.input.Value() != base {
		t.Errorf("ctrl+h did not delete a char in path input: got %q, want %q", m2.pathMod.input.Value(), base)
	}
}

// The hidden-files toggle moved off ctrl+h onto "." must still work while
// browsing the list.
func TestDotTogglesHidden(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	before := m.showHidden
	m = sendKey(m, ".")
	if m.showHidden == before {
		t.Errorf("'.' did not toggle hidden files: showHidden=%v", m.showHidden)
	}
}
