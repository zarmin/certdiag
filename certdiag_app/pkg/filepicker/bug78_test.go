package filepicker

import (
	"fmt"
	"strings"
	"testing"
)

// (A) The highlighted completion row must never be hidden behind the "↓ N more"
// indicator. Drive keyDown across a list longer than the viewport and assert the
// cursor's entry stays rendered at every position.
func TestPathModal_CursorNeverHiddenByMoreIndicator(t *testing.T) {
	comps := make([]string, 10)
	for i := range comps {
		comps[i] = fmt.Sprintf("/base/dir%02d", i)
	}

	m := pickerModel{termW: 100, termH: 30}
	m.pathMod.input = newSimpleInput()
	m.modal = modalPath
	m.pathMod.completions = comps
	m.pathMod.dropCursor = -1
	m.pathMod.dropScroll = 0

	for step := 0; step < len(comps); step++ {
		m = sendKey(m, "down")
		cursorName := fmt.Sprintf("dir%02d", m.pathMod.dropCursor)
		view := m.renderPathModal()
		if !strings.Contains(view, cursorName) {
			t.Fatalf("cursor %d (%s) hidden: dropScroll=%d, not rendered", m.pathMod.dropCursor, cursorName, m.pathMod.dropScroll)
		}
		// The highlighted row must not coincide with the reserved indicator row.
		remaining := len(comps) - (m.pathMod.dropScroll + dropMaxH)
		row := m.pathMod.dropCursor - m.pathMod.dropScroll
		if row < 0 || row >= dropMaxH {
			t.Fatalf("cursor %d outside window: row=%d", m.pathMod.dropCursor, row)
		}
		if row == dropMaxH-1 && remaining > 0 {
			t.Fatalf("cursor %d on indicator row while %d remain", m.pathMod.dropCursor, remaining)
		}
	}
}

// (B) In non-multiSelect search mode, space must be typed into the query rather
// than swallowed as a select toggle.
func TestSearchMode_SpaceAppendedToQuery(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	m = sendKey(m, "/") // enter search mode
	if !m.searchMode {
		t.Fatal("slash should enter search mode")
	}
	m = sendKey(m, "a")
	m = sendKey(m, " ")
	m = sendKey(m, "b")

	if m.searchQuery != "a b" {
		t.Errorf("searchQuery=%q, want %q", m.searchQuery, "a b")
	}
	if !strings.Contains(m.searchQuery, " ") {
		t.Error("space should be appended to search query, not swallowed")
	}
}

// (C) commitPath trims trailing slashes for normal directories but preserves
// filesystem roots ("/" and drive roots like "C:/").
func TestTrimTrailingSlash(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"C:/", "C:/"},
		{"/", "/"},
		{"/foo/bar/", "/foo/bar"},
		{"/foo/bar", "/foo/bar"},
		{"C:/Users/", "C:/Users"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := trimTrailingSlash(tt.in); got != tt.want {
			t.Errorf("trimTrailingSlash(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}
}
