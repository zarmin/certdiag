package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func rk(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

// TestCheckView_FilterTakesPrecedence verifies the fix: while the check-view
// filter is active, command keys (s, digits, q, ?, /) are typed into the filter
// instead of triggering their commands, so terms like "sha1" can be entered.
func TestCheckView_FilterTakesPrecedence(t *testing.T) {
	m := RootModel{width: 100, height: 40}
	m.checkView.filterActive = true
	sortBefore := m.checkView.sortMode
	minSevBefore := m.checkView.minSeverity

	var mm tea.Model = m
	for _, r := range "sha1" {
		var cmd tea.Cmd
		mm, cmd = mm.(RootModel).handleCheckViewKey(rk(r))
		if cmd != nil {
			if _, isQuit := cmd().(tea.QuitMsg); isQuit {
				t.Fatalf("typing %q quit the app while filtering", r)
			}
		}
	}
	rm := mm.(RootModel)
	if rm.checkView.filterText != "sha1" {
		t.Fatalf("filter text = %q, want \"sha1\"", rm.checkView.filterText)
	}
	if rm.checkView.sortMode != sortBefore {
		t.Errorf("sortMode changed while filtering (%d -> %d)", sortBefore, rm.checkView.sortMode)
	}
	if rm.checkView.minSeverity != minSevBefore {
		t.Errorf("minSeverity changed while filtering (digit hijacked)")
	}

	// 'q' must be typed, not quit.
	mm, cmd := rm.handleCheckViewKey(rk('q'))
	if cmd != nil {
		if _, isQuit := cmd().(tea.QuitMsg); isQuit {
			t.Fatal("'q' quit the app while filtering")
		}
	}
	rm = mm.(RootModel)
	if rm.checkView.filterText != "sha1q" {
		t.Errorf("filter text = %q, want \"sha1q\"", rm.checkView.filterText)
	}

	// Backspace edits the filter.
	mm, _ = rm.handleCheckViewKey(tea.KeyMsg{Type: tea.KeyBackspace})
	rm = mm.(RootModel)
	if rm.checkView.filterText != "sha1" {
		t.Errorf("after backspace filter = %q, want \"sha1\"", rm.checkView.filterText)
	}

	// Esc exits the filter (special key falls through to the command switch).
	mm, _ = rm.handleCheckViewKey(tea.KeyMsg{Type: tea.KeyEsc})
	rm = mm.(RootModel)
	if rm.checkView.filterActive {
		t.Error("Esc did not exit the filter")
	}
}

// TestCheckView_FilterAcceptsMultibyteRunes verifies that multibyte runes (é,
// 中) are typed into the check-view filter instead of being dropped by the old
// len(key)==1 byte gate.
func TestCheckView_FilterAcceptsMultibyteRunes(t *testing.T) {
	m := RootModel{width: 100, height: 40}
	m.checkView.filterActive = true

	var mm tea.Model = m
	for _, r := range "é中a" {
		mm, _ = mm.(RootModel).handleCheckViewKey(rk(r))
	}
	rm := mm.(RootModel)
	if rm.checkView.filterText != "é中a" {
		t.Fatalf("filter text = %q, want %q (multibyte runes must be accepted)", rm.checkView.filterText, "é中a")
	}

	// Backspace removes the trailing ASCII byte.
	mm, _ = rm.handleCheckViewKey(tea.KeyMsg{Type: tea.KeyBackspace})
	rm = mm.(RootModel)
	if rm.checkView.filterText != "é中" {
		t.Fatalf("after backspace filter = %q, want %q", rm.checkView.filterText, "é中")
	}
}

// TestCheckView_CommandsWorkWhenNotFiltering is the regression guard: with the
// filter inactive, command keys still work (e.g. 's' toggles sort).
func TestCheckView_CommandsWorkWhenNotFiltering(t *testing.T) {
	m := RootModel{width: 100, height: 40}
	m.checkView.filterActive = false
	before := m.checkView.sortMode
	mm, _ := m.handleCheckViewKey(rk('s'))
	if mm.(RootModel).checkView.sortMode == before {
		t.Error("'s' did not toggle sort when filter inactive")
	}
}
