package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestRemoteForm_QIsTypedNotQuit verifies the fix: pressing 'q' in the remote
// fetch form's focused text input types the character instead of quitting, while
// ctrl+c still quits.
func TestRemoteForm_QIsTypedNotQuit(t *testing.T) {
	m := &RootModel{width: 100, height: 40}
	m.openRemoteForm()

	// 'q' must NOT quit and must reach the focused 'target' field.
	m2, cmd := m.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd != nil {
		if _, isQuit := cmd().(tea.QuitMsg); isQuit {
			t.Fatal("'q' quit the app instead of being typed")
		}
	}
	rm := m2.(RootModel)
	if got := rm.activeForm.fieldValue("target"); got != "q" {
		t.Fatalf("expected 'q' typed into target field, got %q", got)
	}

	// ctrl+c must still quit.
	_, cmd = rm.handleRemoteFormKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c did not produce a command")
	}
	if _, isQuit := cmd().(tea.QuitMsg); !isQuit {
		t.Fatal("ctrl+c did not quit")
	}
}

// TestKeyHelpers ensures isKeyCtrlC is strictly ctrl+c while isKeyQuit also
// matches bare 'q' (used only where no text input is focused).
func TestKeyHelpers(t *testing.T) {
	q := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}}
	c := tea.KeyMsg{Type: tea.KeyCtrlC}
	if isKeyCtrlC(q) {
		t.Error("isKeyCtrlC must not match 'q'")
	}
	if !isKeyCtrlC(c) {
		t.Error("isKeyCtrlC must match ctrl+c")
	}
	if !isKeyQuit(q) || !isKeyQuit(c) {
		t.Error("isKeyQuit must match both 'q' and ctrl+c")
	}
}
