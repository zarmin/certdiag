package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPopup_NonDismissKeyKeepsNoticeKind(t *testing.T) {
	m := RootModel{popup: popupState{kind: popupNotice, message: "heads up"}}

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got := m2.(RootModel).popup.kind
	if got != popupNotice {
		t.Fatalf("non-dismiss key on notice popup: kind=%v, want popupNotice", got)
	}
}

func TestPopup_NonDismissKeyKeepsErrorKind(t *testing.T) {
	m := RootModel{popup: popupState{kind: popupError, message: "boom"}}

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	got := m2.(RootModel).popup.kind
	if got != popupError {
		t.Fatalf("non-dismiss key on error popup: kind=%v, want popupError", got)
	}
}

func TestPopup_DismissKeyClosesNotice(t *testing.T) {
	m := RootModel{popup: popupState{kind: popupNotice, message: "heads up"}}

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := m2.(RootModel).popup.kind
	if got != popupNone {
		t.Fatalf("enter on notice popup: kind=%v, want popupNone", got)
	}
}
