package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func newDirtyPacketForm(t *testing.T) RootModel {
	t.Helper()
	m := RootModel{
		state:          statePacketForm,
		activeForm:     buildProxyForm("", "", false),
		activeFormKind: formProxySetup,
	}
	m.activeForm.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	if !m.activeForm.isDirty() {
		t.Fatalf("form should be dirty after typing")
	}
	return m
}

func TestPacketForm_DirtyEscShowsDiscardConfirm(t *testing.T) {
	m := newDirtyPacketForm(t)

	m2, _ := m.handlePacketFormKey(tea.KeyMsg{Type: tea.KeyEsc})
	rm := m2.(RootModel)

	if !rm.confirmDiscard {
		t.Fatalf("dirty Esc must show discard confirm")
	}
	if rm.activeForm == nil {
		t.Fatalf("dirty Esc must not discard the form")
	}
	if rm.state != statePacketForm {
		t.Fatalf("state = %v, want statePacketForm while confirming", rm.state)
	}

	m3, _ := rm.handlePacketFormKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	rm2 := m3.(RootModel)
	if rm2.confirmDiscard {
		t.Fatalf("confirm must clear confirmDiscard")
	}
	if rm2.activeForm != nil {
		t.Fatalf("confirming discard must drop the form")
	}
	if rm2.state != statePacketAnalyzer {
		t.Fatalf("state = %v, want statePacketAnalyzer after discard", rm2.state)
	}
}

func TestPacketForm_CleanEscClosesDirectly(t *testing.T) {
	m := RootModel{
		state:          statePacketForm,
		activeForm:     buildProxyForm("", "", false),
		activeFormKind: formProxySetup,
	}

	m2, _ := m.handlePacketFormKey(tea.KeyMsg{Type: tea.KeyEsc})
	rm := m2.(RootModel)

	if rm.confirmDiscard {
		t.Fatalf("clean Esc must not show discard confirm")
	}
	if rm.activeForm != nil {
		t.Fatalf("clean Esc must close the form")
	}
	if rm.state != statePacketAnalyzer {
		t.Fatalf("state = %v, want statePacketAnalyzer", rm.state)
	}
}
