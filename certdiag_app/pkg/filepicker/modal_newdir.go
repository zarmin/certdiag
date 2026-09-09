package filepicker

import (
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m pickerModel) updateNewDirModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg.String() {
	case keyEsc:
		m.modal = modalNone
		return m, nil
	case keyEnter:
		name := strings.TrimSpace(m.newDirMod.input.Value())
		if name == "" {
			m.modal = modalNone
			return m, nil
		}
		newPath := filepath.Join(m.currentDir, name)
		if err := os.MkdirAll(newPath, 0755); err != nil {
			m.modal = modalAlert
			m.alert = alertState{message: "Cannot create directory: " + err.Error()}
			return m, nil
		}
		m.modal = modalNone
		m.reloadDir()
		m.setCursorToEntry(name)
		return m, nil
	default:
		m.newDirMod.input, cmd = m.newDirMod.input.Update(msg)
	}
	return m, cmd
}

func (m pickerModel) renderNewDirModal() string {
	w := 40
	textW := w - 4

	var b strings.Builder
	b.WriteString(boxTop(w) + "\n")
	b.WriteString(boxRow(styleAccent.Bold(true).Render("New Folder"), textW) + "\n")
	b.WriteString(boxSep(w) + "\n")
	b.WriteString(boxRow("", textW) + "\n")
	b.WriteString(boxRow("Folder name: "+m.newDirMod.input.View(), textW) + "\n")
	b.WriteString(boxRow("", textW) + "\n")
	b.WriteString(boxRow(styleGrey.Render("Enter Create  Esc Cancel"), textW) + "\n")
	b.WriteString(boxBottom(w))

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, b.String())
}
