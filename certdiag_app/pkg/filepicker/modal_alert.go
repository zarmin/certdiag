package filepicker

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m pickerModel) updateAlertModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case keyEnter, keySpace, keyEsc:
		m.modal = modalNone
		if m.cfg.dialogType == TypeSaveFile {
			m.focus = focusFilename
			m.syncFocus()
			m.filename.CursorEnd()
		}
	}
	return m, nil
}

func (m pickerModel) renderAlertModal() string {
	w := 56
	textW := w - 4
	msg := wrapText(m.alert.message, textW)

	var b strings.Builder
	b.WriteString(boxTop(w) + "\n")
	b.WriteString(boxRow(styleRed.Bold(true).Render("Error"), textW) + "\n")
	b.WriteString(boxSep(w) + "\n")
	b.WriteString(boxRow("", textW) + "\n")
	for _, line := range msg {
		b.WriteString(boxRow(line, textW) + "\n")
	}
	if m.alert.extra != "" {
		b.WriteString(boxRow("", textW) + "\n")
		for _, line := range wrapText(m.alert.extra, textW) {
			b.WriteString(boxRow(styleGrey.Render(line), textW) + "\n")
		}
	}
	b.WriteString(boxRow("", textW) + "\n")
	// OK button centered
	btn := "[  OK  ]"
	pad := (textW - lipgloss.Width(btn)) / 2
	if pad < 0 {
		pad = 0
	}
	b.WriteString(boxRow(strings.Repeat(" ", pad)+styleFocusBtn.Render(btn), textW) + "\n")
	b.WriteString(boxBottom(w))

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, b.String())
}

