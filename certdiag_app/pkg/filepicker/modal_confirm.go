package filepicker

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m pickerModel) updateConfirmModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case keyLeft, keyRight, keyTab:
		m.confirm.yesNo = !m.confirm.yesNo
	case keyEnter, keySpace:
		if m.confirm.yesNo {
			// Yes
			m.modal = modalNone
			switch m.confirm.kind {
			case confirmOverwrite:
				m.confirmedPath = m.confirm.payload
				return m, tea.Quit
			case confirmInvalidExtension:
				return m.proceedAfterExtensionConfirm()
			}
		} else {
			// No
			m.modal = modalNone
		}
	case keyEsc:
		m.modal = modalNone
	}
	return m, nil
}

func (m pickerModel) renderConfirmModal() string {
	w := 56
	textW := w - 4
	msg := wrapText(m.confirm.message, textW)

	yesBtn := renderButton("[ Yes ]", m.confirm.yesNo)
	noBtn := renderButton("[ No  ]", !m.confirm.yesNo)

	btns := yesBtn + "  " + noBtn
	bw := lipgloss.Width(btns)
	pad := max((textW-bw)/2, 0)

	var b strings.Builder
	b.WriteString(boxTop(w) + "\n")
	b.WriteString(boxRow(styleAccent.Bold(true).Render("Confirm"), textW) + "\n")
	b.WriteString(boxSep(w) + "\n")
	b.WriteString(boxRow("", textW) + "\n")
	for _, line := range msg {
		b.WriteString(boxRow(line, textW) + "\n")
	}
	if m.confirm.extra != "" {
		b.WriteString(boxRow("", textW) + "\n")
		for _, line := range wrapText(m.confirm.extra, textW) {
			b.WriteString(boxRow(styleGrey.Render(line), textW) + "\n")
		}
	}
	b.WriteString(boxRow("", textW) + "\n")
	b.WriteString(boxRow(strings.Repeat(" ", pad)+btns, textW) + "\n")
	b.WriteString(boxRow("", textW) + "\n")
	b.WriteString(boxBottom(w))

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, b.String())
}
