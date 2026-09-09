package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type popupKind int

const (
	popupNone popupKind = iota
	popupNotice
	popupError
	popupConfirm
	popupShell
	popupCommand
	popupHelp
)

type popupState struct {
	kind     popupKind
	title    string
	message  string
	lines    []string
	selected int // 0 = Yes (default), 1 = No — only for popupConfirm
}

type notifyLevel int

const (
	notifyInfo notifyLevel = iota
	notifyNotice
	notifyError
)

func popupBoxTop(w int) string {
	return "\u256d" + strings.Repeat("\u2500", w-2) + "\u256e"
}

func popupBoxBottom(w int) string {
	return "\u2570" + strings.Repeat("\u2500", w-2) + "\u256f"
}

func popupBoxSep(w int) string {
	return "\u251c" + strings.Repeat("\u2500", w-2) + "\u2524"
}

func popupBoxRow(content string, textW int) string {
	return "\u2502 " + popupPadToWidth(content, textW) + " \u2502"
}

func popupPadToWidth(s string, w int) string {
	visible := lipgloss.Width(s)
	if visible >= w {
		return ansi.Truncate(s, w, "")
	}
	return s + strings.Repeat(" ", w-visible)
}

func wrapWords(s string, maxW int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if ansi.StringWidth(cur)+1+ansi.StringWidth(w) <= maxW {
			cur += " " + w
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func renderConfirmPopup(popup popupState, width, height int) string {
	// Compute text width based on longest line
	textW := 30
	for _, l := range popup.lines {
		if len(l)+4 > textW {
			textW = len(l) + 4
		}
	}
	msgW := len(popup.message)
	if msgW > textW {
		textW = msgW
	}
	// Cap at terminal width
	maxTextW := width - 8
	if maxTextW < 20 {
		maxTextW = 20
	}
	if textW > maxTextW {
		textW = maxTextW
	}
	boxW := textW + 4

	title := "Confirm Delete"
	if popup.title != "" {
		title = popup.title
	}
	header := stylePopupConfirm.Render(title)

	var sb strings.Builder
	sb.WriteString(popupBoxTop(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow(header, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxSep(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")

	for _, line := range wrapWords(popup.message, textW) {
		sb.WriteString(popupBoxRow(line, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")

	for _, l := range popup.lines {
		display := "  " + l
		if lipgloss.Width(display) > textW {
			display = "  ..." + ansi.TruncateLeft(l, lipgloss.Width(l)-(textW-5), "")
		}
		sb.WriteString(popupBoxRow(display, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")

	yText := "[ Yes ]"
	nText := "[ No ]"
	var yBtn, nBtn string
	if popup.selected == 0 {
		yBtn = styleFormButtonFoc.Render(yText)
		nBtn = styleFormButton.Render(nText)
	} else {
		yBtn = styleFormButton.Render(yText)
		nBtn = styleFormButtonFoc.Render(nText)
	}
	btnRow := yBtn + "  " + nBtn
	btnPad := (textW - lipgloss.Width(btnRow)) / 2
	if btnPad < 0 {
		btnPad = 0
	}
	btnLine := strings.Repeat(" ", btnPad) + btnRow
	sb.WriteString(popupBoxRow(btnLine, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxBottom(boxW))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, sb.String())
}

func renderShellPopup(popup popupState, width, height int) string {
	// lines[0] = shell name, lines[1] = dir, lines[2] = file (optional)
	shellName := ""
	dir := ""
	file := ""
	if len(popup.lines) > 0 {
		shellName = popup.lines[0]
	}
	if len(popup.lines) > 1 {
		dir = popup.lines[1]
	}
	if len(popup.lines) > 2 {
		file = popup.lines[2]
	}

	// Build content lines
	shellLine := "Shell:  " + shellName
	cwdLine := "CWD:    " + dir
	fileLine := ""
	if file != "" {
		fileLine = "FILE:   " + file
	}
	hintLine := "Use the FILE environment variable to"
	hintLine2 := "access this file path in the shell."

	// Compute text width
	textW := 30
	for _, l := range []string{shellLine, cwdLine, fileLine, hintLine, hintLine2} {
		if len(l)+2 > textW {
			textW = len(l) + 2
		}
	}
	maxTextW := width - 8
	if maxTextW < 20 {
		maxTextW = 20
	}
	if textW > maxTextW {
		textW = maxTextW
	}
	boxW := textW + 4

	header := stylePopupNotice.Render("Shell")

	var sb strings.Builder
	sb.WriteString(popupBoxTop(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow(header, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxSep(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("  "+shellLine, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("  "+cwdLine, textW))
	sb.WriteString("\n")
	if fileLine != "" {
		sb.WriteString(popupBoxRow("  "+fileLine, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")
	if file != "" {
		sb.WriteString(popupBoxRow("  "+hintLine, textW))
		sb.WriteString("\n")
		sb.WriteString(popupBoxRow("  "+hintLine2, textW))
		sb.WriteString("\n")
		sb.WriteString(popupBoxRow("", textW))
		sb.WriteString("\n")
	}

	enterBtn := stylePopupBtn.Render(" [Enter] Open shell ")
	escBtn := "  [Esc] Cancel"
	btnRow := enterBtn + escBtn
	btnPad := (textW - lipgloss.Width(btnRow)) / 2
	if btnPad < 0 {
		btnPad = 0
	}
	btnLine := strings.Repeat(" ", btnPad) + btnRow
	sb.WriteString(popupBoxRow(btnLine, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxBottom(boxW))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, sb.String())
}

func renderCommandPopup(popup popupState, width, height int) string {
	maxTextW := width - 8
	if maxTextW < 24 {
		maxTextW = 24
	}
	// Size the box to the longest command/note line so paths and long commands
	// fit without wrapping when the terminal is wide enough.
	textW := 40
	for _, l := range popup.lines {
		if w := lipgloss.Width(l) + 2; w > textW {
			textW = w
		}
	}
	if textW > maxTextW {
		textW = maxTextW
	}
	boxW := textW + 4

	title := popup.title
	if title == "" {
		title = "openssl equivalent"
	}
	header := stylePopupNotice.Render(title)

	// Wrap each source line to the box width; continuation lines are indented so
	// a wrapped command still reads as one command.
	var display []string
	for _, raw := range popup.lines {
		if strings.TrimSpace(raw) == "" {
			display = append(display, "")
			continue
		}
		wrapped := wrapWords(raw, textW-2)
		for i, wl := range wrapped {
			if i == 0 {
				display = append(display, wl)
			} else {
				display = append(display, "    "+wl)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(popupBoxTop(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow(header, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxSep(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")
	for _, line := range display {
		sb.WriteString(popupBoxRow("  "+line, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")

	copyBtn := stylePopupBtn.Render(" [c] Copy ")
	escBtn := "  [Esc] Close"
	btnRow := copyBtn + escBtn
	btnPad := (textW - lipgloss.Width(btnRow)) / 2
	if btnPad < 0 {
		btnPad = 0
	}
	sb.WriteString(popupBoxRow(strings.Repeat(" ", btnPad)+btnRow, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxBottom(boxW))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, sb.String())
}

func renderPopup(popup popupState, width, height int) string {
	if popup.kind == popupNone {
		return ""
	}

	if popup.kind == popupConfirm {
		return renderConfirmPopup(popup, width, height)
	}

	if popup.kind == popupShell {
		return renderShellPopup(popup, width, height)
	}

	if popup.kind == popupCommand {
		return renderCommandPopup(popup, width, height)
	}

	if popup.kind == popupHelp {
		return renderHelpPopup(popup, width, height)
	}

	textW := 36
	if width < 44 {
		textW = width - 8
	}
	if textW < 16 {
		textW = 16
	}
	boxW := textW + 4

	var header string
	switch popup.kind {
	case popupError:
		header = stylePopupError.Render("Error")
	case popupNotice:
		header = stylePopupNotice.Render("Notice")
	}

	msgLines := wrapWords(popup.message, textW)

	var sb strings.Builder
	sb.WriteString(popupBoxTop(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow(header, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxSep(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")
	for _, line := range msgLines {
		sb.WriteString(popupBoxRow(line, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxRow("", textW))
	sb.WriteString("\n")

	btn := stylePopupBtn.Render("  OK  ")
	btnPad := (textW - lipgloss.Width(btn)) / 2
	if btnPad < 0 {
		btnPad = 0
	}
	btnLine := strings.Repeat(" ", btnPad) + btn
	sb.WriteString(popupBoxRow(btnLine, textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxBottom(boxW))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, sb.String())
}

func updatePopup(msg tea.KeyMsg, kind popupKind) popupKind {
	switch msg.String() {
	case "enter", " ", "esc":
		return popupNone
	case "?", "q":
		if kind == popupHelp {
			return popupNone
		}
	}
	return kind
}

// renderHelpPopup lists every key of the current view (keypolicy.go). It is
// sized to its longest line and cut with an ellipsis row when the terminal is
// too short for all of them.
func renderHelpPopup(popup popupState, width, height int) string {
	lines := append([]string{}, popup.lines...)
	textW := lipgloss.Width(popup.title) + lipgloss.Width("  (? or Esc closes)")
	for _, l := range lines {
		if w := lipgloss.Width(l); w > textW {
			textW = w
		}
	}
	if textW > width-8 {
		textW = width - 8
	}
	if textW < 16 {
		textW = 16
	}
	// Chrome is four rows: top, title, separator, bottom.
	maxLines := height - 4
	if maxLines >= 1 && len(lines) > maxLines {
		lines = append(lines[:maxLines-1], "...")
	}
	for i, l := range lines {
		if r := []rune(l); len(r) > textW {
			lines[i] = string(r[:textW])
		}
	}
	boxW := textW + 4

	var sb strings.Builder
	sb.WriteString(popupBoxTop(boxW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxRow(styleModalTitle.Render(popup.title)+styleFormHint.Render("  (? or Esc closes)"), textW))
	sb.WriteString("\n")
	sb.WriteString(popupBoxSep(boxW))
	sb.WriteString("\n")
	for _, line := range lines {
		sb.WriteString(popupBoxRow(line, textW))
		sb.WriteString("\n")
	}
	sb.WriteString(popupBoxBottom(boxW))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, sb.String())
}
