package filepicker

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Color palette
var (
	colorAccent  = lipgloss.Color("99")
	colorDir     = lipgloss.Color("39")
	colorSymlink = lipgloss.Color("6")
	colorGrey    = lipgloss.Color("240")
	colorRed     = lipgloss.Color("9")
)

// Lipgloss styles
var (
	styleAccent    = lipgloss.NewStyle().Foreground(colorAccent)
	styleBold      = lipgloss.NewStyle().Bold(true)
	styleDir       = lipgloss.NewStyle().Foreground(colorDir).Bold(true)
	styleSymlink   = lipgloss.NewStyle().Foreground(colorSymlink)
	styleSymlinkDir = lipgloss.NewStyle().Foreground(colorSymlink).Bold(true)
	styleGrey      = lipgloss.NewStyle().Foreground(colorGrey)
	styleRed       = lipgloss.NewStyle().Foreground(colorRed)
	styleCursor    = lipgloss.NewStyle().Background(colorAccent).Foreground(lipgloss.Color("0"))
	styleFocusBtn  = lipgloss.NewStyle().Background(colorAccent).Foreground(lipgloss.Color("0")).Bold(true)
)

// Box drawing helpers — all content lines are exactly boxW columns wide.
// boxW = textW + 4 (for "│ " and " │")

func boxTop(w int) string {
	return "╭" + strings.Repeat("─", w-2) + "╮"
}

func boxBottom(w int) string {
	return "╰" + strings.Repeat("─", w-2) + "╯"
}

func boxSep(w int) string {
	return "├" + strings.Repeat("─", w-2) + "┤"
}

func boxRow(content string, textW int) string {
	return "│ " + padToWidth(content, textW) + " │"
}

// padToWidth pads or truncates content to exactly w visible columns.
func padToWidth(s string, w int) string {
	visible := lipgloss.Width(s)
	if visible >= w {
		return truncateToWidth(s, w)
	}
	return s + strings.Repeat(" ", w-visible)
}

// truncateToWidth truncates string to at most w visible columns, appending "…" if truncated.
func truncateToWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	// Binary-search style: find longest prefix that fits in w-1 + "…"
	runes := []rune(s)
	// Strip ANSI-style width calculation is handled by lipgloss.Width on substrings
	for i := len(runes); i > 0; i-- {
		candidate := string(runes[:i]) + "…"
		if lipgloss.Width(candidate) <= w {
			return candidate
		}
	}
	return "…"
}

func renderButton(label string, focused bool) string {
	if focused {
		return styleFocusBtn.Render(label)
	}
	return label
}

func renderCheckbox(checked, focused bool) string {
	s := "[ ]"
	if checked {
		s = "[x]"
	}
	return renderButton(s, focused)
}

// wrapText splits s into lines that fit within maxW columns, breaking at word boundaries.
func wrapText(s string, maxW int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
		} else if len(cur)+1+len(w) <= maxW {
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
