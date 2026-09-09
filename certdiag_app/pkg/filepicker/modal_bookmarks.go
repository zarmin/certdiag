package filepicker

import (
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func visibleBookmarks(m pickerModel) []Bookmark {
	var bms []Bookmark
	seen := map[string]bool{}

	// Always add Home first
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(home); err == nil {
			bms = append(bms, Bookmark{Label: "Home", Path: home})
			seen[home] = true
		}
	}

	// Start dir (skip if same as home or already seen)
	if !seen[m.startDir] {
		if _, err := os.Stat(m.startDir); err == nil {
			bms = append(bms, Bookmark{Label: "Start", Path: m.startDir})
			seen[m.startDir] = true
		}
	}

	// Windows drive roots
	for _, bm := range listReadyDriveBookmarks() {
		if !seen[bm.Path] {
			bms = append(bms, bm)
			seen[bm.Path] = true
		}
	}

	// Configured bookmarks (skip duplicates)
	for _, bm := range m.cfg.bookmarks {
		if seen[bm.Path] {
			continue
		}
		if _, err := os.Stat(bm.Path); err == nil {
			bms = append(bms, bm)
			seen[bm.Path] = true
		}
	}

	return bms
}

func (m pickerModel) updateBookmarksModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	bms := visibleBookmarks(m)
	switch msg.String() {
	case keyUp:
		if m.bmMod.cursor > 0 {
			m.bmMod.cursor--
		}
	case keyDown:
		if m.bmMod.cursor < len(bms)-1 {
			m.bmMod.cursor++
		}
	case keyEnter:
		if m.bmMod.cursor < len(bms) {
			bm := bms[m.bmMod.cursor]
			m.modal = modalNone
			m.loadDir(bm.Path)
		}
	case keyEsc:
		m.modal = modalNone
	}
	return m, nil
}

func (m pickerModel) renderBookmarksModal() string {
	bms := visibleBookmarks(m)

	longestLabelLen := 0
	longestPathLen := 0
	for _, bm := range bms {
		longestLabelLen = max(longestLabelLen, len(bm.Label))
		longestPathLen = max(longestPathLen, len(bm.Path))
	}
	requiredMinLengthWithPadding := longestLabelLen + 10 + longestPathLen

	w := m.termW - 4
	if w > requiredMinLengthWithPadding {
		w = requiredMinLengthWithPadding
	}
	if w < 52 {
		w = 52
	}
	textW := w - 4

	var b strings.Builder
	b.WriteString(boxTop(w) + "\n")
	b.WriteString(boxRow(styleAccent.Bold(true).Render("Bookmarks"), textW) + "\n")
	b.WriteString(boxSep(w) + "\n")

	for i, bm := range bms {
		label := truncateToWidth(bm.Label, textW-2)
		path := truncateToWidth(bm.Path, textW-4)

		label = padToWidth(label, longestLabelLen)
		label += "  "
		label += path
		if i == m.bmMod.cursor {
			b.WriteString(boxRow(styleCursor.Render("> "+padToWidth(label, textW-2)), textW) + "\n")
		} else {
			b.WriteString(boxRow("  "+label, textW) + "\n")
		}
	}

	b.WriteString(boxRow("", textW) + "\n")
	b.WriteString(boxRow(styleGrey.Render("↑↓ Navigate  Enter Jump  Esc Cancel"), textW) + "\n")
	b.WriteString(boxBottom(w))

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, b.String())
}
