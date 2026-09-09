package filepicker

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const dropMaxH = 5

func (m pickerModel) updatePathModal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg.String() {
	case keyEsc:
		m.modal = modalNone
		return m, nil

	case keyDown:
		if len(m.pathMod.completions) > 0 && m.pathMod.dropCursor < len(m.pathMod.completions)-1 {
			m.pathMod.dropCursor++
			m.clampDropScroll()
		}
		return m, nil

	case keyTab:
		m = m.tabComplete()
		return m, nil

	case keyUp:
		if m.pathMod.dropCursor > -1 {
			m.pathMod.dropCursor--
			m.clampDropScroll()
		}
		return m, nil

	case keyEnter:
		return m.commitPath()

	case "ctrl+w":
		val := normalizePathInput(m.pathMod.input.Value())
		trimmed := strings.TrimRight(val, "/")
		if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
			val = trimmed[:idx+1]
		}
		m.pathMod.input.SetValue(val)
		m.pathMod.input.CursorEnd()
		m = m.resetAndUpdateCompletions()
		return m, nil

	default:
		m.pathMod.input, cmd = m.pathMod.input.Update(msg)
		m = m.resetAndUpdateCompletions()
		return m, cmd
	}
}

func (m pickerModel) resetAndUpdateCompletions() pickerModel {
	m.pathMod.completions = nil
	m.pathMod.dropCursor = -1
	m.pathMod.dropScroll = 0
	m.pathMod.isRed = false
	return m.updateCompletions()
}

func (m *pickerModel) clampDropScroll() {
	dc := m.pathMod.dropCursor
	if dc < 0 {
		dc = 0
	}
	if dc < m.pathMod.dropScroll {
		m.pathMod.dropScroll = dc
	}
	if dc >= m.pathMod.dropScroll+dropMaxH {
		m.pathMod.dropScroll = dc - dropMaxH + 1
	}
	// The last visible row is replaced by the "↓ N more" indicator when
	// entries remain below the window. Scroll one extra row so the cursor
	// never sits on (and gets hidden behind) that indicator.
	if dc == m.pathMod.dropScroll+dropMaxH-1 && m.pathMod.dropScroll+dropMaxH < len(m.pathMod.completions) {
		m.pathMod.dropScroll = dc - dropMaxH + 2
	}
	if m.pathMod.dropScroll < 0 {
		m.pathMod.dropScroll = 0
	}
}

func (m pickerModel) updateCompletions() pickerModel {
	val := normalizePathInput(m.pathMod.input.Value())
	if val == "" {
		return m
	}
	// Find completions for the last segment
	var dir, prefix string
	if strings.HasSuffix(val, "/") {
		dir = val
		prefix = ""
	} else {
		dir = filepath.Dir(val)
		prefix = filepath.Base(val)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		m.pathMod.isRed = true
		return m
	}

	var comps []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(strings.ToLower(e.Name()), strings.ToLower(prefix)) {
			comps = append(comps, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(comps)
	m.pathMod.completions = comps
	m.pathMod.isRed = len(comps) == 0 && prefix != ""
	return m
}

func (m pickerModel) tabComplete() pickerModel {
	comps := m.pathMod.completions
	if len(comps) == 0 {
		return m
	}

	// If a suggestion is already highlighted, accept it
	if m.pathMod.dropCursor >= 0 && m.pathMod.dropCursor < len(comps) {
		newVal := comps[m.pathMod.dropCursor] + "/"
		m.pathMod.input.SetValue(newVal)
		m.pathMod.input.CursorEnd()
		m = m.resetAndUpdateCompletions()
		return m
	}

	// No item highlighted — LCP logic
	val := normalizePathInput(m.pathMod.input.Value())
	var dir, prefix string
	if strings.HasSuffix(val, "/") {
		dir = val
		prefix = ""
	} else {
		dir = filepath.Dir(val)
		prefix = filepath.Base(val)
	}

	names := make([]string, len(comps))
	for i, c := range comps {
		names[i] = filepath.Base(c)
	}
	lcp := longestCommonPrefix(names)

	if len([]rune(lcp)) > len([]rune(prefix)) {
		newVal := filepath.Join(dir, lcp)
		if len(comps) == 1 {
			newVal += "/"
		}
		m.pathMod.input.SetValue(newVal)
		m.pathMod.input.CursorEnd()
		m = m.resetAndUpdateCompletions()
	} else if m.pathMod.dropCursor < len(comps)-1 {
		m.pathMod.dropCursor++
		m.clampDropScroll()
	}
	return m
}

func longestCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	runes := make([][]rune, len(strs))
	for i, s := range strs {
		runes[i] = []rune(s)
	}
	first := runes[0]
	i := 0
	for i < len(first) {
		r := unicode.ToLower(first[i])
		for _, rs := range runes[1:] {
			if i >= len(rs) || unicode.ToLower(rs[i]) != r {
				return string(first[:i])
			}
		}
		i++
	}
	return string(first[:i])
}

// trimTrailingSlash drops trailing slashes from a "/"-normalized path but keeps
// filesystem roots intact: the Unix root "/" and Windows drive roots like "C:/"
// (trimming those would turn them into empty/drive-relative paths).
func trimTrailingSlash(val string) string {
	trimmed := strings.TrimRight(val, "/")
	if trimmed == "" && val != "" {
		return "/"
	}
	if len(trimmed) == 2 && trimmed[1] == ':' {
		return trimmed + "/"
	}
	return trimmed
}

func (m pickerModel) commitPath() (tea.Model, tea.Cmd) {
	var val string
	if m.pathMod.dropCursor >= 0 && m.pathMod.dropCursor < len(m.pathMod.completions) {
		val = m.pathMod.completions[m.pathMod.dropCursor]
	} else {
		val = trimTrailingSlash(normalizePathInput(m.pathMod.input.Value()))
	}
	if val == "" {
		m.modal = modalNone
		return m, nil
	}
	val = filepath.Clean(val)

	info, err := os.Stat(val)
	if err == nil {
		if info.IsDir() {
			// Navigate into directory
			m.modal = modalNone
			m.loadDir(val)
			return m, nil
		}
		// It's a file
		return m.handlePathFile(val)
	}

	// Non-existing path — check parent
	parent := filepath.Dir(val)
	if _, err2 := os.Stat(parent); err2 == nil {
		// Valid parent
		baseName := filepath.Base(val)
		m.modal = modalNone
		m.loadDir(parent)
		if m.cfg.dialogType == TypeSaveFile {
			m.filename.SetValue(baseName)
		}
		return m, nil
	}

	// No valid parent — stay red
	m.pathMod.isRed = true
	return m, nil
}

func (m pickerModel) handlePathFile(path string) (tea.Model, tea.Cmd) {
	dir := filepath.Dir(path)
	baseName := filepath.Base(path)

	switch m.cfg.dialogType {
	case TypeOpenFile:
		// Check filter
		passes := passesFilter(fileEntry{name: baseName}, m.cfg.fileFilter, m.filterAll, TypeOpenFile)
		if !passes {
			m.modal = modalAlert
			m.alert = alertState{message: "File type not allowed."}
			return m, nil
		}
		// Return immediately
		m.modal = modalNone
		m.confirmedPath = path
		return m, tea.Quit

	case TypeOpenDir:
		m.modal = modalNone
		m.loadDir(dir)
		return m, nil

	case TypeSaveFile:
		m.modal = modalNone
		m.loadDir(dir)
		m.filename.SetValue(baseName)
		return m, nil
	}
	return m, nil
}

func (m pickerModel) renderPathModal() string {
	w := m.termW - 4
	if w > 80 {
		w = 80
	}
	if w < 46 {
		w = 46
	}
	textW := w - 4

	var b strings.Builder
	b.WriteString(boxTop(w) + "\n")
	b.WriteString(boxRow(styleAccent.Bold(true).Render("Go to path"), textW) + "\n")
	b.WriteString(boxSep(w) + "\n")
	m.pathMod.input.width = textW - 2
	b.WriteString(boxRow("> "+m.pathMod.input.View(), textW) + "\n")

	// Dropdown area — always dropMaxH rows tall
	comps := m.pathMod.completions
	for row := 0; row < dropMaxH; row++ {
		idx := m.pathMod.dropScroll + row
		if idx < len(comps) {
			name := filepath.Base(comps[idx])
			// Last visible row: show scroll indicator if more below
			isLast := row == dropMaxH-1
			remaining := len(comps) - (m.pathMod.dropScroll + dropMaxH)
			if isLast && remaining > 0 {
				indicator := styleGrey.Render(fmt.Sprintf("  ↓ %d more", remaining))
				b.WriteString(boxRow(indicator, textW) + "\n")
				continue
			}
			label := truncateToWidth(name, textW-2)
			if idx == m.pathMod.dropCursor {
				b.WriteString(boxRow(styleCursor.Render("> "+padToWidth(label, textW-2)), textW) + "\n")
			} else {
				b.WriteString(boxRow("  "+label, textW) + "\n")
			}
		} else if row == 0 && m.pathMod.isRed {
			b.WriteString(boxRow(styleRed.Render("  Path not found"), textW) + "\n")
		} else {
			b.WriteString(boxRow("", textW) + "\n")
		}
	}

	b.WriteString(boxRow(styleGrey.Render("↑↓ Navigate  Enter Go  Esc Cancel"), textW) + "\n")
	b.WriteString(boxBottom(w))

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, b.String())
}
