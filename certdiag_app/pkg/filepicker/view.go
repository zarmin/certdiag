package filepicker

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	TERMINAL_SIZE_MIN_WIDTH  = 80
	TERMINAL_SIZE_MIN_HEIGHT = 22
)

func (m pickerModel) View() string {
	if m.termW == 0 {
		// Not yet sized — return blank
		return ""
	}

	if m.termW < TERMINAL_SIZE_MIN_WIDTH || m.termH < TERMINAL_SIZE_MIN_HEIGHT {
		return lipgloss.Place(m.termW, m.termH,
			lipgloss.Center, lipgloss.Center,
			styleRed.Render(fmt.Sprintf("Terminal too small. Please resize to at least %dx%d.", TERMINAL_SIZE_MIN_WIDTH, TERMINAL_SIZE_MIN_HEIGHT)))
	}

	boxW, _ := m.boxDims()
	textW := boxW - 4

	var modal string
	switch m.modal {
	case modalAlert:
		modal = m.renderAlertModal()
	case modalConfirm:
		modal = m.renderConfirmModal()
	case modalPath:
		modal = m.renderPathModal()
	case modalBookmarks:
		modal = m.renderBookmarksModal()
	case modalNewDir:
		modal = m.renderNewDirModal()
	default:
		modal = m.renderMain(boxW, textW)
	}

	return lipgloss.Place(m.termW, m.termH, lipgloss.Center, lipgloss.Center, modal)
}

func (m pickerModel) renderMain(boxW, textW int) string {
	var b strings.Builder

	b.WriteString(boxTop(boxW) + "\n")
	b.WriteString(m.renderTitle(textW) + "\n")
	b.WriteString(boxSep(boxW) + "\n")
	b.WriteString(m.renderPathBar(textW) + "\n")
	b.WriteString(boxSep(boxW) + "\n")
	b.WriteString(m.renderFileListHeader(textW) + "\n")

	listH := m.listHeight()
	b.WriteString(m.renderFileListRows(textW, listH))

	b.WriteString(boxSep(boxW) + "\n")

	// Type-specific section
	typeSpecific := m.renderTypeSpecific(textW)
	if typeSpecific != "" {
		b.WriteString(boxSep(boxW) + "\n")
		b.WriteString(typeSpecific)
	}

	if m.showsFilterBar() {
		b.WriteString(m.renderFilterBar(textW) + "\n")
		b.WriteString(boxSep(boxW) + "\n")
	}

	b.WriteString(m.renderButtons(textW) + "\n")
	b.WriteString(boxSep(boxW) + "\n")
	b.WriteString(m.renderHints(textW) + "\n")
	b.WriteString(boxBottom(boxW))

	return b.String()
}

func (m pickerModel) renderTitle(textW int) string {
	return boxRow(styleAccent.Bold(true).Render(m.cfg.title), textW)
}

func (m pickerModel) renderPathBar(textW int) string {
	if m.searchMode {
		cursor := "_"
		return boxRow("Search: "+m.searchQuery+cursor, textW)
	}
	displayDir := m.currentDir
	if displayDir == "" {
		displayDir = "Computer"
	}
	path := truncateToWidth(displayDir, textW)
	return boxRow(styleGrey.Render(path), textW)
}

func (m pickerModel) renderFileListHeader(textW int) string {
	// Name | Size (8) | Date (19)
	sizeW := 8
	dateW := 19
	nameW := textW - sizeW - dateW - 2 // 2 spaces between cols
	if nameW < 10 {
		nameW = 10
	}
	nameH := styleBold.Render(padToWidth("Name", nameW))
	sizeH := styleBold.Render(fmt.Sprintf("%*s", sizeW, "Size"))
	dateH := styleBold.Render(fmt.Sprintf("%*s", dateW, "Modified"))
	header := nameH + "  " + sizeH + " " + dateH
	rule := strings.Repeat("─", textW)
	return boxRow(header, textW) + "\n" + boxRow(rule, textW)
}

func (m pickerModel) renderFileListRows(textW, listH int) string {
	sizeW := 8
	dateW := 19
	nameW := textW - sizeW - dateW - 2
	if nameW < 10 {
		nameW = 10
	}

	var b strings.Builder
	n := len(m.entries)
	end := m.scroll + listH
	if end > n {
		end = n
	}

	for i := m.scroll; i < end; i++ {
		e := m.entries[i]
		isCursor := i == m.cursor
		b.WriteString(m.renderEntryRow(e, isCursor, nameW, sizeW, dateW, textW))
		b.WriteString("\n")
	}
	// Pad remaining rows
	for i := end - m.scroll; i < listH; i++ {
		b.WriteString(boxRow("", textW) + "\n")
	}
	return b.String()
}

func (m pickerModel) renderEntryRow(e fileEntry, isCursor bool, nameW, sizeW, dateW, textW int) string {
	var isSelected bool
	if m.cfg.multiSelect && !e.isDir && e.name != ".." {
		isSelected = m.selected[filepath.Join(m.currentDir, e.name)]
	}

	prefix := "  "
	if isCursor {
		prefix = "> "
	} else if isSelected {
		prefix = "● "
	}

	// Build name
	displayName := e.name
	if e.isSymlink && e.symlinkTarget != "" {
		displayName = e.name + " -> " + e.symlinkTarget
	}
	displayName = truncateToWidth(displayName, nameW-2) // -2 for prefix

	// Color the name
	var styledName string
	switch {
	case e.disabled:
		styledName = prefix + styleGrey.Render(displayName)
	case isCursor:
		styledName = styleCursor.Render(prefix + padToWidth(displayName, nameW-2))
	case e.name == "..":
		styledName = styleDir.Render(prefix + displayName)
	case isSelected:
		styledName = styleAccent.Render(prefix) + displayName
	case e.isDir && e.isSymlink:
		styledName = prefix + styleSymlinkDir.Render(displayName)
	case e.isDir:
		styledName = prefix + styleDir.Render(displayName)
	case e.isSymlink:
		styledName = prefix + styleSymlink.Render(displayName)
	case !e.passesFilter:
		styledName = prefix + styleGrey.Render(displayName)
	default:
		styledName = prefix + displayName
	}

	// Pad name to nameW visible chars
	nameVisible := lipgloss.Width(styledName)
	if nameVisible < nameW {
		styledName += strings.Repeat(" ", nameW-nameVisible)
	}

	// Size and date — blank for dirs and ".."
	sizeStr := ""
	dateStr := ""
	if !e.isDir && e.name != ".." {
		sizeStr = fmt.Sprintf("%*s", sizeW, formatSize(e.size))
		dateStr = fmt.Sprintf("%*s", dateW, formatModTime(e.modTime))
	}

	rowContent := styledName + "  " + sizeStr + " " + dateStr
	return boxRow(rowContent, textW)
}

func (m pickerModel) renderTypeSpecific(textW int) string {
	switch m.cfg.dialogType {
	case TypeSaveFile:
		label := "Filename: "
		inputView := m.filename.View()
		line1 := boxRow(label+inputView, textW)
		line2 := ""
		if len(m.cfg.saveExtensions) > 0 {
			hint := "Use one of these extensions: " + strings.Join(m.cfg.saveExtensions, "  ")
			line2 = boxRow(styleGrey.Render(hint), textW) + "\n"
		}
		return line1 + "\n" + line2

	case TypeOpenDir:
		label := "Selected dir: "
		displayDir := m.currentDir
		if displayDir == "" {
			displayDir = "Computer"
		}
		dir := truncateToWidth(displayDir, textW-len(label))
		return boxRow(label+styleAccent.Render(dir), textW) + "\n"
	}
	return ""
}

func (m pickerModel) renderFilterBar(textW int) string {
	if m.cfg.dialogType == TypeSaveFile {
		// For save, this is the extension hint — handled in renderTypeSpecific
		return ""
	}
	// Open file: show filter extensions + show hidden + optional all files + selection count
	filterText := ""
	if len(m.cfg.fileFilter) > 0 {
		filterText = "Filter: " + strings.Join(m.cfg.fileFilter, " ")
	}

	hiddenText := renderCheckbox(m.showHidden, m.focus == focusShowHidden) + " show hidden"

	allText := ""
	if m.cfg.filterOverridable {
		allText = "  " + renderCheckbox(m.filterAll, m.focus == focusAllFiles) + " all files"
	}

	selectedText := ""
	if m.cfg.multiSelect && len(m.selected) > 0 {
		selectedText = fmt.Sprintf("   %d selected", len(m.selected))
	}

	bar := filterText + "   " + hiddenText + allText + selectedText
	return boxRow(bar, textW)
}

func (m pickerModel) renderButtons(textW int) string {
	okLabel := "   OK   "
	cancelLabel := " Cancel "

	okBtn := renderButton("["+okLabel+"]", m.focus == focusOK)
	cancelBtn := renderButton("["+cancelLabel+"]", m.focus == focusCancel)

	btns := okBtn + "   " + cancelBtn
	// Center
	bw := lipgloss.Width(btns)
	pad := max((textW-bw)/2, 0)
	return boxRow(strings.Repeat(" ", pad)+btns, textW)
}

func (m pickerModel) renderHints(textW int) string {
	parts := []string{"↑↓ Nav", "Enter Select", "Tab Focus", ". Hidden", "Ctrl+P Path", "Ctrl+B Bookmarks"}
	if m.cfg.allowNewDir {
		parts = append(parts, "F7 NewDir")
	}
	if m.cfg.filterOverridable {
		parts = append(parts, "Ctrl+A AllFiles")
	}
	parts = append(parts, "/ Search", "F5 Refresh")
	if m.cfg.multiSelect {
		parts = append(parts, "Space Mark")
	}
	if !m.searchMode {
		parts = append(parts, "a-z Jump")
	}

	oneLine := strings.Join(parts, "  ")
	if lipgloss.Width(oneLine) <= textW {
		return boxRow(styleGrey.Render(oneLine), textW)
	}

	// Two lines: first 4 on line1, rest on line2
	line1 := strings.Join(parts[:4], "  ")
	line2 := strings.Join(parts[4:], "  ")
	return boxRow(styleGrey.Render(line1), textW) + "\n" + boxRow(styleGrey.Render(line2), textW)
}
