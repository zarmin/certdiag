package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/lipgloss"
)

// --- View ---

func (m RootModel) View() string {
	var view string
	switch m.state {
	case stateLoading:
		view = m.viewLoading()
	case stateTree:
		view = m.viewTree()
	case stateSplit:
		if m.height >= splitScreenMinHeight {
			view = m.viewSplitScreen()
		} else {
			view = m.viewDetailFullscreen()
		}
	case stateSearch:
		view = m.viewSearch()
	case statePassword:
		view = m.viewPassword()
	case stateMenu:
		view = m.viewMenu()
	case stateForm:
		view = m.viewForm()
	case stateMultiSelect:
		view = m.viewMultiSelect()
	case stateColumnEditor:
		view = m.viewColumnEditor()
	case stateOptions:
		view = m.viewOptions()
	case stateCheckView:
		view = m.checkView.view()
	case stateCheckCatalog:
		if m.checkCatalog != nil {
			view = m.checkCatalog.view()
		}
	case stateDiff:
		view = m.viewDiff()
	case stateRemoteForm:
		view = m.viewRemoteForm()
	case statePacketAnalyzer:
		if m.packetAnalyzer != nil {
			m.packetAnalyzer.width = m.width
			m.packetAnalyzer.height = m.height
			if m.packetAnalyzer.state == packetCertDetail && m.detail != nil {
				// Render cert detail fullscreen
				view = m.viewDetailFullscreen()
			} else {
				view = m.packetAnalyzer.view()
			}
		}
	case statePacketForm:
		view = m.viewPacketForm()
	case stateVerifyPick:
		view = m.menu.view(m.width, m.height)
	case stateTrustVerify:
		view = m.viewTrustVerify()
	}

	if m.popup.kind != popupNone {
		return renderPopup(m.popup, m.width, m.height)
	}

	return view
}

func (m RootModel) viewLoading() string {
	label := m.loadingMessage
	if label == "" {
		label = "Scanning..."
	}
	msg := m.spinner.View() + " " + label
	if p := m.scanProgress; p != nil {
		dirs := p.DirsScanned.Load()
		files := p.FilesProbed.Load()
		pws := p.PasswordChecks.Load()
		counters := fmt.Sprintf("Dirs scanned: %d  Files probed: %d  Passwords probed: %d", dirs, files, pws)
		msg += "\n" + styleInfoBar.Render(counters)
	}
	hint := styleInfoBar.Render("[Esc] Stop")
	content := msg + "\n\n" + hint
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

func (m RootModel) viewTree() string {
	var sb fmt.Stringer = &treeViewBuilder{m: m, dimmed: false}
	return sb.String()
}

func (m RootModel) viewSplitScreen() string {
	infoBar, infoBarHeight := m.splitInfoBar()
	treeH := m.height / 2
	detailH := m.height - treeH - 1 - infoBarHeight // 1 for separator

	// Adjust tree viewport for split (title + header + margin)
	m.tree.viewportHeight = treeH - 3
	if m.tree.viewportHeight < 1 {
		m.tree.viewportHeight = 1
	}
	m.tree.clampOffset(len(m.visible))

	var sb strings.Builder

	// Tree panel title
	sb.WriteString(styleModalTitle.Render(m.treeTitleLine()))
	sb.WriteString("\n")

	// Tree panel
	tree := renderTree(m.visible, m.tree, false)
	sb.WriteString(tree)

	treeLines := strings.Count(tree, "\n")
	remaining := treeH - treeLines - 1 // -1 for title line
	for i := 0; i < remaining; i++ {
		sb.WriteString("\n")
	}

	// Separator
	sep := strings.Repeat("─", m.width)
	if m.focus == focusTree {
		sb.WriteString(styleUnfocusedBorder.Render(sep))
	} else {
		sb.WriteString(styleFocusedBorder.Render(sep))
	}
	sb.WriteString("\n")

	// Detail panel
	detail := renderDetailPanel(m.detail, m.focus == focusDetail, detailH, m.width)
	sb.WriteString(detail)

	detailLines := strings.Count(detail, "\n")
	remainingDetail := detailH - detailLines
	for i := 0; i < remainingDetail; i++ {
		sb.WriteString("\n")
	}

	// Info bar
	if m.confirmDelete {
		sb.WriteString(styleFormError.Render(deletePrompt(m.deleteFilePath)))
	} else {
		sb.WriteString(infoBar)
	}

	return sb.String()
}

func (m RootModel) viewDetailFullscreen() string {
	return renderDetailFullscreen(m.detail, m.width, m.height)
}

func (m RootModel) viewSearch() string {
	var sb fmt.Stringer = &treeViewBuilder{m: m, dimmed: false, searchBar: true}
	return sb.String()
}

func (m RootModel) viewPassword() string {
	var sb fmt.Stringer = &treeViewBuilder{m: m, dimmed: false, passwordBar: true}
	return sb.String()
}

func (m RootModel) splitHints() ([]Hint, []StatusHint) {
	var hints []Hint

	if m.copyFeedback != "" {
		hints = append(hints, Hint{"", m.copyFeedback})
	}

	if m.focus == focusTree {
		hints = append(hints, Hint{"Tab", "Detail"})
	} else {
		hints = append(hints, Hint{"Tab", "Tree"})
	}

	if m.detail != nil && m.focus == focusDetail {
		sel := m.detail.selectedLine()
		if sel != nil && sel.navigable {
			hints = append(hints, Hint{"Enter", "Navigate"})
		}
		if !clipboard.Unsupported {
			hints = append(hints, Hint{"c", "Copy to clipboard"})
		}
	}

	if m.history.canGoBack() {
		hints = append(hints, Hint{"[", "Back"})
	}
	if m.history.canGoForward() {
		hints = append(hints, Hint{"]", "Fwd"})
	}

	switch {
	case m.inTrustStoreView():
		hints = append(hints,
			Hint{"r", "Reload"}, Hint{"F", "Functions"}, Hint{"g", "Grouping"}, Hint{"E", "Export"},
			Hint{"V", "Verify"}, Hint{"C", "Columns"}, Hint{"O", "Options"}, Hint{"W", "Checks"},
			Hint{"/", "Search"}, Hint{"?", "Help"}, Hint{"Esc/q", "Close"},
		)
	case m.inRemoteView():
		// The write actions the lister offers are all refused on a served
		// chain, so advertising them here would only mislead.
		hints = append(hints,
			Hint{"s", "Save chain"}, Hint{"S", "Save all"}, Hint{"c", "Check"}, Hint{"A", "Fetch AIA"},
			Hint{"R", "New remote"}, Hint{"r", "Re-fetch"}, Hint{"F", "Functions"},
			Hint{"C", "Columns"}, Hint{"O", "Options"},
			Hint{"/", "Search"}, Hint{"?", "Help"}, Hint{"Esc/q", "Close"},
		)
	default:
		hints = append(hints,
			Hint{"r", "Rescan"}, Hint{"F", "Functions"}, Hint{"n", "New"}, Hint{"a", "Actions"}, Hint{"m", "Multi-select"},
			Hint{"C", "Columns"}, Hint{"O", "Options"}, Hint{"A", "Fetch AIA"}, Hint{"Ctrl+D", "Delete"}, Hint{"!", "Shell"},
			Hint{"/", "Search"}, Hint{"?", "Help"}, Hint{"Esc/q", "Close"},
		)
	}

	var status []StatusHint
	if m.scanIncomplete {
		status = append(status, StatusHint{"(incomplete scan)"})
	}
	if m.search.filterText != "" {
		status = append(status, StatusHint{fmt.Sprintf("Filter: %s", m.search.filterText)})
	}
	if m.statusMessage != "" {
		status = append(status, StatusHint{m.statusMessage})
	}

	return hints, status
}

func (m RootModel) splitInfoBar() (string, int) {
	hints, status := m.splitHints()
	return RenderHintBar(m.width, hints, status...)
}

func (m RootModel) detailPanelHeight() int {
	if m.height >= splitScreenMinHeight {
		treeH := m.height / 2
		_, infoBarHeight := m.splitInfoBar()
		return m.height - treeH - 1 - infoBarHeight
	}
	// Fullscreen modal
	h := m.height - 4
	if h > 30 {
		h = 30
	}
	if h < 5 {
		h = 5
	}
	return h - 4
}

type treeViewBuilder struct {
	m           RootModel
	dimmed      bool
	searchBar   bool
	passwordBar bool
}

func (b *treeViewBuilder) String() string {
	var sb strings.Builder

	// Title
	title := b.m.treeTitleLine()
	if b.dimmed {
		sb.WriteString(styleDimRow.Render(title))
	} else {
		sb.WriteString(styleModalTitle.Render(title))
	}
	sb.WriteString("\n")

	errLines := 0
	if b.m.err != nil {
		sb.WriteString(styleError.Render(fmt.Sprintf("Error: %v", b.m.err)))
		sb.WriteString("\n\n")
		errLines = 2
	}

	// Shrink the tree budget by the error lines so the total does not overrun.
	b.m.tree.viewportHeight -= errLines
	if b.m.tree.viewportHeight < 1 {
		b.m.tree.viewportHeight = 1
	}

	tree := renderTree(b.m.visible, b.m.tree, b.dimmed)
	sb.WriteString(tree)

	var footer string
	var footerLines int
	if b.passwordBar {
		footer = b.m.password.view(b.m.width)
		footerLines = strings.Count(footer, "\n") + 1
	} else if b.searchBar {
		footer = b.m.search.view(b.m.width)
		footerLines = strings.Count(footer, "\n") + 1
	} else if b.m.confirmDelete {
		footer = styleFormError.Render(deletePrompt(b.m.deleteFilePath))
		footerLines = strings.Count(footer, "\n") + 1
	} else {
		hints, status := b.m.treeFooterHints()
		footer, footerLines = RenderHintBar(b.m.width, hints, status...)
	}
	treeLines := strings.Count(tree, "\n")
	remaining := b.m.height - treeLines - 1 - errLines - footerLines // -1: title line
	if remaining < 0 {
		remaining = 0
	}
	for i := 0; i < remaining; i++ {
		sb.WriteString("\n")
	}

	sb.WriteString(footer)

	return sb.String()
}

// deletePrompt names the file first, then the keys, then where it lives; a
// long path must not push the name off the screen (M31 E3).
func deletePrompt(path string) string {
	return fmt.Sprintf(" Delete %s? [y/N]  (in %s)", filepath.Base(path), filepath.Dir(path))
}
