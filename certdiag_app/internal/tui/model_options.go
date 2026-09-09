package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// --- Column editor ---

func (m RootModel) handleColumnEditorKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		m.state = m.colEditorReturn
		return m, nil

	case isKeyUp(msg):
		if m.columnEditor.cursor > 0 {
			m.columnEditor.cursor--
		}
		return m, nil

	case isKeyDown(msg):
		if m.columnEditor.cursor < len(m.columnEditor.specs)-1 {
			m.columnEditor.cursor++
		}
		return m, nil

	case isKeySpace(msg), isKeyEnter(msg):
		m.columnEditor.toggle()
		m.tree.activeCols = m.columnEditor.pending
		m.autoRunChecks()
		m.allNodes = ConvertStore(m.store, m.opts, m.pathDisplay)
		if m.inTrustStoreView() {
			m.storeCols = m.columnEditor.pending
			m.decorateStoreNodes()
		} else {
			m.decorateListerNodes()
		}
		m.recomputeVisible()
		m.tree.clampCursor(len(m.visible))
		// Switching TRUST or STORES on is what triggers the store read; until
		// then a plain browse never pays for it.
		return m, m.ensureListerTrust()

	case isKeySave(msg):
		if m.inTrustStoreView() {
			var text string
			if m.saveStoreOpts == nil {
				return m, nil
			}
			if err := m.saveStoreOpts(m.columnEditor.pending, string(m.storeGrouping)); err != nil {
				text = fmt.Sprintf("save failed: %v", err)
			} else {
				text = "store columns saved to config"
			}
			cmd := m.notify(notifyInfo, text)
			return m, cmd
		}
		if m.saveColumns != nil {
			var msg string
			if err := m.saveColumns(m.columnEditor.pending); err != nil {
				msg = fmt.Sprintf("save failed: %v", err)
			} else {
				msg = "columns saved to config"
			}
			cmd := m.notify(notifyInfo, msg)
			return m, cmd
		}
		return m, nil
	}

	return m, nil
}

func (m RootModel) viewColumnEditor() string {
	hints := m.columnEditorHints()
	var status []StatusHint
	if m.statusMessage != "" {
		status = append(status, StatusHint{m.statusMessage})
	}
	info, infoBarHeight := RenderHintBar(m.width, hints, status...)

	// Minimum terminal height is 16. Below that, skip the dimmed tree entirely.
	const minHeightForTree = 16
	if m.height < minHeightForTree {
		var sb strings.Builder
		sb.WriteString(m.columnEditor.view(m.width))
		sb.WriteString(info)
		return sb.String()
	}

	// Column editor panel height: title + separator + one row per column
	editorLines := 2 + len(m.columnEditor.specs)

	// Layout: 1(title) + treeH + 1(sep) + editorLines + infoBarHeight(info) = m.height
	treeH := m.height - 2 - infoBarHeight - editorLines
	if treeH < 2 {
		treeH = 2
	}
	m.tree.viewportHeight = treeH - 1 // subtract tree header row
	if m.tree.viewportHeight < 1 {
		m.tree.viewportHeight = 1
	}
	m.tree.clampOffset(len(m.visible))

	var sb strings.Builder

	// Title
	sb.WriteString(styleModalTitle.Render(m.treeTitleLine()))
	sb.WriteString("\n")

	// Dimmed tree
	tree := renderTree(m.visible, m.tree, true)
	sb.WriteString(tree)

	// Pad tree section to treeH lines
	treeLines := strings.Count(tree, "\n")
	for i := treeLines; i < treeH; i++ {
		sb.WriteString("\n")
	}

	// Separator
	sb.WriteString(styleSeparator.Render(strings.Repeat("─", m.width)))
	sb.WriteString("\n")

	// Column editor panel
	sb.WriteString(m.columnEditor.view(m.width))

	// Info bar
	sb.WriteString(info)

	return sb.String()
}

func (m RootModel) currentScanSnapshot() scanOptionSnapshot {
	return scanOptionSnapshot{
		Recursive:         m.scanOpts.Recursive,
		MaxDepth:          m.scanOpts.MaxDepth,
		FileSignatureScan: m.scanOpts.UseSignatureScan,
		AutoDiscover:      m.discover,
		PathDisplay:       m.pathDisplay,
		StoreGrouping:     string(m.storeGrouping),
		StoreView:         m.inTrustStoreView(),
		FingerprintFormat: string(m.fingerprintFormat),
	}
}

func (m *RootModel) applyOptionsSnapshot(snap scanOptionSnapshot) {
	m.scanOpts.Recursive = snap.Recursive
	m.scanOpts.MaxDepth = snap.MaxDepth
	m.scanOpts.UseSignatureScan = snap.FileSignatureScan
	m.discover = snap.AutoDiscover
	m.pathDisplay = snap.PathDisplay
	if snap.StoreGrouping != "" {
		m.storeGrouping = certops.ParseStoreGrouping(snap.StoreGrouping)
	}
	if snap.FingerprintFormat != "" {
		m.fingerprintFormat = certlib.ParseFingerprintFormat(snap.FingerprintFormat)
	}
	// Re-stamp so the ConvertStore that follows sees the new display settings.
	m.opts = m.stampDisplayOpts(m.opts)
}

func (m RootModel) handleOptionsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		scanChanged := m.optionsEditor.changed
		displayChanged := m.optionsEditor.displayChanged
		storeChanged := m.optionsEditor.storeChanged
		if scanChanged || displayChanged || storeChanged {
			snap := m.optionsEditor.snapshot()
			m.applyOptionsSnapshot(snap)
		}
		m.state = m.optionsReturn
		if storeChanged && m.inTrustStoreView() {
			m.detail = nil
			m.rebuildTrustStoreTree()
			if m.saveStoreOpts != nil {
				_ = m.saveStoreOpts(m.storeCols, string(m.storeGrouping))
			}
			return m, nil
		}
		if scanChanged {
			m.resetScanContext()
			m.state = stateLoading
			return m, m.startScan()
		}
		if displayChanged && m.store != nil {
			m.detail = nil
			m.allNodes = ConvertStore(m.store, m.opts, m.pathDisplay)
			// ConvertStore rebuilds nodes from scratch; the store-only columns
			// are filled separately and would otherwise blank out.
			if m.inTrustStoreView() {
				m.decorateStoreNodes()
			}
			m.recomputeVisible()
			m.tree.clampCursor(len(m.visible))
		}
		return m, nil

	case isKeyUp(msg):
		if m.optionsEditor.cursor > 0 {
			m.optionsEditor.cursor--
		}
		return m, nil

	case isKeyDown(msg):
		if m.optionsEditor.cursor < len(m.optionsEditor.defs)-1 {
			m.optionsEditor.cursor++
		}
		return m, nil

	case isKeySpace(msg), isKeyEnter(msg):
		def := m.optionsEditor.currentDef()
		switch def.kind {
		case optBool:
			m.optionsEditor.toggleBool(def.key)
		case optInt:
			if m.optionsEditor.ints[def.key] == 0 {
				m.optionsEditor.adjustInt(def.key, 10-m.optionsEditor.ints[def.key])
			} else {
				m.optionsEditor.ints[def.key] = 0
				m.optionsEditor.changed = true
			}
		case optChoice:
			m.optionsEditor.cycleChoice(def.key, 1)
		}
		return m, nil

	case isKeyLeft(msg):
		def := m.optionsEditor.currentDef()
		switch def.kind {
		case optInt:
			m.optionsEditor.adjustInt(def.key, -1)
		case optChoice:
			m.optionsEditor.cycleChoice(def.key, -1)
		}
		return m, nil

	case isKeyRight(msg):
		def := m.optionsEditor.currentDef()
		switch def.kind {
		case optInt:
			m.optionsEditor.adjustInt(def.key, 1)
		case optChoice:
			m.optionsEditor.cycleChoice(def.key, 1)
		}
		return m, nil

	case isKeySave(msg):
		if m.saveOptions != nil {
			snap := m.optionsEditor.snapshot()
			saved := SavedOptions{
				Recursive:         snap.Recursive,
				MaxDepth:          snap.MaxDepth,
				FileSignatureScan: snap.FileSignatureScan,
				AutoDiscover:      snap.AutoDiscover,
				PathDisplay:       snap.PathDisplay,
				FingerprintFormat: snap.FingerprintFormat,
			}
			var msg string
			if err := m.saveOptions(saved); err != nil {
				msg = fmt.Sprintf("save failed: %v", err)
			} else {
				msg = "options saved to config"
			}
			cmd := m.notify(notifyInfo, msg)
			return m, cmd
		}
		return m, nil
	}

	return m, nil
}

func (m RootModel) viewOptions() string {
	hints := m.optionsHints()
	var status []StatusHint
	if m.optionsEditor.changed {
		status = append(status, StatusHint{"(rescan pending)"})
	} else if m.optionsEditor.displayChanged {
		status = append(status, StatusHint{"(display changed)"})
	}
	if m.statusMessage != "" {
		status = append(status, StatusHint{m.statusMessage})
	}
	info, infoBarHeight := RenderHintBar(m.width, hints, status...)

	const minHeightForTree = 16
	if m.height < minHeightForTree {
		var sb strings.Builder
		sb.WriteString(m.optionsEditor.view(m.width))
		sb.WriteString(info)
		return sb.String()
	}

	// Options panel height: title + separator + category labels + one row per option
	editorLines := 2 + m.optionsEditor.categoryCount() + len(m.optionsEditor.defs)

	treeH := m.height - 2 - infoBarHeight - editorLines
	if treeH < 2 {
		treeH = 2
	}
	m.tree.viewportHeight = treeH - 1
	if m.tree.viewportHeight < 1 {
		m.tree.viewportHeight = 1
	}
	m.tree.clampOffset(len(m.visible))

	var sb strings.Builder

	sb.WriteString(styleModalTitle.Render(m.treeTitleLine()))
	sb.WriteString("\n")

	tree := renderTree(m.visible, m.tree, true)
	sb.WriteString(tree)

	treeLines := strings.Count(tree, "\n")
	for i := treeLines; i < treeH; i++ {
		sb.WriteString("\n")
	}

	sb.WriteString(styleSeparator.Render(strings.Repeat("\u2500", m.width)))
	sb.WriteString("\n")

	sb.WriteString(m.optionsEditor.view(m.width))

	sb.WriteString(info)

	return sb.String()
}

func (m RootModel) viewMultiSelect() string {
	var sb strings.Builder

	// Title
	title := m.treeTitleLine()
	sb.WriteString(styleModalTitle.Render(title))
	sb.WriteString("\n")

	if m.err != nil {
		sb.WriteString(styleError.Render(fmt.Sprintf("Error: %v", m.err)))
		sb.WriteString("\n\n")
	}

	tree := renderTree(m.visible, m.tree, false, m.multiSelect.selected)
	sb.WriteString(tree)

	hints := m.multiSelectHints()
	var status []StatusHint
	if m.statusMessage != "" {
		status = append(status, StatusHint{m.statusMessage})
	}
	footer, footerLines := RenderHintBar(m.width, hints, status...)

	treeLines := strings.Count(tree, "\n")
	remaining := m.height - treeLines - 1 - footerLines // -1: title line
	if remaining < 0 {
		remaining = 0
	}
	for i := 0; i < remaining; i++ {
		sb.WriteString("\n")
	}

	sb.WriteString(footer)

	return sb.String()
}

func (m RootModel) columnEditorHints() []Hint {
	return []Hint{{"Space/Enter", "Toggle"}, {"s", "Save to config"}, {"?", "Help"}, {"Esc/q", "Close"}}
}

func (m RootModel) optionsHints() []Hint {
	return []Hint{{"Space/Enter", "Toggle"}, {"Left/Right", "Adjust"}, {"s", "Save to config"}, {"?", "Help"}, {"Esc/q", "Close"}}
}

// multiSelectHints: the Diff hint appears only when exactly two certificates
// are selected, since that is the only case the action accepts.
func (m RootModel) multiSelectHints() []Hint {
	certCount := 0
	for _, n := range m.multiSelect.collectSelected(m.allNodes) {
		if n.Item != nil && n.Item.Type == certlib.ContentCertificate && n.Item.Certificate != nil {
			certCount++
		}
	}
	hints := []Hint{{"", fmt.Sprintf("Selected: %d items", m.multiSelect.count())}, {"Space", "Toggle"}, {"a", "Auto-chain"}}
	if certCount == 2 {
		hints = append(hints, Hint{"d", "Diff"})
	}
	return append(hints, Hint{"Enter", "Bundle"}, Hint{"Ctrl+D", "Delete"}, Hint{"?", "Help"}, Hint{"Esc/q", "Cancel"})
}
