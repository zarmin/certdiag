package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// Key policy (M31 section 7), enforced by key_policy_test.go:
//
//   - Ctrl+C quits from anywhere.
//   - q quits from a tree (cert lister, remote view, trust store view, packet
//     session list) and closes the pane or overlay in every other view. A
//     focused text input receives it as a character. q is never an action key.
//   - Esc undoes the most recent transient state: cancel a load, close a popup,
//     clear a search or filter, close the pane and return to the previous view.
//     At the top of a tree it does nothing and never quits.
//   - ? opens this overlay with every key of the current view; the footer shows
//     as many of them as fit on one row (RenderHintBar).

const helpPopupTitle = "Keys in this view"

// currentHints is the one source for the footer and the help overlay of the
// view that is active, so the overlay can never advertise a key the view does
// not have.
func (m RootModel) currentHints() ([]Hint, []StatusHint) {
	switch m.state {
	case stateTree:
		return m.treeFooterHints()
	case stateSplit:
		// Below the split threshold the detail is shown full screen and has
		// its own, smaller key set.
		if m.height < splitScreenMinHeight && m.detail != nil {
			return detailHints(m.detail, false), nil
		}
		return m.splitHints()
	case stateCheckView:
		return m.checkView.hints()
	case stateCheckCatalog:
		if m.checkCatalog != nil {
			return m.checkCatalog.hints()
		}
	case stateDiff:
		return m.diffHints(), nil
	case stateMultiSelect:
		return m.multiSelectHints(), nil
	case stateColumnEditor:
		return m.columnEditorHints(), nil
	case stateOptions:
		return m.optionsHints(), nil
	case stateTrustVerify:
		return m.trustVerifyHints(), nil
	case statePacketAnalyzer:
		if m.packetAnalyzer != nil {
			return m.packetAnalyzer.hints()
		}
	}
	return nil, nil
}

// helpAvailable reports whether ? opens the overlay in the current state. It is
// false wherever a text input or a confirmation owns the keyboard.
func (m RootModel) helpAvailable() bool {
	switch m.state {
	case stateTree, stateSplit:
		return !m.confirmDelete
	case stateCheckView:
		return !m.checkView.filterActive
	case stateCheckCatalog, stateDiff, stateMultiSelect, stateColumnEditor, stateOptions, stateTrustVerify:
		return true
	case statePacketAnalyzer:
		if m.packetAnalyzer == nil {
			return false
		}
		switch m.packetAnalyzer.state {
		case packetIdle, packetSessions, packetProxyRunning, packetDetail, packetCertDetail:
			return true
		}
	}
	return false
}

func (m RootModel) openHelp() (tea.Model, tea.Cmd) {
	hints, _ := m.currentHints()
	var lines []string
	for _, h := range hints {
		if h.Key == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%-14s %s", h.Key, h.Label))
	}
	lines = append(lines, fmt.Sprintf("%-14s %s", "Ctrl+C", "Quit"))
	m.popup = popupState{kind: popupHelp, title: helpPopupTitle, lines: lines}
	return m, nil
}
