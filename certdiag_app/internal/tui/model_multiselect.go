package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// --- Multi-select ---

func (m RootModel) handleMultiSelectKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		m.multiSelectActive = false
		m.multiSelect.clear()
		m.statusMessage = "" // the selection status does not outlive the mode
		m.state = m.multiSelectReturn
		return m, nil

	case isKeySpace(msg):
		if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := m.visible[m.tree.cursor]
			if node.Locked {
				return m, m.notify(notifyInfo, "unlock first")
			}
			if node.Skipped {
				return m, m.notify(notifyInfo, "skipped files cannot be selected")
			}
			if node.isReadOnlySource() {
				return m, m.notify(notifyInfo, "trust store rows are read-only; export with E")
			}
			m.multiSelect.toggle(node, m.allNodes)
		}
		return m, nil

	case isKeyEnter(msg):
		if m.multiSelect.count() == 0 {
			cmd := m.notify(notifyInfo, "no items selected")
			return m, cmd
		}
		selectedNodes := m.multiSelect.collectSelected(m.allNodes)
		filePaths := m.multiSelect.collectFilePaths(m.allNodes)
		form := buildBundleForm(m.scanPath, selectedNodes, filePaths)
		if !m.scanOpts.UseSignatureScan {
			form.setExtensionWarning(warnNoSignatureScan)
		}
		form.width = m.width
		form.height = m.height
		m.activeForm = form
		m.activeFormKind = formBundle
		m.confirmOverwrite = false
		m.confirmDiscard = false
		m.prevState = stateMultiSelect
		m.state = stateForm
		return m, nil

	case msg.String() == "a":
		// Auto-chain works from the selection when there is one (every
		// selected certificate), else from the cursor row (M31 E8).
		var seeds []TreeNode
		for _, n := range m.multiSelect.collectSelected(m.allNodes) {
			if n.Item != nil && n.Item.Type == certlib.ContentCertificate {
				seeds = append(seeds, n)
			}
		}
		if len(seeds) == 0 && len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			seeds = append(seeds, m.visible[m.tree.cursor])
		}
		if len(seeds) == 0 {
			return m, m.notify(notifyInfo, "auto-chain requires a certificate")
		}
		result := ""
		for _, n := range seeds {
			result = m.multiSelect.autoSelectChain(n, m.allNodes, m.opts.RelationIndex)
		}
		if len(seeds) > 1 {
			result = fmt.Sprintf("auto-chain applied to %d selected certificates", len(seeds))
		}
		return m, m.notify(notifyInfo, result)

	case msg.String() == "d":
		cmd := m.openDiffFromMultiSelect()
		return m, cmd

	case isKeyDelete(msg):
		if m.multiSelect.count() == 0 {
			cmd := m.notify(notifyInfo, "no items selected")
			return m, cmd
		}
		paths := m.multiSelect.collectFilePaths(m.allNodes)
		m.deleteFilePaths = paths
		m.popup = popupState{
			kind:    popupConfirm,
			message: fmt.Sprintf("Delete %d file(s)?", len(paths)),
			lines:   paths,
		}
		return m, nil

	case isKeyUp(msg):
		if m.tree.cursor > 0 {
			m.tree.cursor--
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyDown(msg):
		if m.tree.cursor < len(m.visible)-1 {
			m.tree.cursor++
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgUp(msg):
		m.tree.cursor -= m.tree.viewportHeight
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgDown(msg):
		m.tree.cursor += m.tree.viewportHeight
		if m.tree.cursor >= len(m.visible) {
			m.tree.cursor = len(m.visible) - 1
		}
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyHome(msg):
		m.tree.cursor = 0
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyEnd(msg):
		m.tree.cursor = len(m.visible) - 1
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyExpandAll(msg):
		m.toggleExpandAll()
		return m, nil

	case isKeyRight(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset += 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, true)
			}
		}
		return m, nil

	case isKeyLeft(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset -= 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, false)
			} else if node.IsChild {
				for i := m.tree.cursor - 1; i >= 0; i-- {
					if m.visible[i].IsBundle && m.visible[i].ContainerIdx == node.ContainerIdx {
						m.tree.cursor = i
						break
					}
				}
			}
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil
	}

	return m, nil
}
