package tui

import (
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// --- Navigation ---

func (m *RootModel) currentNavEntry() navEntry {
	entry := navEntry{
		treeCursor: m.tree.cursor,
		treeOffset: m.tree.offset,
	}
	if m.detail != nil {
		entry.ref = m.detail.node.Ref
		entry.detailScroll = m.detail.scrollOffset
	}
	return entry
}

func (m *RootModel) pushCurrentToHistory() {
	m.history.push(m.currentNavEntry())
}

func (m *RootModel) navigateToSelectedRelation() {
	if m.detail == nil {
		return
	}
	sel := m.detail.selectedLine()
	if sel == nil || !sel.navigable {
		return
	}

	m.pushCurrentToHistory()
	m.navigateToRef(sel.targetRef)
}

func (m *RootModel) navigateToRef(ref certlib.ItemRef) {
	node := m.findNodeByRef(ref)
	if node == nil {
		return
	}

	m.syncTreeToRef(ref)
	m.detail = newDetailModel(*node, m.structured, m.store, m.opts, m.width, m.height)
}

func (m *RootModel) navigateBack() {
	entry, ok := m.history.goBack(m.currentNavEntry())
	if !ok {
		return
	}
	m.restoreNavEntry(entry)
}

func (m *RootModel) navigateForward() {
	entry, ok := m.history.goForward(m.currentNavEntry())
	if !ok {
		return
	}
	m.restoreNavEntry(entry)
}

func (m *RootModel) restoreNavEntry(entry navEntry) {
	node := m.findNodeByRef(entry.ref)
	if node == nil {
		return
	}

	found := m.syncTreeToRef(entry.ref)
	if !found {
		m.tree.cursor = entry.treeCursor
	}
	m.tree.offset = entry.treeOffset
	m.tree.clampCursor(len(m.visible))

	m.detail = newDetailModel(*node, m.structured, m.store, m.opts, m.width, m.height)
	m.detail.scrollOffset = entry.detailScroll
}

func (m *RootModel) findNodeByRef(ref certlib.ItemRef) *TreeNode {
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.ContainerIdx == ref.ContainerIdx && n.ItemIdx == ref.ItemIdx {
			return n
		}
	}
	return nil
}

func (m *RootModel) syncTreeToRef(ref certlib.ItemRef) bool {
	// Ensure parent bundle is expanded if target is a child
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.IsBundle && n.ContainerIdx == ref.ContainerIdx {
			n.Expanded = true
			break
		}
	}

	// Clear search filter if target would be hidden
	if m.search.filterText != "" {
		m.search.filterText = ""
		m.search.textInput.SetValue("")
	}

	m.recomputeVisible()

	// Find the target in visible and set cursor
	found := false
	for i, v := range m.visible {
		if v.ContainerIdx == ref.ContainerIdx && v.ItemIdx == ref.ItemIdx {
			m.tree.cursor = i
			found = true
			break
		}
	}
	m.tree.clampCursor(len(m.visible))
	return found
}
