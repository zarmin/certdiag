package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func readOnlyTestModel(t *testing.T) RootModel {
	t.Helper()
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", tsCert(t, "Root A"), tsCert(t, "Root B")),
	)
	// Park the cursor on a certificate row, the most dangerous position.
	for i := range m.visible {
		if m.visible[i].IsChild {
			m.tree.cursor = i
			break
		}
	}
	return m
}

func TestReadOnly_DeleteSuppressed(t *testing.T) {
	m := readOnlyTestModel(t)

	model, _ := m.handleTreeKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)

	if got.confirmDelete {
		t.Error("ctrl+d must never arm a delete on a trust store node")
	}
	if got.deleteFilePath != "" {
		t.Errorf("no delete target may be set, got %q", got.deleteFilePath)
	}
	if got.state != stateTree {
		t.Errorf("expected to stay on the tree, got state %v", got.state)
	}
}

func TestReadOnly_DeleteSuppressedOnGroupHeader(t *testing.T) {
	m := readOnlyTestModel(t)
	m.tree.cursor = 0 // group header

	model, _ := m.handleTreeKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)

	if got.confirmDelete || got.deleteFilePath != "" {
		t.Error("ctrl+d must not target a store file")
	}
}

func TestReadOnly_ActionMenuSuppressed(t *testing.T) {
	m := readOnlyTestModel(t)

	model, _ := m.handleTreeKey(keyMsg("a"))
	got := model.(RootModel)

	if got.state == stateMenu {
		t.Error("the actions menu must not open for a trust store node")
	}
}

func TestReadOnly_BuildActionMenuReturnsNil(t *testing.T) {
	node := TreeNode{
		Container:   &certlib.CertContainer{Source: certlib.SourceTrustStore},
		Item:        &certlib.CertItem{Type: certlib.ContentCertificate},
		ContentType: "der/cert",
	}
	if items := buildActionMenu(node); items != nil {
		t.Errorf("expected no actions for a trust store node, got %v", items)
	}
}

func TestReadOnly_NewAndMultiSelectAndSaveSuppressed(t *testing.T) {
	for _, key := range []string{"n", "m", "s"} {
		m := readOnlyTestModel(t)
		model, _ := m.handleTreeKey(keyMsg(key))
		got := model.(RootModel)

		if got.state != stateTree {
			t.Errorf("key %q must be inert in the store view, moved to state %v", key, got.state)
		}
		if got.multiSelectActive {
			t.Errorf("key %q must not start multi-select", key)
		}
	}
}

func TestReadOnly_GuardIsOnSourceNotView(t *testing.T) {
	// A trust store container reached from the cert lister root must still be
	// read-only: the guard is on the data, not on which screen is active.
	m := readOnlyTestModel(t)
	m.currentRoot = rootCertLister

	model, _ := m.handleTreeKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)

	if got.confirmDelete || got.deleteFilePath != "" {
		t.Error("read-only enforcement must not depend on the active root view")
	}

	model, _ = m.handleTreeKey(keyMsg("a"))
	if model.(RootModel).state == stateMenu {
		t.Error("the actions menu must stay closed for trust store data")
	}
}

func TestReadOnly_FileNodesStillMutable(t *testing.T) {
	// The guard must not leak into the cert lister: normal file nodes keep
	// their actions.
	m := makeTestRootModel()
	m.tree.cursor = 0

	if m.visible[0].isReadOnlySource() {
		t.Fatal("a scanned file node must not be read-only")
	}

	model, _ := m.handleTreeKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)
	if !got.confirmDelete {
		t.Error("ctrl+d must still work for scanned files")
	}
}

func TestIsReadOnlySource(t *testing.T) {
	tests := []struct {
		name string
		node TreeNode
		want bool
	}{
		{"trust store", TreeNode{Container: &certlib.CertContainer{Source: certlib.SourceTrustStore}}, true},
		{"file", TreeNode{Container: &certlib.CertContainer{Source: certlib.SourceFile}}, false},
		// A served chain is not ours to edit either (M30a part IV); saving it
		// stays an explicit remote save action.
		{"remote", TreeNode{Container: &certlib.CertContainer{Source: certlib.SourceRemote}}, true},
		{"pcap", TreeNode{Container: &certlib.CertContainer{Source: certlib.SourcePcap}}, false},
		{"no container", TreeNode{}, false},
	}
	for _, tt := range tests {
		if got := tt.node.isReadOnlySource(); got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestReadOnly_SplitViewAlsoGuarded(t *testing.T) {
	m := readOnlyTestModel(t)
	m.state = stateSplit

	model, _ := m.handleSplitKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)

	if got.confirmDelete || got.deleteFilePath != "" {
		t.Error("the split view must enforce read-only too")
	}
}
