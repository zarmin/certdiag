package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// foldTestModel builds a Cert Lister over three bundle containers, through the
// real ConvertStore path so the Expanded default is exercised, not assumed.
func foldTestModel(t *testing.T, names ...string) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	store := certlib.NewCertStore()
	for _, name := range names {
		store.AddContainer(certlib.CertContainer{
			FilePath: "/tmp/" + name,
			Format:   certlib.FormatPKCS12,
			Source:   certlib.SourceFile,
			Items: []certlib.CertItem{
				{Type: certlib.ContentCertificate},
				{Type: certlib.ContentPrivateKey},
			},
		})
	}

	m := makeTestRootModel()
	m.store = store
	m.allNodes = ConvertStore(store, output.OutputOptions{}, m.pathDisplay)
	m.recomputeVisible()
	m.tree.cursor = 0
	return m
}

func pressFold(t *testing.T, m RootModel) RootModel {
	t.Helper()
	model, _ := m.handleTreeKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'z'}})
	return model.(RootModel)
}

func expandedCount(m RootModel) int {
	n := 0
	for _, node := range m.allNodes {
		if node.IsBundle && node.Expanded {
			n++
		}
	}
	return n
}

func TestExpandAll_ToggleCollapsesThenExpands(t *testing.T) {
	m := foldTestModel(t, "a.p12", "b.p12", "c.p12")
	if got := expandedCount(m); got != 3 {
		t.Fatalf("expected three expanded bundles to start, got %d", got)
	}
	if len(m.visible) != 9 { // 3 headers + 6 children
		t.Fatalf("expected 9 visible rows, got %d", len(m.visible))
	}

	m = pressFold(t, m)
	if got := expandedCount(m); got != 0 {
		t.Errorf("z must collapse every bundle, %d still expanded", got)
	}
	if len(m.visible) != 3 {
		t.Errorf("expected only the 3 headers visible, got %d", len(m.visible))
	}

	m = pressFold(t, m)
	if got := expandedCount(m); got != 3 {
		t.Errorf("z on a fully collapsed tree must expand every bundle, got %d", got)
	}
	if len(m.visible) != 9 {
		t.Errorf("expected 9 visible rows again, got %d", len(m.visible))
	}
}

// TestExpandAll_MixedStateCollapses: any expanded bundle means the toggle folds.
// Without this the key would oscillate on a half-open tree.
func TestExpandAll_MixedStateCollapses(t *testing.T) {
	m := foldTestModel(t, "a.p12", "b.p12", "c.p12")
	m.allNodes[0].Expanded = false
	m.recomputeVisible()

	m = pressFold(t, m)
	if got := expandedCount(m); got != 0 {
		t.Errorf("a mixed tree must collapse, %d bundles still expanded", got)
	}
}

func TestExpandAll_CursorRepair(t *testing.T) {
	m := foldTestModel(t, "a.p12", "b.p12", "c.p12")
	// Row 4 is a child of the second bundle (0,1,2 = header+children of the first).
	m.tree.cursor = 4
	if !m.visible[4].IsChild {
		t.Fatalf("test setup: row 4 is not a child row")
	}
	wantContainer := m.visible[4].ContainerIdx

	m = pressFold(t, m)

	cur := m.visible[m.tree.cursor]
	if !cur.IsBundle {
		t.Errorf("cursor must land on a bundle row after its child folded away, got %+v", cur.Filename)
	}
	if cur.ContainerIdx != wantContainer {
		t.Errorf("cursor moved to the wrong bundle: want container %d, got %d", wantContainer, cur.ContainerIdx)
	}
}

// TestExpandAll_RespectsFilter: folding acts on what is on screen. A container
// the filter hides must keep the state the user left it in.
func TestExpandAll_RespectsFilter(t *testing.T) {
	m := foldTestModel(t, "alpha.p12", "beta.p12")
	m.search.filterText = "alpha"
	m.recomputeVisible()

	m = pressFold(t, m)

	var alpha, beta *TreeNode
	for i := range m.allNodes {
		if !m.allNodes[i].IsBundle {
			continue // child rows carry the container filename too
		}
		switch m.allNodes[i].Filename {
		case "alpha.p12":
			alpha = &m.allNodes[i]
		case "beta.p12":
			beta = &m.allNodes[i]
		}
	}
	if alpha == nil || beta == nil {
		t.Fatal("test setup: bundles not found")
	}
	if alpha.Expanded {
		t.Error("the filtered-in bundle must collapse")
	}
	if !beta.Expanded {
		t.Error("a bundle hidden by the filter must keep its state")
	}
}

func TestExpandAll_MultiSelect(t *testing.T) {
	m := foldTestModel(t, "a.p12", "b.p12")
	m.multiSelect = newMultiSelectModel()
	m.multiSelectActive = true
	m.state = stateMultiSelect
	m.multiSelect.toggle(m.visible[1], m.allNodes)
	before := m.multiSelect.count()
	if before == 0 {
		t.Fatal("test setup: nothing selected")
	}

	model, _ := m.handleMultiSelectKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'z'}})
	m = model.(RootModel)

	if got := expandedCount(m); got != 0 {
		t.Errorf("z must fold in multi-select mode too, %d bundles still expanded", got)
	}
	if m.multiSelect.count() != before {
		t.Errorf("folding must not disturb the selection: had %d, now %d", before, m.multiSelect.count())
	}
}

// TestCertLister_StartsExpanded and TestTrustStoreView_StartsCollapsed pin the
// discriminator: it is the container source, never the active root view.
func TestCertLister_StartsExpanded(t *testing.T) {
	m := foldTestModel(t, "a.p12")
	if expandedCount(m) != 1 {
		t.Error("file bundles must start expanded in the Cert Lister")
	}
}

func TestTrustStoreView_StartsCollapsed(t *testing.T) {
	m, _ := newStoreTestModelWithLoader(t, tsStore("OS Trust Store", truststore.StoreTypeOS, "/os", tsCert(t, "Root A"), tsCert(t, "Root B")))
	for _, n := range m.allNodes {
		if n.IsBundle && n.Expanded {
			t.Errorf("trust store %q must start collapsed", n.Filename)
		}
	}
	for _, n := range m.visible {
		if n.IsChild {
			t.Errorf("no child rows should be visible before expanding, saw %q", n.Filename)
		}
	}
}

func TestHintBar_ShowsFold(t *testing.T) {
	m := foldTestModel(t, "a.p12")
	hints, _ := m.treeFooterHints()
	if !hintsContain(hints, "z") {
		t.Error("the Cert Lister hint bar must advertise z")
	}

	sm := newStoreTestModel(t, tsStore("OS Trust Store", truststore.StoreTypeOS, "/os", tsCert(t, "Root A")))
	storeHints, _ := sm.treeFooterHints()
	if !hintsContain(storeHints, "z") {
		t.Error("the trust store hint bar must advertise z")
	}
}

func hintsContain(hints []Hint, key string) bool {
	for _, h := range hints {
		if strings.EqualFold(h.Key, key) {
			return true
		}
	}
	return false
}
