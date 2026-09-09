package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func TestFunctionsMenu_HasTrustStoresEntry(t *testing.T) {
	items := buildFunctionsMenu()

	if len(items) != 4 {
		t.Fatalf("expected 4 function entries, got %d", len(items))
	}
	last := items[3]
	if last.key != "4" {
		t.Errorf("expected key 4, got %q", last.key)
	}
	if last.label != "Trust Stores" {
		t.Errorf("expected the Trust Stores label, got %q", last.label)
	}
	if last.kind != formTrustStore {
		t.Error("expected the formTrustStore kind")
	}
}

func TestFunctionsMenu_CursorOnTrustStores(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.openFunctionsMenu()

	if m.menu.cursor != 3 {
		t.Errorf("expected the cursor on Trust Stores, got %d", m.menu.cursor)
	}
}

func TestOpenTrustStores_EntersLoading(t *testing.T) {
	m := makeTestRootModel()
	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("OS", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	}}
	m.tuiOpts.TrustStoreLoader = stub.load

	cmd := m.openTrustStores()

	if m.currentRoot != rootTrustStore {
		t.Error("expected the trust store root view")
	}
	if m.state != stateLoading {
		t.Errorf("expected the loading state, got %v", m.state)
	}
	if cmd == nil {
		t.Fatal("expected a load command")
	}
}

func TestTrustStoreLoadedMsg_BuildsTree(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.storeGrouping = certops.GroupByInstance
	m.storeCols = defaultStoreCols()
	m.state = stateLoading

	stores := []truststore.StoreContents{
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", tsCert(t, "Root A")),
	}

	model, _ := m.handleTrustStoreLoaded(TrustStoreLoadedMsg{Stores: stores})
	got := model.(RootModel)

	if got.state != stateTree {
		t.Errorf("expected the tree state, got %v", got.state)
	}
	if len(got.trustStores) != 1 {
		t.Errorf("expected the stores cached, got %d", len(got.trustStores))
	}
	if len(got.visible) == 0 {
		t.Error("expected tree rows")
	}
	if got.tree.firstColHeader != headerStore {
		t.Errorf("expected the STORE header, got %q", got.tree.firstColHeader)
	}
}

func TestTrustStoreLoadedMsg_WarningsNotified(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.storeGrouping = certops.GroupByInstance
	m.storeCols = defaultStoreCols()

	model, _ := m.handleTrustStoreLoaded(TrustStoreLoadedMsg{
		Stores:   []truststore.StoreContents{tsStore("OS", truststore.StoreTypeOS, "/kc", tsCert(t, "R"))},
		Warnings: []string{"jssecacerts detected"},
	})
	got := model.(RootModel)

	if len(got.storeWarnings) != 1 {
		t.Errorf("expected the warnings kept, got %v", got.storeWarnings)
	}
}

func TestTrustStoreLoadedMsg_ErrorSurfaced(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.state = stateLoading

	model, _ := m.handleTrustStoreLoaded(TrustStoreLoadedMsg{
		Err: errors.New("no trust store could be read"),
	})
	got := model.(RootModel)

	if got.err == nil {
		t.Fatal("expected the error recorded")
	}
	if got.state != stateTree {
		t.Errorf("expected to land on the tree with an error banner, got %v", got.state)
	}

	// F must still work so the user is not stranded.
	model, _ = got.handleTreeKey(keyMsg("F"))
	if model.(RootModel).state != stateMenu {
		t.Error("the functions menu must remain reachable after a load failure")
	}
}

func TestRescan_ReloadsStoresNotFiles(t *testing.T) {
	m, stub := multiStoreModel(t)
	before := stub.calls

	model, cmd := m.handleTreeKey(keyMsg("r"))
	got := model.(RootModel)

	if got.state != stateLoading {
		t.Errorf("expected the loading state, got %v", got.state)
	}
	if cmd == nil {
		t.Fatal("expected a reload command")
	}

	// Running the command is what performs the read. tea.Batch returns a
	// BatchMsg holding the sub-commands, so they must be run individually.
	runCmd(cmd)
	if stub.calls != before+1 {
		t.Errorf("expected exactly one reload, got %d calls (was %d)", stub.calls, before)
	}
	if got.loadingMessage == "" || !strings.Contains(got.loadingMessage, "trust store") {
		t.Errorf("expected a store-specific loading message, got %q", got.loadingMessage)
	}
}

func TestViewSwitch_BackToStoresDoesNotReread(t *testing.T) {
	m, stub := multiStoreModel(t)
	before := stub.calls

	// Leave to the cert lister and come back.
	m.currentRoot = rootCertLister
	cmd := m.openTrustStores()

	if cmd != nil {
		t.Error("returning to cached stores must not issue a load command")
	}
	if stub.calls != before {
		t.Errorf("returning to the store view must not re-read: %d -> %d", before, stub.calls)
	}
	if m.state != stateTree {
		t.Errorf("expected the tree immediately, got %v", m.state)
	}
}

func TestCertListerSwitch_RestoresFilenameHeader(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.tuiOpts.ActiveCols = []string{"subject", "issuer"}

	m.menu.activate("Functions", buildFunctionsMenu(), "")
	m.menu.cursor = 0
	model, _ := m.handleMenuKey(tea.KeyMsg{Type: tea.KeyEnter})
	got := model.(RootModel)

	if got.currentRoot != rootCertLister {
		t.Fatalf("expected the cert lister root, got %v", got.currentRoot)
	}
	if got.tree.firstColHeader != headerFilename {
		t.Errorf("expected FILENAME restored, got %q", got.tree.firstColHeader)
	}
	if strings.Join(got.tree.activeCols, ",") != "subject,issuer" {
		t.Errorf("expected the cert lister columns restored, got %v", got.tree.activeCols)
	}
}

func TestOptions_ReducedInStoreView(t *testing.T) {
	m, _ := multiStoreModel(t)

	snap := m.currentScanSnapshot()
	if !snap.StoreView {
		t.Fatal("expected the snapshot to know it is the store view")
	}

	editor := newOptionsModel(snap, nil)
	var ids []string
	for _, d := range editor.defs {
		ids = append(ids, d.key)
	}

	for _, hidden := range []string{"recursive", "max_depth", "signature_scan", "auto_discover"} {
		if slicesContains(ids, hidden) {
			t.Errorf("scan option %q must be hidden in the store view (got %v)", hidden, ids)
		}
	}
	if !slicesContains(ids, "store_grouping") {
		t.Errorf("expected the grouping option, got %v", ids)
	}
	if !slicesContains(ids, "path_display") {
		t.Errorf("expected path display to remain, got %v", ids)
	}
}

func TestOptions_UnchangedForCertLister(t *testing.T) {
	m := makeTestRootModel()
	editor := newOptionsModel(m.currentScanSnapshot(), nil)

	var ids []string
	for _, d := range editor.defs {
		ids = append(ids, d.key)
	}
	if slicesContains(ids, "store_grouping") {
		t.Errorf("the grouping option must not appear in the cert lister, got %v", ids)
	}
	if len(editor.defs) != 6 {
		t.Errorf("expected 6 cert lister options, got %d: %v", len(editor.defs), ids)
	}
}

func TestOptions_GroupingChangeRebuildsTree(t *testing.T) {
	m, stub := multiStoreModel(t)
	before := stub.calls

	m.optionsEditor = newOptionsModel(m.currentScanSnapshot(), nil)
	m.optionsReturn = stateTree
	m.state = stateOptions

	// Cycle the grouping choice, then close the editor.
	m.optionsEditor.cycleChoice("store_grouping", 1)
	model, _ := m.handleOptionsKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)

	if got.storeGrouping != certops.GroupByKind {
		t.Errorf("expected the grouping applied, got %q", got.storeGrouping)
	}
	if got.state != stateTree {
		t.Errorf("expected to return to the tree, got %v", got.state)
	}
	if stub.calls != before {
		t.Error("a grouping change must not re-read the stores")
	}
}

func TestTreeTitle_NamesStoreCountAndGrouping(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.width = 120

	title := m.treeTitleLine()
	if !strings.Contains(title, "Trust stores") {
		t.Errorf("expected a store-specific title, got %q", title)
	}
	if !strings.Contains(title, "4 loaded") {
		t.Errorf("expected the store count, got %q", title)
	}
	if !strings.Contains(title, "instance") {
		t.Errorf("expected the grouping mode, got %q", title)
	}
}

func TestFooterHints_StoreViewKeys(t *testing.T) {
	m, _ := multiStoreModel(t)
	hints, _ := m.treeFooterHints()

	var keys []string
	for _, h := range hints {
		keys = append(keys, h.Key)
	}

	for _, want := range []string{"g", "E", "V"} {
		if !slicesContains(keys, want) {
			t.Errorf("expected the %q hint in the store view, got %v", want, keys)
		}
	}
	for _, unwanted := range []string{"n", "a", "m", "Ctrl+D"} {
		if slicesContains(keys, unwanted) {
			t.Errorf("write action %q must not be advertised in the store view", unwanted)
		}
	}
}

func slicesContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// runCmd executes a tea.Cmd, descending into tea.Batch results.
func runCmd(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			runCmd(sub)
		}
	}
}
