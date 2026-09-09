package tui

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func groupHeaders(m RootModel) []string {
	var out []string
	for _, n := range m.visible {
		if n.IsBundle {
			out = append(out, n.Filename)
		}
	}
	return out
}

func multiStoreModel(t *testing.T) (RootModel, *loaderStub) {
	t.Helper()
	shared := tsCert(t, "Shared Root")
	osOnly := tsCert(t, "OS Only Root")
	javaOnly := tsCert(t, "Java Only Root")

	return newStoreTestModelWithLoader(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc1", shared, osOnly),
		tsStore("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21", shared, javaOnly),
		tsStore("Java 17 (Corretto)", truststore.StoreTypeJava, "/jdk17", shared),
		tsStore("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", shared),
	)
}

func TestGroupingToggle_Cycles(t *testing.T) {
	m, _ := multiStoreModel(t)

	if got := len(groupHeaders(m)); got != 4 {
		t.Fatalf("expected 4 instance groups, got %d: %v", got, groupHeaders(m))
	}

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.storeGrouping != certops.GroupByKind {
		t.Fatalf("expected kind grouping, got %q", m.storeGrouping)
	}
	headers := groupHeaders(m)
	if len(headers) != 3 {
		t.Fatalf("expected 3 kind groups, got %d: %v", len(headers), headers)
	}
	if !strings.HasPrefix(headers[0], "System") {
		t.Errorf("expected the System group first, got %q", headers[0])
	}
	if !strings.Contains(headers[1], "2 stores") {
		t.Errorf("expected the Java group to name the instance count, got %q", headers[1])
	}

	model, _ = m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.storeGrouping != certops.GroupByInstance {
		t.Fatalf("expected instance grouping again, got %q", m.storeGrouping)
	}
	if got := len(groupHeaders(m)); got != 4 {
		t.Errorf("expected 4 instance groups again, got %d", got)
	}
}

func TestGroupingToggle_DedupsInKindMode(t *testing.T) {
	m, _ := multiStoreModel(t)

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)
	m.expandAll(true) // regrouping rebuilds the tree folded

	// Java 21 has [shared, javaOnly], Java 17 has [shared] -> 2 unique.
	var javaChildren int
	inJava := false
	for _, n := range m.visible {
		if n.IsBundle {
			inJava = strings.HasPrefix(n.Filename, "Java")
			continue
		}
		if inJava && n.IsChild {
			javaChildren++
		}
	}
	if javaChildren != 2 {
		t.Errorf("expected 2 unique Java certificates, got %d", javaChildren)
	}
}

func TestGroupingToggle_DoesNotReread(t *testing.T) {
	m, stub := multiStoreModel(t)
	before := stub.calls

	for i := 0; i < 4; i++ {
		model, _ := m.handleTreeKey(keyMsg("g"))
		m = model.(RootModel)
	}

	if stub.calls != before {
		t.Errorf("regrouping must not re-read stores: %d -> %d calls", before, stub.calls)
	}
}

func TestGroupingToggle_PreservesSearchAndColumns(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.storeCols = []string{"subject", "stores"}
	m.rebuildTrustStoreTree()
	m.tree.displayMode = displayWrap
	m.search.filterText = "shared"
	m.recomputeVisible()

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.search.filterText != "shared" {
		t.Errorf("the search filter must survive a regroup, got %q", m.search.filterText)
	}
	if m.tree.displayMode != displayWrap {
		t.Error("the display mode must survive a regroup")
	}
	if strings.Join(m.tree.activeCols, ",") != "subject,stores" {
		t.Errorf("the active columns must survive a regroup, got %v", m.tree.activeCols)
	}
	// And the filter is actually reapplied to the new tree.
	for _, n := range m.visible {
		if n.IsChild && !strings.Contains(strings.ToLower(n.Searchable), "shared") {
			t.Errorf("filter not reapplied: %q", n.Subject)
		}
	}
}

func TestGroupingToggle_ResetsCursor(t *testing.T) {
	m, _ := multiStoreModel(t)
	m.tree.cursor = len(m.visible) - 1
	m.tree.offset = 3

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.tree.cursor != 0 {
		t.Errorf("expected the cursor reset, got %d", m.tree.cursor)
	}
	if m.tree.offset != 0 {
		t.Errorf("expected the offset reset, got %d", m.tree.offset)
	}
}

func TestGroupingToggle_CursorClampedAfterRegroup(t *testing.T) {
	m, _ := multiStoreModel(t)

	// Cursor on the last row of the largest group, then regroup to a smaller tree.
	m.tree.cursor = len(m.visible) - 1
	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.tree.cursor >= len(m.visible) {
		t.Fatalf("cursor %d out of range for %d rows", m.tree.cursor, len(m.visible))
	}
}

func TestGroupingToggle_InertInCertLister(t *testing.T) {
	m := makeTestRootModel()
	before := m.storeGrouping

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if m.storeGrouping != before {
		t.Error("g must not regroup outside the trust store view")
	}
}

func TestGroupingToggle_PersistsToConfig(t *testing.T) {
	m, _ := multiStoreModel(t)

	var savedGrouping string
	var savedCols []string
	m.saveStoreOpts = func(cols []string, grouping string) error {
		savedCols = cols
		savedGrouping = grouping
		return nil
	}

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	if savedGrouping != string(certops.GroupByKind) {
		t.Errorf("expected the grouping persisted, got %q", savedGrouping)
	}
	if len(savedCols) == 0 {
		t.Error("expected the store columns persisted alongside")
	}
}

func TestGroupingToggle_KindModeStoresColumnNamesInstances(t *testing.T) {
	m, _ := multiStoreModel(t)

	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)
	m.expandAll(true) // regrouping rebuilds the tree folded

	// The shared root lives in all four stores; kind mode must still name them
	// individually, which is what makes the column useful after merging.
	for _, n := range m.visible {
		if !n.IsChild || !strings.Contains(n.Subject, "Shared Root") {
			continue
		}
		got := singleColValue(n, "stores")
		if !strings.Contains(got, "J21") || !strings.Contains(got, "J17") {
			t.Errorf("expected instance tags in kind mode, got %q", got)
		}
		return
	}
	t.Fatal("shared root not found")
}
