package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func hasColSpec(specs []colSpec, id string) bool {
	for _, s := range specs {
		if s.id == id {
			return true
		}
	}
	return false
}

func TestVisibleColSpecs_TrustColumnsOfferedInCertLister(t *testing.T) {
	specs := visibleColSpecs(false)

	// M29 un-gated TRUST and STORES: they answer "does this machine trust
	// this certificate", which is the question the cert lister exists for.
	if !hasColSpec(specs, colIDStores) || !hasColSpec(specs, colIDTrust) {
		t.Error("TRUST and STORES must be offered in the cert lister")
	}
	// Regression guard: nine original columns, the two trust columns and the
	// five fingerprint columns.
	if len(specs) != 16 {
		var ids []string
		for _, s := range specs {
			ids = append(ids, s.id)
		}
		t.Errorf("expected 16 cert lister columns, got %d: %v", len(specs), ids)
	}
}

func TestVisibleColSpecs_StoreOnlyShownInStoreView(t *testing.T) {
	specs := visibleColSpecs(true)

	if !hasColSpec(specs, "stores") {
		t.Error("expected the STORES column in the store view")
	}
	if !hasColSpec(specs, "trust") {
		t.Error("expected the TRUST column in the store view")
	}
	if len(specs) != 16 {
		t.Errorf("expected 16 columns in the store view, got %d", len(specs))
	}
}

func TestColumnEditor_CertListerOffersTrustColumns(t *testing.T) {
	ce := newColumnEditorModel([]string{"subject"}, false)

	if len(ce.specs) != 16 {
		t.Errorf("expected the 16 cert lister columns, got %d", len(ce.specs))
	}
	out := ce.view(80)
	if !strings.Contains(out, "STORES") || !strings.Contains(out, "TRUST") {
		t.Errorf("TRUST and STORES must be offered in the cert lister editor:\n%s", out)
	}
}

func TestColumnEditor_StoreViewOffersStoreColumns(t *testing.T) {
	ce := newColumnEditorModel(defaultStoreCols(), true)

	out := ce.view(80)
	if !strings.Contains(out, "STORES") {
		t.Errorf("expected STORES in the store editor:\n%s", out)
	}
	if !strings.Contains(out, "TRUST") {
		t.Errorf("expected TRUST in the store editor:\n%s", out)
	}
}

func TestColumnEditor_ToggleRespectsFilteredSpecs(t *testing.T) {
	ce := newColumnEditorModel(nil, true)

	// Walk to the STORES entry and toggle it on.
	for i, s := range ce.specs {
		if s.id == "stores" {
			ce.cursor = i
			break
		}
	}
	ce.toggle()

	if !ce.isActive("stores") {
		t.Error("expected STORES to be enabled after toggling")
	}
}

func TestColumnEditor_ToggleOutOfRangeIsSafe(t *testing.T) {
	ce := newColumnEditorModel(nil, false)
	ce.cursor = 999
	ce.toggle() // must not panic
}

func TestStoresColumn_Value(t *testing.T) {
	shared := tsCert(t, "Shared Root")
	javaOnly := tsCert(t, "Corporate Root")

	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared, javaOnly),
	)

	var sharedNode, javaNode *TreeNode
	for i := range m.visible {
		switch {
		case strings.Contains(m.visible[i].Subject, "Shared Root") && sharedNode == nil:
			sharedNode = &m.visible[i]
		case strings.Contains(m.visible[i].Subject, "Corporate Root"):
			javaNode = &m.visible[i]
		}
	}
	if sharedNode == nil || javaNode == nil {
		t.Fatal("expected both certificates in the tree")
	}

	if got := singleColValue(*sharedNode, "stores"); got != "OS J21" {
		t.Errorf("expected 'OS J21' for the shared root, got %q", got)
	}
	if !sharedNode.StoresInAll {
		t.Error("the shared root is in every store")
	}

	if got := singleColValue(*javaNode, "stores"); got != "J21" {
		t.Errorf("expected 'J21' for the Java-only root, got %q", got)
	}
	if javaNode.StoresInAll {
		t.Error("a Java-only root is not in every store")
	}
}

func TestTrustColumn_AnchorWithoutTrustMap(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", tsCert(t, "Java Root")),
	)

	for _, n := range m.visible {
		if !n.IsChild {
			continue
		}
		// Java and Linux have no per-cert trust concept, so there is nothing to
		// fabricate: the certificate is in the store, which is ANCHOR. Per-policy
		// detail stays empty.
		if n.Trust != truststore.VerdictAnchor.Display() {
			t.Errorf("expected ANCHOR without a trust map, got %q", n.Trust)
		}
		if len(n.TrustPolicies) != 0 {
			t.Errorf("expected no per-policy detail without a trust map, got %v", n.TrustPolicies)
		}
	}
}

func TestTrustColumn_FromTrustMap(t *testing.T) {
	denied := tsCert(t, "Distrusted Root")
	trusted := tsCert(t, "Trusted Root")

	sc := tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", denied, trusted)
	sc.TrustMap = map[string]truststore.CertTrust{
		truststore.CertFingerprint(denied): {
			Overall:  truststore.TrustDenied,
			Policies: []truststore.TrustPolicy{{Purpose: "SSL", Status: truststore.TrustDenied}},
		},
		truststore.CertFingerprint(trusted): {Overall: truststore.TrustTrusted},
	}

	m := newStoreTestModel(t, sc)

	var deniedNode, trustedNode *TreeNode
	for i := range m.visible {
		switch {
		case strings.Contains(m.visible[i].Subject, "Distrusted"):
			deniedNode = &m.visible[i]
		case strings.Contains(m.visible[i].Subject, "Trusted Root"):
			trustedNode = &m.visible[i]
		}
	}
	if deniedNode == nil || trustedNode == nil {
		t.Fatal("expected both certificates")
	}

	if deniedNode.Trust != truststore.VerdictDenied.Display() {
		t.Errorf("expected DENIED, got %q", deniedNode.Trust)
	}
	if len(deniedNode.TrustPolicies) != 1 {
		t.Errorf("expected the per-policy detail, got %v", deniedNode.TrustPolicies)
	}
	if trustedNode.Trust != truststore.VerdictAnchor.Display() {
		t.Errorf("expected ANCHOR, got %q", trustedNode.Trust)
	}
}

func TestSanitizeStoreCols(t *testing.T) {
	if got := sanitizeStoreCols(nil); len(got) != 4 {
		t.Errorf("expected the default store columns, got %v", got)
	}
	if got := sanitizeStoreCols([]string{"subject", "not_a_column", "stores"}); len(got) != 2 {
		t.Errorf("expected unknown ids dropped, got %v", got)
	}
	if got := sanitizeStoreCols([]string{"bogus"}); len(got) != 4 {
		t.Errorf("an all-invalid list must fall back to defaults, got %v", got)
	}
}

func TestColSpecByID(t *testing.T) {
	if colSpecByID("stores") == nil {
		t.Error("expected the stores spec to resolve")
	}
	if colSpecByID("nope") != nil {
		t.Error("expected nil for an unknown column")
	}
}

func TestStoreColumns_RenderAllModesAndWidths(t *testing.T) {
	shared := tsCert(t, "Some Very Long Root Certificate Name For Testing")
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
	)
	m.storeCols = []string{"subject", "expiry", "algo", "stores", "trust"}
	m.rebuildTrustStoreTree()

	// Every mode/width combination must render without panicking, and at a
	// realistic terminal width truncate mode must fit.
	//
	// Narrow terminals are deliberately not asserted: the tree has a per-column
	// minimum, so 5+ active columns already overflow a 40-column terminal in the
	// cert lister too (5 cert-lister columns render 51 wide there, vs 49 for
	// this store set). That is pre-existing behaviour, not something the store
	// columns introduce. hscroll renders at natural width by design.
	for _, width := range []int{40, 60, 80, 200} {
		m.tree.width = width
		m.tree.viewportHeight = 20
		for _, mode := range []displayMode{displayTruncate, displayWrap, displayHScroll} {
			m.tree.displayMode = mode
			out := renderTree(m.visible, m.tree, false)
			if out == "" {
				t.Errorf("width %d mode %d: expected output", width, mode)
			}
			if mode != displayTruncate || width < 80 {
				continue
			}
			for _, line := range strings.Split(out, "\n") {
				if ansi.StringWidth(line) > width {
					t.Errorf("width %d truncate mode: line overflows (%d): %q",
						width, ansi.StringWidth(line), line)
				}
			}
		}
	}
}

func TestStoreColumns_HScrollRendersStoreColumns(t *testing.T) {
	shared := tsCert(t, "HScroll Root")
	m := newStoreTestModel(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
	)
	m.storeCols = []string{"subject", "stores"}
	m.rebuildTrustStoreTree()
	m.expandAll(true) // rebuilding re-folds the stores

	m.tree.width = 200
	m.tree.viewportHeight = 20
	m.tree.displayMode = displayHScroll

	out := renderTree(m.visible, m.tree, false)
	if !strings.Contains(out, "OS J21") {
		t.Errorf("expected the store tags in hscroll mode:\n%s", out)
	}
}
