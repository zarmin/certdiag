package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// --- columns ---

func TestFingerprintColumns_Registered(t *testing.T) {
	for _, algo := range certlib.FingerprintAlgos {
		id := "fp_" + string(algo)
		spec := colSpecByID(id)
		if spec == nil {
			t.Fatalf("expected a column spec for %s", id)
		}
		if spec.storeOnly {
			t.Errorf("%s must be available in both views", id)
		}
		if spec.fixedWidth != 0 {
			// A fixedWidth column is padded to that width unconditionally, and a
			// SHA-512 hex-colon value is 191 chars -- it would blow out the row.
			t.Errorf("%s must use proportion, not fixedWidth", id)
		}
	}
}

func TestFingerprintColumns_OfferedInBothViews(t *testing.T) {
	for _, storeView := range []bool{false, true} {
		specs := visibleColSpecs(storeView)
		for _, algo := range certlib.FingerprintAlgos {
			id := "fp_" + string(algo)
			if !hasColSpec(specs, id) {
				t.Errorf("storeView=%v: expected %s to be offered", storeView, id)
			}
		}
	}
}

func TestBuildItemNode_PopulatesFingerprints(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHex)

	var certNode, keyNode *TreeNode
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.Item == nil {
			continue
		}
		if n.Item.Type == certlib.ContentCertificate && certNode == nil {
			certNode = n
		}
		if n.Item.Type == certlib.ContentPrivateKey && keyNode == nil {
			keyNode = n
		}
	}
	if certNode == nil {
		t.Fatal("expected a certificate node")
	}
	if len(certNode.Fingerprints) != len(certlib.FingerprintAlgos) {
		t.Errorf("expected %d fingerprints, got %d",
			len(certlib.FingerprintAlgos), len(certNode.Fingerprints))
	}
	if keyNode != nil && len(keyNode.Fingerprints) != 0 {
		t.Error("a private key node must carry no certificate fingerprints")
	}
}

func TestSingleColValue_Fingerprints(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHex)
	node := firstCertNode(t, m)

	for _, algo := range certlib.FingerprintAlgos {
		want := certlib.CertFingerprint(node.Item.Certificate, algo, certlib.FingerprintHex)
		if got := singleColValue(*node, "fp_"+string(algo)); got != want {
			t.Errorf("%s: expected %q, got %q", algo, want, got)
		}
	}

	// A non-certificate row renders blank rather than a stale value.
	blank := TreeNode{}
	if got := singleColValue(blank, "fp_sha256"); got != "" {
		t.Errorf("expected empty value for a node with no certificate, got %q", got)
	}
}

func TestConvertStore_FingerprintFormatHonoured(t *testing.T) {
	for _, format := range certlib.FingerprintFormats {
		m := newFingerprintModel(t, format)
		node := firstCertNode(t, m)

		want := certlib.CertFingerprint(node.Item.Certificate, certlib.FingerprintSHA256, format)
		if got := node.Fingerprints[certlib.FingerprintSHA256]; got != want {
			t.Errorf("format %q: expected %q, got %q", format, want, got)
		}
	}
}

func TestFingerprintColumns_RenderAllModes(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHexColon)
	m.tree.activeCols = []string{"subject", "fp_sha256", "fp_sha512"}
	m.recomputeVisible()

	for _, width := range []int{40, 80, 200} {
		m.tree.width = width
		m.tree.viewportHeight = 20
		for _, mode := range []displayMode{displayTruncate, displayWrap, displayHScroll} {
			m.tree.displayMode = mode
			if out := renderTree(m.visible, m.tree, false); out == "" {
				t.Errorf("width %d mode %d: expected output", width, mode)
			}
		}
	}
}

func TestFingerprintColumns_HScrollShowsFullValue(t *testing.T) {
	// hscroll renders at natural width, which is how the full digest is read
	// in the tree; truncate mode is expected to clip.
	m := newFingerprintModel(t, certlib.FingerprintHexColon)
	m.tree.activeCols = []string{"fp_sha256"}
	m.recomputeVisible()
	m.tree.width = 200
	m.tree.viewportHeight = 20
	m.tree.displayMode = displayHScroll

	node := firstCertNode(t, m)
	full := node.Fingerprints[certlib.FingerprintSHA256]

	if out := renderTree(m.visible, m.tree, false); !strings.Contains(out, full) {
		t.Errorf("expected the full %d-char fingerprint in hscroll output", len(full))
	}
}

// --- detail pane ---

func TestDetailPane_ShowsAllFiveFingerprints(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHex)
	node := firstCertNode(t, m)

	d := newDetailModel(*node, m.structured, m.store, m.opts, 200, 60)

	var labels []string
	for _, line := range d.contentLines {
		for _, algo := range certlib.FingerprintAlgos {
			if strings.HasPrefix(line.text, algo.Label()+":") {
				labels = append(labels, algo.Label())
			}
		}
	}
	if len(labels) != len(certlib.FingerprintAlgos) {
		t.Errorf("expected all %d fingerprints in the detail pane, got %v",
			len(certlib.FingerprintAlgos), labels)
	}
}

func TestDetailPane_FingerprintFormatHonoured(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintBase64)
	node := firstCertNode(t, m)

	d := newDetailModel(*node, m.structured, m.store, m.opts, 200, 60)
	want := certlib.CertFingerprint(node.Item.Certificate, certlib.FingerprintSHA256, certlib.FingerprintBase64)

	var found bool
	for _, line := range d.contentLines {
		if strings.Contains(line.text, want) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the base64 SHA-256 %q in the detail pane", want)
	}
}

// --- options plumbing ---

func TestOptions_FingerprintFormatOffered(t *testing.T) {
	for _, storeView := range []bool{false, true} {
		snap := scanOptionSnapshot{StoreView: storeView, FingerprintFormat: string(certlib.FingerprintHex)}
		editor := newOptionsModel(snap, nil)

		var found bool
		for _, d := range editor.defs {
			if d.key == "fingerprint_format" {
				found = true
			}
		}
		if !found {
			t.Errorf("storeView=%v: expected the fingerprint format option", storeView)
		}
	}
}

func TestOptions_FingerprintFormatCycles(t *testing.T) {
	editor := newOptionsModel(scanOptionSnapshot{
		FingerprintFormat: string(certlib.FingerprintHex),
	}, nil)

	editor.cycleChoice("fingerprint_format", 1)
	if got := editor.snapshot().FingerprintFormat; got != string(certlib.FingerprintHexColon) {
		t.Errorf("expected hex-colon after one step, got %q", got)
	}
	if !editor.displayChanged {
		t.Error("a format change must mark the display dirty so the tree re-renders")
	}
	if editor.changed || editor.storeChanged {
		t.Error("a format change must not trigger a rescan or a regroup")
	}

	editor.cycleChoice("fingerprint_format", 1)
	editor.cycleChoice("fingerprint_format", 1)
	if got := editor.snapshot().FingerprintFormat; got != string(certlib.FingerprintHex) {
		t.Errorf("expected the choice to wrap back to hex, got %q", got)
	}
}

func TestApplyOptionsSnapshot_StampsOpts(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHex)

	snap := m.currentScanSnapshot()
	snap.FingerprintFormat = string(certlib.FingerprintBase64)
	m.applyOptionsSnapshot(snap)

	if m.fingerprintFormat != certlib.FingerprintBase64 {
		t.Errorf("expected the model updated, got %q", m.fingerprintFormat)
	}
	// The ConvertStore that follows reads m.opts, not m.fingerprintFormat.
	if m.opts.FingerprintFormat != certlib.FingerprintBase64 {
		t.Errorf("expected opts re-stamped, got %q", m.opts.FingerprintFormat)
	}
}

// TestScanComplete_PreservesFingerprintFormat guards the trap that the scan
// goroutine builds OutputOptions with no access to the model, so m.opts is
// replaced wholesale when the scan lands.
func TestScanComplete_PreservesFingerprintFormat(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHexColon)

	model, _ := m.Update(ScanCompleteMsg{
		Store: m.store,
		Opts:  output.OutputOptions{}, // as produced by the scan goroutine
	})
	got := model.(RootModel)

	if got.opts.FingerprintFormat != certlib.FingerprintHexColon {
		t.Errorf("scan completion wiped the display format: %q", got.opts.FingerprintFormat)
	}
	for _, n := range got.allNodes {
		if n.Item == nil || n.Item.Certificate == nil {
			continue
		}
		if !strings.Contains(n.Fingerprints[certlib.FingerprintSHA256], ":") {
			t.Error("nodes rebuilt after a scan must use the configured format")
		}
		break
	}
}

func TestRebuildTrustStoreTree_PreservesFingerprintFormat(t *testing.T) {
	m, _ := newStoreTestModelWithLoader(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)
	m.fingerprintFormat = certlib.FingerprintHexColon
	m.rebuildTrustStoreTree()

	if m.opts.FingerprintFormat != certlib.FingerprintHexColon {
		t.Errorf("trust store rebuild wiped the display format: %q", m.opts.FingerprintFormat)
	}
}

// TestDisplayChange_InStoreViewKeepsStoreColumns guards the store-only columns,
// which ConvertStore does not populate -- they are filled separately and would
// blank out if a display change rebuilt nodes without re-decorating them.
func TestDisplayChange_InStoreViewKeepsStoreColumns(t *testing.T) {
	shared := tsCert(t, "Shared Root")
	m, _ := newStoreTestModelWithLoader(t,
		tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
	)

	m.optionsEditor = newOptionsModel(m.currentScanSnapshot(), nil)
	m.optionsReturn = stateTree
	m.state = stateOptions
	m.optionsEditor.cycleChoice("fingerprint_format", 1)

	model, _ := m.handleOptionsKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := model.(RootModel)
	got.expandAll(true) // the rebuild re-folds the stores; this test is about child rows

	var checked bool
	for _, n := range got.visible {
		if !n.IsChild {
			continue
		}
		checked = true
		if len(n.Stores) == 0 {
			t.Error("the STORES column blanked out after a display change")
		}
		if n.Fingerprints[certlib.FingerprintSHA256] == "" {
			t.Error("expected fingerprints on the rebuilt node")
		}
	}
	if !checked {
		t.Fatal("expected certificate rows")
	}
}

func TestSavedOptions_IncludesFingerprintFormat(t *testing.T) {
	m := newFingerprintModel(t, certlib.FingerprintHex)
	m.optionsEditor = newOptionsModel(m.currentScanSnapshot(), nil)
	m.optionsEditor.cycleChoice("fingerprint_format", 1)

	var saved SavedOptions
	m.saveOptions = func(o SavedOptions) error {
		saved = o
		return nil
	}
	m.state = stateOptions
	m.handleOptionsKey(keyMsg("s"))

	if saved.FingerprintFormat != string(certlib.FingerprintHexColon) {
		t.Errorf("expected the format persisted, got %q", saved.FingerprintFormat)
	}
}

// --- helpers ---

func newFingerprintModel(t *testing.T, format certlib.FingerprintFormat) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	msg := scanTestCerts(t)
	m := makeTestRootModel()
	m.fingerprintFormat = format
	m.store = msg.Store
	m.structured = msg.Structured
	m.opts = m.stampDisplayOpts(msg.Opts)
	m.allNodes = ConvertStore(msg.Store, m.opts, m.pathDisplay)
	m.recomputeVisible()
	return m
}

func firstCertNode(t *testing.T, m RootModel) *TreeNode {
	t.Helper()
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.Item != nil && n.Item.Certificate != nil {
			return n
		}
	}
	t.Fatal("no certificate node found")
	return nil
}
