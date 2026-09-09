package tui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func makeTestNodes() []TreeNode {
	bundleContainer := &certlib.CertContainer{
		FilePath: "/tmp/bundle.p12",
		Format:   certlib.FormatPKCS12,
		Items: []certlib.CertItem{
			{Type: certlib.ContentCertificate},
			{Type: certlib.ContentPrivateKey},
		},
	}

	certContainer := &certlib.CertContainer{
		FilePath: "/tmp/server.pem",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate}},
	}

	keyContainer := &certlib.CertContainer{
		FilePath: "/tmp/key.pem",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentPrivateKey}},
	}

	return []TreeNode{
		// Bundle header (ci=0, ii=-1)
		{ContainerIdx: 0, ItemIdx: -1, Filename: "bundle.p12", ContentType: "pkcs12", IsBundle: true, Expanded: true, ChildCount: 2, Container: bundleContainer},
		// Bundle child: cert (ci=0, ii=0)
		{ContainerIdx: 0, ItemIdx: 0, Filename: "cert", ContentType: "pkcs12/cert", IsChild: true, Container: bundleContainer, Item: &bundleContainer.Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "/tmp/bundle.p12"}},
		// Bundle child: key (ci=0, ii=1)
		{ContainerIdx: 0, ItemIdx: 1, Filename: "key", ContentType: "pkcs12/key", IsChild: true, Container: bundleContainer, Item: &bundleContainer.Items[1],
			Ref: certlib.ItemRef{ContainerIdx: 0, ItemIdx: 1, FilePath: "/tmp/bundle.p12"}},
		// Standalone cert (ci=1, ii=0)
		{ContainerIdx: 1, ItemIdx: 0, Filename: "server.pem", ContentType: "pem/cert", Container: certContainer, Item: &certContainer.Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "/tmp/server.pem"}},
		// Standalone key (ci=2, ii=0)
		{ContainerIdx: 2, ItemIdx: 0, Filename: "key.pem", ContentType: "pem/key", Container: keyContainer, Item: &keyContainer.Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 2, ItemIdx: 0, FilePath: "/tmp/key.pem"}},
	}
}

// =============================================================================
// Section 3.1 -- Multi-select toggle
// =============================================================================

func TestMultiSelect_ToggleSingleItem(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Toggle standalone cert on
	ms.toggle(nodes[3], nodes)
	if !ms.isSelected(nodes[3]) {
		t.Error("expected standalone cert to be selected")
	}
	if ms.count() != 1 {
		t.Errorf("expected count 1, got %d", ms.count())
	}

	// Toggle it off
	ms.toggle(nodes[3], nodes)
	if ms.isSelected(nodes[3]) {
		t.Error("expected standalone cert to be deselected")
	}
	if ms.count() != 0 {
		t.Errorf("expected count 0, got %d", ms.count())
	}
}

func TestMultiSelect_BundleHeaderSelectsChildren(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select bundle header
	ms.toggle(nodes[0], nodes)
	if !ms.isSelected(nodes[0]) {
		t.Error("expected bundle header to be selected")
	}
	if !ms.isSelected(nodes[1]) {
		t.Error("expected bundle child 0 to be selected")
	}
	if !ms.isSelected(nodes[2]) {
		t.Error("expected bundle child 1 to be selected")
	}
	// count() reports real items only (2 children), not the bundle header
	if ms.count() != 2 {
		t.Errorf("expected count 2, got %d", ms.count())
	}
}

func TestMultiSelect_CountExcludesBundleHeader(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select bundle header (cascades to header + 2 children)
	ms.toggle(nodes[0], nodes)

	// Header key (itemIdx == -1) must not be counted
	if ms.count() != 2 {
		t.Errorf("expected count 2 (children only), got %d", ms.count())
	}
	// count() must never diverge from collectSelected
	if ms.count() != len(ms.collectSelected(nodes)) {
		t.Errorf("count() = %d, len(collectSelected()) = %d; must match", ms.count(), len(ms.collectSelected(nodes)))
	}
}

func TestMultiSelect_CountNoBundleUnchanged(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Two standalone items, no bundle header selected
	ms.toggle(nodes[3], nodes)
	ms.toggle(nodes[4], nodes)

	if ms.count() != 2 {
		t.Errorf("expected count 2, got %d", ms.count())
	}
	if ms.count() != len(ms.collectSelected(nodes)) {
		t.Errorf("count() = %d, len(collectSelected()) = %d; must match", ms.count(), len(ms.collectSelected(nodes)))
	}
}

func TestMultiSelect_CountExcludesMultipleBundleHeaders(t *testing.T) {
	bundleA := &certlib.CertContainer{
		FilePath: "/tmp/a.p12",
		Format:   certlib.FormatPKCS12,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate}, {Type: certlib.ContentPrivateKey}},
	}
	bundleB := &certlib.CertContainer{
		FilePath: "/tmp/b.p12",
		Format:   certlib.FormatPKCS12,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate}, {Type: certlib.ContentPrivateKey}},
	}
	nodes := []TreeNode{
		{ContainerIdx: 0, ItemIdx: -1, IsBundle: true, ChildCount: 2, Container: bundleA},
		{ContainerIdx: 0, ItemIdx: 0, IsChild: true, Container: bundleA, Item: &bundleA.Items[0]},
		{ContainerIdx: 0, ItemIdx: 1, IsChild: true, Container: bundleA, Item: &bundleA.Items[1]},
		{ContainerIdx: 1, ItemIdx: -1, IsBundle: true, ChildCount: 2, Container: bundleB},
		{ContainerIdx: 1, ItemIdx: 0, IsChild: true, Container: bundleB, Item: &bundleB.Items[0]},
		{ContainerIdx: 1, ItemIdx: 1, IsChild: true, Container: bundleB, Item: &bundleB.Items[1]},
	}

	ms := newMultiSelectModel()
	ms.toggle(nodes[0], nodes)
	ms.toggle(nodes[3], nodes)

	// 4 real items, 2 headers excluded
	if ms.count() != 4 {
		t.Errorf("expected count 4, got %d", ms.count())
	}
	if ms.count() != len(ms.collectSelected(nodes)) {
		t.Errorf("count() = %d, len(collectSelected()) = %d; must match", ms.count(), len(ms.collectSelected(nodes)))
	}
}

func TestMultiSelect_BundleHeaderDeselectsChildren(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select, then deselect
	ms.toggle(nodes[0], nodes)
	ms.toggle(nodes[0], nodes)

	if ms.isSelected(nodes[0]) {
		t.Error("expected bundle header to be deselected")
	}
	if ms.isSelected(nodes[1]) {
		t.Error("expected bundle child 0 to be deselected")
	}
	if ms.isSelected(nodes[2]) {
		t.Error("expected bundle child 1 to be deselected")
	}
	if ms.count() != 0 {
		t.Errorf("expected count 0, got %d", ms.count())
	}
}

func TestMultiSelect_IndividualChildToggle(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select just one child
	ms.toggle(nodes[1], nodes)
	if !ms.isSelected(nodes[1]) {
		t.Error("expected child to be selected")
	}
	if ms.isSelected(nodes[0]) {
		t.Error("bundle header should not be auto-selected")
	}
	if ms.isSelected(nodes[2]) {
		t.Error("other child should not be selected")
	}
	if ms.count() != 1 {
		t.Errorf("expected count 1, got %d", ms.count())
	}
}

func TestMultiSelect_LockedCannotSelect(t *testing.T) {
	ms := newMultiSelectModel()
	lockedNode := TreeNode{ContainerIdx: 5, ItemIdx: 0, Locked: true}
	nodes := []TreeNode{lockedNode}

	ms.toggle(lockedNode, nodes)
	if ms.count() != 0 {
		t.Errorf("expected count 0 for locked node, got %d", ms.count())
	}
}

func TestMultiSelect_ClearOnEsc(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	ms.toggle(nodes[3], nodes)
	ms.toggle(nodes[4], nodes)
	if ms.count() != 2 {
		t.Fatalf("expected count 2, got %d", ms.count())
	}

	ms.clear()
	if ms.count() != 0 {
		t.Errorf("expected count 0 after clear, got %d", ms.count())
	}
}

func TestMultiSelect_CollectSelected(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select bundle header (which selects children too)
	ms.toggle(nodes[0], nodes)
	// Also select standalone cert
	ms.toggle(nodes[3], nodes)

	selected := ms.collectSelected(nodes)
	// Should have 3 items: 2 bundle children + standalone cert (header excluded because ItemIdx < 0)
	if len(selected) != 3 {
		t.Fatalf("expected 3 selected items (excluding header), got %d", len(selected))
	}

	// Verify order matches allNodes order
	if selected[0].ContainerIdx != 0 || selected[0].ItemIdx != 0 {
		t.Errorf("first selected should be bundle child 0")
	}
	if selected[1].ContainerIdx != 0 || selected[1].ItemIdx != 1 {
		t.Errorf("second selected should be bundle child 1")
	}
	if selected[2].ContainerIdx != 1 || selected[2].ItemIdx != 0 {
		t.Errorf("third selected should be standalone cert")
	}
}

func TestMultiSelect_CollectFilePaths(t *testing.T) {
	ms := newMultiSelectModel()
	nodes := makeTestNodes()

	// Select both children from same bundle
	ms.toggle(nodes[1], nodes)
	ms.toggle(nodes[2], nodes)
	// Select standalone cert
	ms.toggle(nodes[3], nodes)

	paths := ms.collectFilePaths(nodes)
	if len(paths) != 2 {
		t.Fatalf("expected 2 unique paths, got %d: %v", len(paths), paths)
	}
	if paths[0] != "/tmp/bundle.p12" {
		t.Errorf("expected first path /tmp/bundle.p12, got %s", paths[0])
	}
	if paths[1] != "/tmp/server.pem" {
		t.Errorf("expected second path /tmp/server.pem, got %s", paths[1])
	}
}

// =============================================================================
// Section 3.2 -- Bundle form
// =============================================================================

func TestBuildBundleForm_Fields(t *testing.T) {
	initStyles()
	initFormStyles()
	nodes := makeTestNodes()
	selected := []TreeNode{nodes[1], nodes[3]} // cert from bundle + standalone cert
	paths := []string{"/tmp/bundle.p12", "/tmp/server.pem"}

	f := buildBundleForm("/tmp", selected, paths)
	if f == nil {
		t.Fatal("expected non-nil form")
	}

	if !strings.Contains(f.title, "2 items") {
		t.Errorf("expected title to contain '2 items', got %q", f.title)
	}

	expectedFields := []string{"format", "item_aliases", "tip", "pkcs12_notice", "password", "legacy", "output", "submit"}
	if len(f.fieldNames) != len(expectedFields) {
		t.Fatalf("expected %d fields, got %d: %v", len(expectedFields), len(f.fieldNames), f.fieldNames)
	}
	for i, name := range expectedFields {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildBundleOptions_InputPaths(t *testing.T) {
	initStyles()
	initFormStyles()
	nodes := makeTestNodes()
	selected := []TreeNode{nodes[1], nodes[3]}
	paths := []string{"/tmp/bundle.p12", "/tmp/server.pem"}

	f := buildBundleForm("/tmp", selected, paths)
	opts, err := buildBundleOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.InputPaths) != 2 {
		t.Fatalf("expected 2 input paths, got %d", len(opts.InputPaths))
	}
	if opts.InputPaths[0] != "/tmp/bundle.p12" {
		t.Errorf("expected first input path /tmp/bundle.p12, got %s", opts.InputPaths[0])
	}
}

func TestBuildBundleOptions_HardcodedDefaults(t *testing.T) {
	initStyles()
	initFormStyles()
	nodes := makeTestNodes()
	selected := []TreeNode{nodes[1]}
	paths := []string{"/tmp/bundle.p12"}

	f := buildBundleForm("/tmp", selected, paths)

	opts, err := buildBundleOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.AutoChain {
		t.Error("expected AutoChain=true (hardcoded)")
	}
	if !opts.IncludeRoot {
		t.Error("expected IncludeRoot=true (hardcoded)")
	}
	if opts.Alias != "" {
		t.Errorf("expected empty Alias, got %q", opts.Alias)
	}
}

func TestBuildBundleOptions_FormatVisibility(t *testing.T) {
	initStyles()
	initFormStyles()
	nodes := makeTestNodes()
	selected := []TreeNode{nodes[1]}
	paths := []string{"/tmp/bundle.p12"}

	f := buildBundleForm("/tmp", selected, paths)

	// Default PEM: password hidden, aliases not focusable, pkcs12_notice hidden
	if f.fieldByName("password").Visible() {
		t.Error("password should be hidden for PEM format")
	}
	if f.fieldByName("item_aliases").Focusable() {
		t.Error("item_aliases should not be focusable for PEM format")
	}
	if f.fieldByName("pkcs12_notice").Visible() {
		t.Error("pkcs12_notice should be hidden for PEM format")
	}

	// Switch to PKCS#12: password visible, aliases not focusable, notice visible
	f.fieldByName("format").SetValue("PKCS#12")
	f.evaluateVisibility()
	if !f.fieldByName("password").Visible() {
		t.Error("password should be visible for PKCS#12 format")
	}
	if f.fieldByName("item_aliases").Focusable() {
		t.Error("item_aliases should not be focusable for PKCS#12 format")
	}
	if !f.fieldByName("pkcs12_notice").Visible() {
		t.Error("pkcs12_notice should be visible for PKCS#12 format")
	}

	// Switch to JKS: password visible, aliases focusable, notice hidden
	f.fieldByName("format").SetValue("JKS")
	f.evaluateVisibility()
	if !f.fieldByName("password").Visible() {
		t.Error("password should be visible for JKS format")
	}
	if !f.fieldByName("item_aliases").Focusable() {
		t.Error("item_aliases should be focusable for JKS format")
	}
	if f.fieldByName("pkcs12_notice").Visible() {
		t.Error("pkcs12_notice should be hidden for JKS format")
	}

	// Switch back to PEM: all hidden/not focusable
	f.fieldByName("format").SetValue("PEM")
	f.evaluateVisibility()
	if f.fieldByName("password").Visible() {
		t.Error("password should be hidden for PEM format")
	}
	if f.fieldByName("item_aliases").Focusable() {
		t.Error("item_aliases should not be focusable for PEM format")
	}
}

func TestBuildBundleOptions_LegacyVisibility(t *testing.T) {
	initStyles()
	initFormStyles()
	nodes := makeTestNodes()
	selected := []TreeNode{nodes[1]}
	paths := []string{"/tmp/bundle.p12"}

	f := buildBundleForm("/tmp", selected, paths)

	// Legacy should be hidden for PEM
	if f.fieldByName("legacy").Visible() {
		t.Error("legacy should be hidden for PEM")
	}

	// Visible for PKCS#12
	f.fieldByName("format").SetValue("PKCS#12")
	f.evaluateVisibility()
	if !f.fieldByName("legacy").Visible() {
		t.Error("legacy should be visible for PKCS#12")
	}

	// Hidden for JKS
	f.fieldByName("format").SetValue("JKS")
	f.evaluateVisibility()
	if f.fieldByName("legacy").Visible() {
		t.Error("legacy should be hidden for JKS")
	}
}

func TestReadOnlyField_NotFocusable(t *testing.T) {
	f := newReadOnlyTextField("Items", "line1\nline2")
	if f.Focusable() {
		t.Error("readOnlyTextField should not be focusable")
	}
	if f.IsDirty() {
		t.Error("readOnlyTextField should not be dirty")
	}
	if f.Height() != 2 {
		t.Errorf("expected height 2 for 2-line content, got %d", f.Height())
	}
	if f.Value() != "line1\nline2" {
		t.Errorf("expected content preserved, got %q", f.Value())
	}
}

func TestAutoSelectChain_DuplicateRoot(t *testing.T) {
	// Generate root -> intermediate -> leaf chain
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDer, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDer)

	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intTemplate := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDer, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDer)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.local"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDer, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafDer)

	// Build store: leaf(0), intermediate(1), root(2), duplicate-root(3)
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "leaf.crt",
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: leafCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "int.crt",
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: intCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "root.crt",
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: rootCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "root_copy.crt",
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: rootCert}},
	})

	relations := certlib.DetectRelations(store)
	relIndex := certlib.BuildRelationIndex(relations, store)

	// Build TreeNode slice
	allNodes := []TreeNode{
		{
			ContainerIdx: 0, ItemIdx: 0, Filename: "leaf.crt", ContentType: "pem/cert",
			Container: &store.Containers[0], Item: &store.Containers[0].Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "leaf.crt"},
		},
		{
			ContainerIdx: 1, ItemIdx: 0, Filename: "int.crt", ContentType: "pem/cert",
			Container: &store.Containers[1], Item: &store.Containers[1].Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "int.crt"},
		},
		{
			ContainerIdx: 2, ItemIdx: 0, Filename: "root.crt", ContentType: "pem/cert",
			Container: &store.Containers[2], Item: &store.Containers[2].Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 2, ItemIdx: 0, FilePath: "root.crt"},
		},
		{
			ContainerIdx: 3, ItemIdx: 0, Filename: "root_copy.crt", ContentType: "pem/cert",
			Container: &store.Containers[3], Item: &store.Containers[3].Items[0],
			Ref: certlib.ItemRef{ContainerIdx: 3, ItemIdx: 0, FilePath: "root_copy.crt"},
		},
	}

	ms := newMultiSelectModel()
	msg := ms.autoSelectChain(allNodes[0], allNodes, relIndex)

	// Should select leaf + intermediate + one root = 3, NOT 4
	if ms.count() != 3 {
		t.Fatalf("expected 3 selected (leaf+int+one root), got %d; msg=%s", ms.count(), msg)
	}

	// Verify the duplicate root was NOT selected
	rootSelected := ms.isSelected(allNodes[2])
	rootCopySelected := ms.isSelected(allNodes[3])
	if rootSelected && rootCopySelected {
		t.Fatal("both root copies should not be selected")
	}
	if !rootSelected && !rootCopySelected {
		t.Fatal("at least one root copy should be selected")
	}
}
