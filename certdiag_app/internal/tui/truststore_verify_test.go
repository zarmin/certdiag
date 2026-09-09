package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// tsChain builds a root plus a leaf it signed.
func tsChain(t *testing.T) (root, leaf *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Verify Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"leaf.example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf
}

func writeCertFile(t *testing.T, dir, name string, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)

	var buf strings.Builder
	for _, c := range certs {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerify_TrustedAgainstCursorGroup(t *testing.T) {
	root, leaf := tsChain(t)
	dir := t.TempDir()
	leafPath := writeCertFile(t, dir, "leaf.pem", leaf)

	m := newStoreTestModel(t,
		tsStore("Corporate Store", truststore.StoreTypeCustom, "/tmp/corp.pem", root),
	)
	cursorTo(t, &m, "Corporate Store")

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: leafPath})
	got := model.(RootModel)

	if got.state != stateTrustVerify {
		t.Fatalf("expected the verify view, got %v", got.state)
	}
	if got.trustVerify == nil {
		t.Fatal("expected a verify result")
	}
	if !got.trustVerify.Trusted {
		t.Errorf("expected the leaf to verify against its root: %s", got.trustVerify.Reason)
	}
	if got.trustVerify.Store.Name != "Corporate Store" {
		t.Errorf("expected the cursor's store used, got %q", got.trustVerify.Store.Name)
	}
}

func TestVerify_NotTrustedAgainstWrongStore(t *testing.T) {
	_, leaf := tsChain(t)
	otherRoot := tsCert(t, "Unrelated Root")

	dir := t.TempDir()
	leafPath := writeCertFile(t, dir, "leaf.pem", leaf)

	m := newStoreTestModel(t,
		tsStore("Other Store", truststore.StoreTypeCustom, "/tmp/other.pem", otherRoot),
	)
	cursorTo(t, &m, "Other Store")

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: leafPath})
	got := model.(RootModel)

	if got.trustVerify == nil {
		t.Fatal("expected a verify result")
	}
	if got.trustVerify.Trusted {
		t.Error("expected the leaf to be untrusted by an unrelated store")
	}
	if got.trustVerify.Reason == "" {
		t.Error("expected a reason for the failure")
	}
}

func TestVerify_KindModeUsesMergedPool(t *testing.T) {
	root, leaf := tsChain(t)
	dir := t.TempDir()
	leafPath := writeCertFile(t, dir, "leaf.pem", leaf)

	// The root lives in only one of two JDKs; kind mode merges them, so the
	// Java group as a whole must trust the leaf.
	m := newStoreTestModel(t,
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk21", tsCert(t, "Irrelevant Root")),
		tsStore("Java 17", truststore.StoreTypeJava, "/jdk17", root),
	)
	model, _ := m.handleTreeKey(keyMsg("g"))
	m = model.(RootModel)

	// Cursor on the merged Java group.
	for i := range m.visible {
		if m.visible[i].IsBundle && strings.HasPrefix(m.visible[i].Filename, "Java") {
			m.tree.cursor = i
			break
		}
	}

	model, _ = m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: leafPath})
	got := model.(RootModel)

	if got.trustVerify == nil {
		t.Fatal("expected a verify result")
	}
	if !got.trustVerify.Trusted {
		t.Errorf("the merged Java pool must trust the leaf: %s", got.trustVerify.Reason)
	}
}

func TestVerify_ReadErrorNotified(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{
		path: filepath.Join(t.TempDir(), "missing.pem"),
	})
	got := model.(RootModel)

	if got.state == stateTrustVerify {
		t.Error("a read failure must not open the verify view")
	}
	if got.popup.kind == popupNone && got.statusMessage == "" {
		t.Error("expected the error surfaced to the user")
	}
}

func TestVerify_EmptyPathIsNoop(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: ""})
	if model.(RootModel).state == stateTrustVerify {
		t.Error("a cancelled picker must not open the verify view")
	}
}

func TestVerifyView_RendersOutcome(t *testing.T) {
	root, leaf := tsChain(t)
	dir := t.TempDir()
	leafPath := writeCertFile(t, dir, "leaf.pem", leaf)

	m := newStoreTestModel(t,
		tsStore("Corporate Store", truststore.StoreTypeCustom, "/tmp/corp.pem", root),
	)
	cursorTo(t, &m, "Corporate Store")
	m.width, m.height = 100, 30

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: leafPath})
	got := model.(RootModel)

	out := got.viewTrustVerify()
	if !strings.Contains(out, "TRUSTED") {
		t.Errorf("expected the verdict rendered:\n%s", out)
	}
	if !strings.Contains(out, "Corporate Store") {
		t.Errorf("expected the store named:\n%s", out)
	}
	if !strings.Contains(out, "leaf.pem") {
		t.Errorf("expected the verified file named:\n%s", out)
	}
	if !strings.Contains(out, "Trust anchor") {
		t.Errorf("expected the trust anchor:\n%s", out)
	}

	// Chain renders root first, per the project-wide issuance order rule.
	rootIdx := strings.Index(out, "[Root]")
	leafIdx := strings.Index(out, "[Leaf]")
	if rootIdx == -1 || leafIdx == -1 || rootIdx > leafIdx {
		t.Errorf("expected the chain in issuance order (root first):\n%s", out)
	}
}

func TestVerifyView_EscReturnsToTree(t *testing.T) {
	root, leaf := tsChain(t)
	dir := t.TempDir()
	leafPath := writeCertFile(t, dir, "leaf.pem", leaf)

	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeCustom, "/tmp/corp.pem", root),
	)
	cursorTo(t, &m, "Store")

	model, _ := m.handleTrustVerifyPicked(trustVerifyPickedMsg{path: leafPath})
	got := model.(RootModel)

	model, _ = got.handleTrustVerifyKey(tea.KeyMsg{Type: tea.KeyEsc})
	back := model.(RootModel)

	if back.state != stateTree {
		t.Errorf("expected to return to the tree, got %v", back.state)
	}
	if back.trustVerify != nil {
		t.Error("expected the result cleared on exit")
	}
	if len(back.visible) == 0 {
		t.Error("expected the tree still populated")
	}
}

func TestVerifyView_EmptyResultDoesNotPanic(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)
	m.width, m.height = 80, 24
	m.state = stateTrustVerify

	if out := m.viewTrustVerify(); out == "" {
		t.Error("expected some output")
	}
}

// --- Export ---

func TestExport_WritesSelectedCertificate(t *testing.T) {
	cert := tsCert(t, "Export Me")
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", cert),
	)

	for i := range m.visible {
		if m.visible[i].IsChild {
			m.tree.cursor = i
			break
		}
	}
	m.storeExportCert = m.visible[m.tree.cursor].Item.Certificate

	out := filepath.Join(t.TempDir(), "exported.pem")
	model, _ := m.handleStoreExportPicked(storeExportPickedMsg{path: out})
	got := model.(RootModel)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected the file written: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected a PEM certificate")
	}
	if string(block.Bytes) != string(cert.Raw) {
		t.Error("exported bytes must match the store certificate")
	}
	if got.storeExportCert != nil {
		t.Error("expected the pending export cleared")
	}
}

func TestExport_GroupHeaderIsRejected(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)
	m.tree.cursor = 0 // group header, no certificate

	cmd := m.openStoreExport()
	if cmd != nil {
		// A notify command is fine, but no picker may be launched and no cert
		// may be pending.
		_ = cmd
	}
	if m.storeExportCert != nil {
		t.Error("a group header must not arm an export")
	}
}

func TestExport_EmptyPathIsNoop(t *testing.T) {
	m := newStoreTestModel(t,
		tsStore("Store", truststore.StoreTypeOS, "/kc", tsCert(t, "Root")),
	)
	m.storeExportCert = tsCert(t, "Pending")

	model, _ := m.handleStoreExportPicked(storeExportPickedMsg{path: ""})
	if model.(RootModel).storeExportCert == nil {
		t.Error("a cancelled picker must leave the pending export alone")
	}
}
