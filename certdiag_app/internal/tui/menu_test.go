package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func keyMsg(key string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

func specialKeyMsg(t tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: t}
}

// --- Menu tests ---

func TestMenu_ArrowNavigation(t *testing.T) {
	m := menuModel{}
	m.activate("Test", buildNewMenu(), "")

	if m.cursor != 0 {
		t.Fatalf("expected cursor 0, got %d", m.cursor)
	}

	// Down
	m.update(specialKeyMsg(tea.KeyDown))
	if m.cursor != 1 {
		t.Fatalf("expected cursor 1 after down, got %d", m.cursor)
	}

	// Down again
	m.update(specialKeyMsg(tea.KeyDown))
	if m.cursor != 2 {
		t.Fatalf("expected cursor 2 after down, got %d", m.cursor)
	}

	// Down wraps to 0
	m.update(specialKeyMsg(tea.KeyDown))
	if m.cursor != 0 {
		t.Fatalf("expected cursor 0 after wrap, got %d", m.cursor)
	}

	// Up wraps to last
	m.update(specialKeyMsg(tea.KeyUp))
	if m.cursor != 2 {
		t.Fatalf("expected cursor 2 after up wrap, got %d", m.cursor)
	}
}

func TestMenu_EnterSelects(t *testing.T) {
	m := menuModel{}
	m.activate("Test", buildNewMenu(), "")
	m.update(specialKeyMsg(tea.KeyDown)) // cursor=1

	selected, done := m.update(specialKeyMsg(tea.KeyEnter))
	if !done {
		t.Fatal("expected done=true on Enter")
	}
	if selected == nil {
		t.Fatal("expected non-nil selected")
	}
	if selected.kind != formCreateCert {
		t.Fatalf("expected formCreateCert, got %d", selected.kind)
	}
}

func TestMenu_HotkeySelects(t *testing.T) {
	m := menuModel{}
	m.activate("Test", buildNewMenu(), "")

	selected, done := m.update(keyMsg("k"))
	if !done {
		t.Fatal("expected done=true on hotkey")
	}
	if selected == nil {
		t.Fatal("expected non-nil selected")
	}
	if selected.kind != formCreateKey {
		t.Fatalf("expected formCreateKey, got %d", selected.kind)
	}
}

func TestMenu_EscCloses(t *testing.T) {
	m := menuModel{}
	m.activate("Test", buildNewMenu(), "")

	selected, done := m.update(specialKeyMsg(tea.KeyEsc))
	if !done {
		t.Fatal("expected done=true on Esc")
	}
	if selected != nil {
		t.Fatal("expected nil selected on Esc")
	}
}

func TestMenu_NewMenuItems(t *testing.T) {
	items := buildNewMenu()
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	if items[0].kind != formCreateKey {
		t.Errorf("first item should be Create Key")
	}
	if items[1].kind != formCreateCert {
		t.Errorf("second item should be Create Certificate")
	}
	if items[2].kind != formCreateCSR {
		t.Errorf("third item should be Create CSR")
	}
}

func TestMenu_ActionMenuCert(t *testing.T) {
	node := TreeNode{
		ContentType: "pem/cert",
		Item:        &certlib.CertItem{Type: certlib.ContentCertificate},
	}
	items := buildActionMenu(node)
	if len(items) != 4 {
		t.Fatalf("expected 4 items for standalone cert, got %d", len(items))
	}
	kinds := make(map[formKind]bool)
	for _, item := range items {
		kinds[item.kind] = true
	}
	for _, k := range []formKind{formRenew, formConvert, formCreateCert, formCreateCSR} {
		if !kinds[k] {
			t.Errorf("missing expected kind %d", k)
		}
	}
	if kinds[formExtract] {
		t.Error("standalone cert should not have Extract")
	}
	if kinds[formReencrypt] {
		t.Error("cert node should not have Change Password")
	}
}

func TestMenu_ActionMenuCertNoExtract(t *testing.T) {
	node := TreeNode{
		ContentType: "pem/cert",
		Item:        &certlib.CertItem{Type: certlib.ContentCertificate},
	}
	items := buildActionMenu(node)
	for _, item := range items {
		if item.kind == formExtract {
			t.Fatal("standalone (non-child) cert must not have Extract")
		}
	}
}

func TestMenu_ActionMenuKey(t *testing.T) {
	node := TreeNode{
		ContentType: "pem/key",
		Item:        &certlib.CertItem{Type: certlib.ContentPrivateKey},
	}
	items := buildActionMenu(node)
	if len(items) != 4 {
		t.Fatalf("expected 4 items for key, got %d", len(items))
	}
	kinds := make(map[formKind]bool)
	for _, item := range items {
		kinds[item.kind] = true
	}
	for _, k := range []formKind{formConvert, formCreateCert, formCreateCSR, formReencrypt} {
		if !kinds[k] {
			t.Errorf("missing expected kind %d", k)
		}
	}
}

func TestMenu_ActionMenuCSR(t *testing.T) {
	node := TreeNode{
		ContentType: "pem/csr",
		Item:        &certlib.CertItem{Type: certlib.ContentCSR},
	}
	items := buildActionMenu(node)
	if len(items) != 4 {
		t.Fatalf("expected 4 items for CSR, got %d", len(items))
	}
	if items[0].kind != formSignCSR {
		t.Errorf("expected Sign, got %d", items[0].kind)
	}
	kinds := make(map[formKind]bool)
	for _, item := range items {
		kinds[item.kind] = true
	}
	for _, k := range []formKind{formSignCSR, formCreateCert, formCreateCSR, formConvert} {
		if !kinds[k] {
			t.Errorf("missing expected kind %d", k)
		}
	}
}

func TestMenu_ActionMenuBundle(t *testing.T) {
	node := TreeNode{
		IsBundle:    true,
		ContentType: "pkcs12",
		Container:   &certlib.CertContainer{},
	}
	items := buildActionMenu(node)
	if len(items) != 3 {
		t.Fatalf("expected 3 items for bundle, got %d", len(items))
	}
	kinds := make(map[formKind]bool)
	for _, item := range items {
		kinds[item.kind] = true
	}
	for _, k := range []formKind{formExtract, formConvert, formReencrypt} {
		if !kinds[k] {
			t.Errorf("missing expected kind %d", k)
		}
	}
}

func TestMenu_ActionMenuChildItem(t *testing.T) {
	node := TreeNode{
		IsChild:     true,
		ContentType: "pem/cert",
		Item:        &certlib.CertItem{Type: certlib.ContentCertificate},
	}
	items := buildActionMenu(node)
	if len(items) != 5 {
		t.Fatalf("expected 5 items for child cert, got %d", len(items))
	}
	kinds := make(map[formKind]bool)
	for _, item := range items {
		kinds[item.kind] = true
	}
	for _, k := range []formKind{formRenew, formConvert, formExtract, formCreateCert, formCreateCSR} {
		if !kinds[k] {
			t.Errorf("missing expected kind %d", k)
		}
	}
}

func TestMenu_ActionMenuEmpty(t *testing.T) {
	node := TreeNode{Locked: true}
	items := buildActionMenu(node)
	if len(items) != 0 {
		t.Fatalf("expected 0 items for locked node, got %d", len(items))
	}
}

func TestMenu_View(t *testing.T) {
	initStyles()
	m := menuModel{}
	m.activate("Test Menu", buildNewMenu(), "")
	view := m.view(80, 24)
	if !strings.Contains(view, "Test Menu") {
		t.Error("view should contain title")
	}
	if !strings.Contains(view, "Create Key") {
		t.Error("view should contain Create Key")
	}
}

// --- Form builder tests ---

func TestBuildCreateKeyForm_Fields(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	expected := []string{"algo", "size", "curve", "format", "encrypt", "password", "output", "submit"}
	if len(f.fieldNames) != len(expected) {
		t.Fatalf("expected %d fields, got %d", len(expected), len(f.fieldNames))
	}
	for i, name := range expected {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildCreateKeyForm_DefaultVisibility(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	// Default is ECDSA (index 0): size hidden, curve visible
	sizeField := f.fieldByName("size")
	curveField := f.fieldByName("curve")

	if sizeField.Visible() {
		t.Error("size should be hidden when ECDSA selected")
	}
	if !curveField.Visible() {
		t.Error("curve should be visible when ECDSA selected")
	}
}

func TestBuildCreateKeyForm_RSAVisibility(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	// Switch to RSA
	algoField := f.fieldByName("algo")
	algoField.SetValue("RSA")
	f.evaluateVisibility()

	sizeField := f.fieldByName("size")
	curveField := f.fieldByName("curve")

	if !sizeField.Visible() {
		t.Error("size should be visible when RSA selected")
	}
	if curveField.Visible() {
		t.Error("curve should be hidden when RSA selected")
	}
}

func TestBuildCreateKeyForm_Ed25519Visibility(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	algoField := f.fieldByName("algo")
	algoField.SetValue("Ed25519")
	f.evaluateVisibility()

	sizeField := f.fieldByName("size")
	curveField := f.fieldByName("curve")

	if sizeField.Visible() {
		t.Error("size should be hidden when Ed25519 selected")
	}
	if curveField.Visible() {
		t.Error("curve should be hidden when Ed25519 selected")
	}
}

func TestBuildCreateKeyForm_EncryptVisibility(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	// Default: PEM format, encrypt unchecked -> password hidden
	pwField := f.fieldByName("password")
	if pwField.Visible() {
		t.Error("password should be hidden when encrypt is unchecked")
	}

	// Check encrypt
	encField := f.fieldByName("encrypt")
	encField.SetValue("true")
	f.evaluateVisibility()

	if !pwField.Visible() {
		t.Error("password should be visible when encrypt is checked")
	}
}

func TestBuildCreateKeyForm_DERHidesEncrypt(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	// Switch to DER
	fmtField := f.fieldByName("format")
	fmtField.SetValue("DER")
	f.evaluateVisibility()

	encField := f.fieldByName("encrypt")
	if encField.Visible() {
		t.Error("encrypt should be hidden when DER format selected")
	}

	pwField := f.fieldByName("password")
	if pwField.Visible() {
		t.Error("password should be hidden when DER format selected")
	}
}

func TestBuildCreateKeyForm_Sections(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})

	if len(f.sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(f.sections))
	}
	if f.sections[0].title != "Key Parameters" {
		t.Errorf("section 0: expected 'Key Parameters', got %q", f.sections[0].title)
	}
	if f.sections[1].title != "Output" {
		t.Errorf("section 1: expected 'Output', got %q", f.sections[1].title)
	}
}

func TestBuildForm_NilForUnimplemented(t *testing.T) {
	f := buildForm(formBundle, "/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	if f != nil {
		t.Error("expected nil for unimplemented form kind")
	}
}

func TestBuildForm_CreateKey(t *testing.T) {
	initStyles()
	initFormStyles()
	f := buildForm(formCreateKey, "/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	if f == nil {
		t.Fatal("expected non-nil form for formCreateKey")
	}
	if f.title != "Create Key" {
		t.Errorf("expected title 'Create Key', got %q", f.title)
	}
}
