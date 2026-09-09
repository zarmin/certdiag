package tui

import (
	"crypto/x509"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func makeTestNode(filePath, contentType string, item *certlib.CertItem) *TreeNode {
	container := &certlib.CertContainer{
		FilePath: filePath,
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{},
	}
	if item != nil {
		container.Items = append(container.Items, *item)
	}
	return &TreeNode{
		Filename:    filePath,
		ContentType: contentType,
		Container:   container,
		Item:        item,
		Subject:     "Test Subject",
	}
}

// =============================================================================
// Sign CSR -- option builder tests
// =============================================================================

func TestBuildSignCSROptions_WithCA(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)
	if f == nil {
		t.Fatal("expected non-nil form")
	}

	f.fieldByName("signing").SetValue("Sign with CA")
	f.evaluateVisibility()
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.CACertPath != "/tmp/ca.crt" {
		t.Errorf("expected CA cert path '/tmp/ca.crt', got '%s'", opts.CACertPath)
	}
	if opts.CAKeyPath != "/tmp/ca.key" {
		t.Errorf("expected CA key path '/tmp/ca.key', got '%s'", opts.CAKeyPath)
	}
	if opts.CSRPath != "/tmp/test.csr" {
		t.Errorf("expected CSR path '/tmp/test.csr', got '%s'", opts.CSRPath)
	}
}

func TestBuildSignCSROptions_CAType(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)

	f.fieldByName("cert_type").SetValue("CA")
	f.evaluateVisibility()
	f.fieldByName("path_len").(*textInputField).input.SetValue("2")
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.IsCA {
		t.Error("expected IsCA=true")
	}
	if opts.PathLength != 2 {
		t.Errorf("expected PathLength=2, got %d", opts.PathLength)
	}
}

// =============================================================================
// Convert -- option builder tests
// =============================================================================

func TestBuildConvertOptions_FormatMapping(t *testing.T) {
	initTestStyles()

	cases := []struct {
		label    string
		expected certlib.FileFormat
	}{
		{"PEM", certlib.FormatPEM},
		{"DER", certlib.FormatDER},
		{"PKCS#12", certlib.FormatPKCS12},
		{"PKCS#7", certlib.FormatPKCS7},
		{"JKS", certlib.FormatJKS},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
			f := buildConvertForm("/tmp", node)
			f.fieldByName("format").SetValue(tc.label)
			f.evaluateVisibility()

			opts, err := buildConvertOptions(f, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.OutputFormat != tc.expected {
				t.Errorf("expected format %s, got %s", tc.expected, opts.OutputFormat)
			}
		})
	}
}

func TestBuildConvertOptions_PasswordFormats(t *testing.T) {
	initTestStyles()

	passwordFormats := []string{"PKCS#12", "JKS"}
	noPasswordFormats := []string{"PEM", "DER", "PKCS#7"}

	for _, fmt := range passwordFormats {
		t.Run(fmt+"_has_password", func(t *testing.T) {
			node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
			f := buildConvertForm("/tmp", node)
			f.fieldByName("format").SetValue(fmt)
			f.evaluateVisibility()

			pwField := f.fieldByName("password")
			if !pwField.Visible() {
				t.Errorf("password should be visible for format %s", fmt)
			}
		})
	}

	for _, fmt := range noPasswordFormats {
		t.Run(fmt+"_no_password", func(t *testing.T) {
			node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
			f := buildConvertForm("/tmp", node)
			f.fieldByName("format").SetValue(fmt)
			f.evaluateVisibility()

			pwField := f.fieldByName("password")
			if pwField.Visible() {
				t.Errorf("password should be hidden for format %s", fmt)
			}
		})
	}
}

func TestBuildConvertOptions_IncludeFilter(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildConvertForm("/tmp", node)
	f.fieldByName("include").SetValue("Certificates only")

	opts, err := buildConvertOptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Include != "certs" {
		t.Errorf("expected include 'certs', got '%s'", opts.Include)
	}
}

// =============================================================================
// Renew -- option builder tests
// =============================================================================

func TestBuildRenewOptions_ReuseKey(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/cert.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildRenewForm("/tmp", node, certlib.KeyGenOptions{}, 0)

	f.fieldByName("key_source").SetValue("Reuse existing")
	f.evaluateVisibility()
	f.fieldByName("key_path").SetValue("/tmp/cert.key")

	opts, err := buildRenewOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.NewKey {
		t.Error("expected NewKey=false for Reuse existing")
	}
	if opts.KeyFilePath != "/tmp/cert.key" {
		t.Errorf("expected key file path '/tmp/cert.key', got '%s'", opts.KeyFilePath)
	}
}

func TestBuildRenewOptions_NewKey(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/cert.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildRenewForm("/tmp", node, certlib.KeyGenOptions{}, 0)

	f.fieldByName("key_source").SetValue("Generate new")
	f.evaluateVisibility()
	f.fieldByName("algo").SetValue("RSA")
	f.evaluateVisibility()
	f.fieldByName("size").SetValue("4096")

	opts, err := buildRenewOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.NewKey {
		t.Error("expected NewKey=true for Generate new")
	}
	if opts.KeyOptions.Algorithm != "rsa" {
		t.Errorf("expected key algo 'rsa', got '%s'", opts.KeyOptions.Algorithm)
	}
	if opts.KeyOptions.KeySize != 4096 {
		t.Errorf("expected key size 4096, got %d", opts.KeyOptions.KeySize)
	}
}

// =============================================================================
// Extract -- option builder tests
// =============================================================================

func TestBuildExtractOptions_TypeFilter(t *testing.T) {
	initTestStyles()

	cases := []struct {
		label    string
		expected string
	}{
		{"All", "all"},
		{"Certificates only", "certs"},
		{"Keys only", "keys"},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			node := makeTestNode("/tmp/bundle.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
			f := buildExtractForm("/tmp", node)
			f.fieldByName("type_filter").SetValue(tc.label)

			opts, err := buildExtractOptions(f)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.TypeFilter != tc.expected {
				t.Errorf("expected type filter '%s', got '%s'", tc.expected, opts.TypeFilter)
			}
		})
	}
}

// =============================================================================
// Change Password -- option builder tests
// =============================================================================

func TestBuildReencryptOptions_NewFile(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/store.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildReencryptForm("/tmp", node)

	f.fieldByName("new_password").(*textInputField).input.SetValue("newpass123")
	f.fieldByName("confirm_password").(*textInputField).input.SetValue("newpass123")
	f.fieldByName("output_mode").SetValue("New file")
	f.evaluateVisibility()
	f.fieldByName("output").SetValue("/tmp/new-store.p12")

	opts, err := buildReencryptOptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.OutputPath != "/tmp/new-store.p12" {
		t.Errorf("expected output path '/tmp/new-store.p12', got '%s'", opts.OutputPath)
	}
	if opts.Overwrite {
		t.Error("expected Overwrite=false for New file mode")
	}
	if string(opts.NewPassword) != "newpass123" {
		t.Errorf("expected password 'newpass123', got '%s'", string(opts.NewPassword))
	}
}

func TestBuildReencryptOptions_Overwrite(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/store.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildReencryptForm("/tmp", node)

	f.fieldByName("new_password").(*textInputField).input.SetValue("newpass123")
	f.fieldByName("confirm_password").(*textInputField).input.SetValue("newpass123")
	f.fieldByName("output_mode").SetValue("Overwrite original")
	f.evaluateVisibility()

	opts, err := buildReencryptOptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.OutputPath != "/tmp/store.p12" {
		t.Errorf("expected output path '/tmp/store.p12' (same as input), got '%s'", opts.OutputPath)
	}
	if !opts.Overwrite {
		t.Error("expected Overwrite=true for Overwrite original mode")
	}
}

// =============================================================================
// Form structure tests
// =============================================================================

func TestBuildSignCSRForm_Fields(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)
	if f == nil {
		t.Fatal("expected non-nil form")
	}

	expected := []string{"signing", "ca_cert", "ca_key", "cert_type", "days", "path_len", "permitted_names", "excluded_names", "key_usage", "ext_key_usage", "format", "output", "submit"}
	if len(f.fieldNames) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(f.fieldNames), f.fieldNames)
	}
	for i, name := range expected {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildSignCSRForm_LeafKUDefaults(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if opts.KeyUsage != expectedKU {
		t.Errorf("expected leaf KU %d, got %d", expectedKU, opts.KeyUsage)
	}
	if len(opts.ExtKeyUsage) != 2 {
		t.Fatalf("expected 2 EKU entries, got %d", len(opts.ExtKeyUsage))
	}
	if opts.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("expected EKU[0]=ServerAuth, got %d", opts.ExtKeyUsage[0])
	}
	if opts.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Errorf("expected EKU[1]=ClientAuth, got %d", opts.ExtKeyUsage[1])
	}
}

func TestBuildSignCSRForm_CAKUDefaults(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)
	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if opts.KeyUsage != expectedKU {
		t.Errorf("expected CA KU %d, got %d", expectedKU, opts.KeyUsage)
	}
	if len(opts.ExtKeyUsage) != 0 {
		t.Errorf("expected no EKU for CA, got %d entries", len(opts.ExtKeyUsage))
	}
}

func TestBuildSignCSRForm_CustomKU(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)
	f.fieldByName("key_usage").SetValue("digitalSignature")
	f.fieldByName("ext_key_usage").SetValue("emailProtection")

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("expected KU=digitalSignature, got %d", opts.KeyUsage)
	}
	if len(opts.ExtKeyUsage) != 1 || opts.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
		t.Errorf("expected EKU=[emailProtection], got %v", opts.ExtKeyUsage)
	}
}

func TestBuildSignCSRForm_KUSwitchesOnCertType(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})
	f := buildSignCSRForm("/tmp", node, 0, 0)

	// Default leaf
	if f.fieldValue("key_usage") != kuDefaultLeaf {
		t.Errorf("expected leaf KU default, got %q", f.fieldValue("key_usage"))
	}
	if f.fieldValue("ext_key_usage") != ekuDefaultLeaf {
		t.Errorf("expected leaf EKU default, got %q", f.fieldValue("ext_key_usage"))
	}

	// Switch to CA
	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	if f.fieldValue("key_usage") != kuDefaultCA {
		t.Errorf("expected CA KU default, got %q", f.fieldValue("key_usage"))
	}
	if f.fieldValue("ext_key_usage") != "" {
		t.Errorf("expected empty EKU for CA, got %q", f.fieldValue("ext_key_usage"))
	}
}

func TestBuildSignCSRForm_NilForNilNode(t *testing.T) {
	initTestStyles()
	f := buildSignCSRForm("/tmp", nil, 0, 0)
	if f != nil {
		t.Error("expected nil form for nil node")
	}
}

func TestBuildConvertForm_PasswordVisibility(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildConvertForm("/tmp", node)

	// Default is PEM: password hidden
	if f.fieldByName("password").Visible() {
		t.Error("password should be hidden for PEM format")
	}

	// Switch to PKCS#12: password visible
	f.fieldByName("format").SetValue("PKCS#12")
	f.evaluateVisibility()
	if !f.fieldByName("password").Visible() {
		t.Error("password should be visible for PKCS#12 format")
	}

	// Alias should also be hidden for PKCS#12
	if f.fieldByName("alias").Visible() {
		t.Error("alias should be hidden for PKCS#12 (only JKS)")
	}

	// Legacy should be visible for PKCS#12
	if !f.fieldByName("legacy").Visible() {
		t.Error("legacy should be visible for PKCS#12")
	}
}

func TestBuildConvertForm_AliasVisibility(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildConvertForm("/tmp", node)

	// Switch to JKS: alias visible
	f.fieldByName("format").SetValue("JKS")
	f.evaluateVisibility()
	if !f.fieldByName("alias").Visible() {
		t.Error("alias should be visible for JKS format")
	}
	if !f.fieldByName("password").Visible() {
		t.Error("password should be visible for JKS format")
	}
	if f.fieldByName("legacy").Visible() {
		t.Error("legacy should be hidden for JKS format")
	}
}

func TestBuildRenewForm_CompoundVisibility(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/cert.pem", "pem/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildRenewForm("/tmp", node, certlib.KeyGenOptions{}, 0)

	// Default: key_source="Reuse existing" -> size/curve/algo hidden even if algo=RSA
	if f.fieldByName("algo").Visible() {
		t.Error("algo should be hidden when key_source is 'Reuse existing'")
	}
	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden when key_source is 'Reuse existing'")
	}

	// Switch to Generate new
	f.fieldByName("key_source").SetValue("Generate new")
	f.evaluateVisibility()

	if !f.fieldByName("algo").Visible() {
		t.Error("algo should be visible when key_source is 'Generate new'")
	}

	// Default algo is ECDSA -> size hidden, curve visible
	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden when algo is ECDSA")
	}
	if !f.fieldByName("curve").Visible() {
		t.Error("curve should be visible when algo is ECDSA")
	}

	// Switch algo to RSA -> size visible, curve hidden
	f.fieldByName("algo").SetValue("RSA")
	f.evaluateVisibility()
	if !f.fieldByName("size").Visible() {
		t.Error("size should be visible when key_source='Generate new' and algo='RSA'")
	}
	if f.fieldByName("curve").Visible() {
		t.Error("curve should be hidden when algo is RSA")
	}

	// Switch key_source back to Reuse -> size hidden again
	f.fieldByName("key_source").SetValue("Reuse existing")
	f.evaluateVisibility()
	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden when key_source switched back to 'Reuse existing'")
	}
}

func TestBuildExtractForm_Fields(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/bundle.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildExtractForm("/tmp", node)
	if f == nil {
		t.Fatal("expected non-nil form")
	}

	expected := []string{"type_filter", "format", "output_dir", "submit"}
	if len(f.fieldNames) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(f.fieldNames), f.fieldNames)
	}
	for i, name := range expected {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildReencryptForm_ConfirmValidation(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/store.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildReencryptForm("/tmp", node)

	// Set mismatched passwords
	f.fieldByName("new_password").(*textInputField).input.SetValue("secret123")
	f.fieldByName("confirm_password").(*textInputField).input.SetValue("different")

	ok := f.validateAll()
	if ok {
		t.Error("validateAll should fail on password mismatch")
	}
	confirmIdx := f.fieldIndex("confirm_password")
	if _, hasErr := f.errors[confirmIdx]; !hasErr {
		t.Error("expected error on confirm_password field")
	}

	// Fix password match
	f.fieldByName("confirm_password").(*textInputField).input.SetValue("secret123")
	ok = f.validateAll()
	if !ok {
		t.Errorf("validateAll should pass with matching passwords, errors: %v", f.errors)
	}
}

func TestBuildReencryptForm_OutputVisibility(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/store.p12", "pkcs12/cert", &certlib.CertItem{Type: certlib.ContentCertificate})
	f := buildReencryptForm("/tmp", node)

	// Default: "Overwrite original" -> output field hidden
	if f.fieldByName("output").Visible() {
		t.Error("output should be hidden when output_mode is 'Overwrite original'")
	}

	// Switch to "New file" -> output visible
	f.fieldByName("output_mode").SetValue("New file")
	f.evaluateVisibility()
	if !f.fieldByName("output").Visible() {
		t.Error("output should be visible when output_mode is 'New file'")
	}
}

// =============================================================================
// Metadata tests
// =============================================================================

func TestActionForms_StoreMetadata(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})

	f := buildSignCSRForm("/tmp", node, 0, 0)
	if f.getMeta("input_path") != "/tmp/test.csr" {
		t.Errorf("expected input_path '/tmp/test.csr', got '%s'", f.getMeta("input_path"))
	}
}

func TestBuildForm_ActionFormWithNode(t *testing.T) {
	initTestStyles()
	node := makeTestNode("/tmp/test.csr", "pem/csr", &certlib.CertItem{Type: certlib.ContentCSR})

	f := buildForm(formSignCSR, "/tmp", node, "", "", certlib.KeyGenOptions{}, 0, 0)
	if f == nil {
		t.Fatal("expected non-nil form for formSignCSR with valid node")
	}

	f = buildForm(formSignCSR, "/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	if f != nil {
		t.Error("expected nil form for formSignCSR with nil node")
	}
}
