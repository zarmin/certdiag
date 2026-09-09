package tui

import (
	"crypto/x509"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func initTestStyles() {
	initStyles()
	initFormStyles()
}

// =============================================================================
// Create Key option builder tests
// =============================================================================

func TestBuildCreateKeyOptions_RSA(t *testing.T) {
	initTestStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	f.fieldByName("algo").SetValue("RSA")
	f.fieldByName("size").SetValue("4096")
	f.evaluateVisibility()

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Algorithm != "rsa" {
		t.Errorf("expected algo rsa, got %s", opts.Algorithm)
	}
	if opts.KeySize != 4096 {
		t.Errorf("expected key size 4096, got %d", opts.KeySize)
	}
}

func TestBuildCreateKeyOptions_ECDSA(t *testing.T) {
	initTestStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	f.fieldByName("algo").SetValue("ECDSA")
	f.evaluateVisibility()
	f.fieldByName("curve").SetValue("P-384")

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Algorithm != "ecdsa" {
		t.Errorf("expected algo ecdsa, got %s", opts.Algorithm)
	}
	if opts.Curve != "p384" {
		t.Errorf("expected curve p384, got %s", opts.Curve)
	}
}

func TestBuildCreateKeyOptions_Encrypt(t *testing.T) {
	initTestStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	f.fieldByName("encrypt").SetValue("true")
	f.evaluateVisibility()
	f.fieldByName("password").(*textInputField).input.SetValue("secret123")

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.Encrypt {
		t.Error("expected Encrypt=true")
	}
	if string(opts.Password) != "secret123" {
		t.Errorf("expected password 'secret123', got '%s'", string(opts.Password))
	}
}

func TestBuildCreateKeyOptions_DERFormat(t *testing.T) {
	initTestStyles()
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	f.fieldByName("format").SetValue("DER")
	f.evaluateVisibility()

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Format != certlib.FormatDER {
		t.Errorf("expected FormatDER, got %s", opts.Format)
	}
}

// =============================================================================
// Create Cert option builder tests
// =============================================================================

func TestBuildCreateCertOptions_SelfSigned(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	f.fieldByName("signing").SetValue("Self-signed")
	f.evaluateVisibility()

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.SignerCertPath != "" {
		t.Errorf("expected empty signer cert path for self-signed, got %s", opts.SignerCertPath)
	}
	if opts.SignerKeyPath != "" {
		t.Errorf("expected empty signer key path for self-signed, got %s", opts.SignerKeyPath)
	}
}

func TestBuildCreateCertOptions_WithCA(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	f.fieldByName("signing").SetValue("Sign with CA")
	f.evaluateVisibility()
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.SignerCertPath != "/tmp/ca.crt" {
		t.Errorf("expected signer cert path '/tmp/ca.crt', got '%s'", opts.SignerCertPath)
	}
	if opts.SignerKeyPath != "/tmp/ca.key" {
		t.Errorf("expected signer key path '/tmp/ca.key', got '%s'", opts.SignerKeyPath)
	}
}

func TestBuildCreateCertOptions_CAType(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("My CA")
	f.fieldByName("cert_type").SetValue("CA")
	f.evaluateVisibility()
	f.fieldByName("path_len").(*textInputField).input.SetValue("1")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !opts.IsCA {
		t.Error("expected IsCA=true")
	}
	if opts.PathLength != 1 {
		t.Errorf("expected PathLength=1, got %d", opts.PathLength)
	}
}

func TestBuildCreateCertOptions_SANs(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	// Set SANs by manipulating the dynamic list field
	sansField := f.fieldByName("sans").(*dynamicListField)
	sansField.inputs[0].SetValue("dns:a.com")
	sansField.Update(makeSpecialKeyMsg(0x0d)) // Enter to add row
	sansField.inputs[1].SetValue("ip:1.2.3.4")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.SANs.DNSNames) != 1 || opts.SANs.DNSNames[0] != "a.com" {
		t.Errorf("expected DNS SAN 'a.com', got %v", opts.SANs.DNSNames)
	}
	if len(opts.SANs.IPAddresses) != 1 || opts.SANs.IPAddresses[0].String() != "1.2.3.4" {
		t.Errorf("expected IP SAN '1.2.3.4', got %v", opts.SANs.IPAddresses)
	}
}

func TestBuildCreateCertOptions_Subject(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("example.com")
	f.fieldByName("org").(*textInputField).input.SetValue("My Corp")
	f.fieldByName("country").(*textInputField).input.SetValue("US")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Subject.CommonName != "example.com" {
		t.Errorf("expected CN 'example.com', got '%s'", opts.Subject.CommonName)
	}
	if len(opts.Subject.Organization) != 1 || opts.Subject.Organization[0] != "My Corp" {
		t.Errorf("expected Org 'My Corp', got %v", opts.Subject.Organization)
	}
	if len(opts.Subject.Country) != 1 || opts.Subject.Country[0] != "US" {
		t.Errorf("expected Country 'US', got %v", opts.Subject.Country)
	}
}

func TestBuildCreateCertOptions_Defaults(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Days != 365 {
		t.Errorf("expected days=365, got %d", opts.Days)
	}
	if opts.OutputFormat != certlib.FormatPEM {
		t.Errorf("expected FormatPEM, got %s", opts.OutputFormat)
	}
	if !opts.WithKey {
		t.Error("expected WithKey=true")
	}
	if opts.IsCA {
		t.Error("expected IsCA=false by default")
	}
}

// =============================================================================
// Create CSR option builder tests
// =============================================================================

func TestBuildCreateCSROptions_Basic(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")

	opts, err := buildCreateCSROptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", opts.Subject.CommonName)
	}
	if !opts.WithKey {
		t.Error("expected WithKey=true")
	}
	if opts.OutputFormat != certlib.FormatPEM {
		t.Errorf("expected FormatPEM, got %s", opts.OutputFormat)
	}
}

func TestBuildCreateCSROptions_SANs(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	sansField := f.fieldByName("sans").(*dynamicListField)
	sansField.inputs[0].SetValue("dns:a.com")

	opts, err := buildCreateCSROptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(opts.SANs.DNSNames) != 1 || opts.SANs.DNSNames[0] != "a.com" {
		t.Errorf("expected DNS SAN 'a.com', got %v", opts.SANs.DNSNames)
	}
}

func TestBuildCreateCSROptions_ECDSADefault(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")

	// Default algo index is 0 which is ECDSA
	algoVal := f.fieldValue("algo")
	if algoVal != "ECDSA" {
		t.Fatalf("expected default algo 'ECDSA', got '%s'", algoVal)
	}

	opts, err := buildCreateCSROptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.KeyOptions.Algorithm != "ecdsa" {
		t.Errorf("expected key algo 'ecdsa', got '%s'", opts.KeyOptions.Algorithm)
	}
}

func TestBuildCreateCSROptions_UseExistingKey(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	f.fieldByName("key_source").SetValue(keySourceExisting)
	f.evaluateVisibility()
	f.fieldByName("key_path").SetValue("/tmp/my.key")

	opts, err := buildCreateCSROptions(f, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.WithKey {
		t.Error("expected WithKey=false when using existing key")
	}
	if opts.KeyFilePath != "/tmp/my.key" {
		t.Errorf("expected KeyFilePath '/tmp/my.key', got '%s'", opts.KeyFilePath)
	}
	if opts.KeyOutputPath != "" {
		t.Errorf("expected empty KeyOutputPath, got '%s'", opts.KeyOutputPath)
	}
}

// =============================================================================
// Confirm-discard dirty tracking tests
// =============================================================================

func TestBuildCreateCertForm_ConfirmDiscard_Dirty(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	// Initially clean
	if f.isDirty() {
		t.Error("new cert form should not be dirty")
	}

	// Modify CN field
	f.fieldByName("cn").(*textInputField).input.SetValue("modified")
	if !f.isDirty() {
		t.Error("cert form should be dirty after editing CN")
	}
}

func TestBuildCreateCertForm_ConfirmDiscard_Clean(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	if f.isDirty() {
		t.Error("unmodified cert form should not be dirty")
	}
}

// =============================================================================
// Form structure tests
// =============================================================================

func TestBuildCreateCertForm_Fields(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	expected := []string{"cn", "org", "country", "extra_dn", "sans", "key_source", "key_path", "algo", "size", "curve",
		"signing", "ca_cert", "ca_key", "cert_type", "days", "path_len", "permitted_names", "excluded_names", "key_usage", "ext_key_usage",
		"output_mode", "format", "encrypt_key", "encrypt_password", "cert_out", "key_out", "bundle_out", "submit"}
	if len(f.fieldNames) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(f.fieldNames), f.fieldNames)
	}
	for i, name := range expected {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildCreateCertForm_Sections(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	expectedSections := []string{"Subject", "Key", "Signing", "Certificate", "Output"}
	if len(f.sections) != len(expectedSections) {
		t.Fatalf("expected %d sections, got %d", len(expectedSections), len(f.sections))
	}
	for i, name := range expectedSections {
		if f.sections[i].title != name {
			t.Errorf("section %d: expected %q, got %q", i, name, f.sections[i].title)
		}
	}
}

func TestBuildCreateCertForm_LeafKUDefaults(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
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

func TestBuildCreateCertForm_CAKUDefaults(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("My CA")
	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
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

func TestBuildCreateCertForm_CustomKU(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("cn").(*textInputField).input.SetValue("test.example.com")
	f.fieldByName("key_usage").SetValue("digitalSignature,contentCommitment")
	f.fieldByName("ext_key_usage").SetValue("codeSigning")

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedKU := x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	if opts.KeyUsage != expectedKU {
		t.Errorf("expected custom KU %d, got %d", expectedKU, opts.KeyUsage)
	}
	if len(opts.ExtKeyUsage) != 1 || opts.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("expected EKU=[codeSigning], got %v", opts.ExtKeyUsage)
	}
}

func TestBuildCreateCertForm_KUSwitchesOnCertType(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	// Default leaf
	kuVal := f.fieldValue("key_usage")
	if kuVal != kuDefaultLeaf {
		t.Errorf("expected leaf KU default %q, got %q", kuDefaultLeaf, kuVal)
	}
	ekuVal := f.fieldValue("ext_key_usage")
	if ekuVal != ekuDefaultLeaf {
		t.Errorf("expected leaf EKU default %q, got %q", ekuDefaultLeaf, ekuVal)
	}

	// Switch to CA
	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	kuVal = f.fieldValue("key_usage")
	if kuVal != kuDefaultCA {
		t.Errorf("expected CA KU default %q, got %q", kuDefaultCA, kuVal)
	}
	ekuVal = f.fieldValue("ext_key_usage")
	if ekuVal != "" {
		t.Errorf("expected empty EKU for CA, got %q", ekuVal)
	}

	// Switch back to Leaf
	f.fieldByName("cert_type").SetValue("Leaf")
	f.evaluateVisibility()

	kuVal = f.fieldValue("key_usage")
	if kuVal != kuDefaultLeaf {
		t.Errorf("expected leaf KU default %q after switching back, got %q", kuDefaultLeaf, kuVal)
	}
	ekuVal = f.fieldValue("ext_key_usage")
	if ekuVal != ekuDefaultLeaf {
		t.Errorf("expected leaf EKU default %q after switching back, got %q", ekuDefaultLeaf, ekuVal)
	}
}

func TestBuildCreateCertForm_CAFieldsHiddenByDefault(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	if f.fieldByName("ca_cert").Visible() {
		t.Error("ca_cert should be hidden when signing is Self-signed")
	}
	if f.fieldByName("ca_key").Visible() {
		t.Error("ca_key should be hidden when signing is Self-signed")
	}
	if f.fieldByName("path_len").Visible() {
		t.Error("path_len should be hidden when cert_type is Leaf")
	}
}

func TestBuildCreateCertForm_SignWithCAShowsPaths(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)
	f.fieldByName("signing").SetValue("Sign with CA")
	f.evaluateVisibility()

	if !f.fieldByName("ca_cert").Visible() {
		t.Error("ca_cert should be visible when signing is 'Sign with CA'")
	}
	if !f.fieldByName("ca_key").Visible() {
		t.Error("ca_key should be visible when signing is 'Sign with CA'")
	}
}

func TestBuildCreateCSRForm_Fields(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})

	expected := []string{"cn", "org", "country", "extra_dn", "sans", "key_source", "key_path", "algo", "size", "curve",
		"format", "csr_out", "key_out", "submit"}
	if len(f.fieldNames) != len(expected) {
		t.Fatalf("expected %d fields, got %d: %v", len(expected), len(f.fieldNames), f.fieldNames)
	}
	for i, name := range expected {
		if f.fieldNames[i] != name {
			t.Errorf("field %d: expected %q, got %q", i, name, f.fieldNames[i])
		}
	}
}

func TestBuildCreateCSRForm_Sections(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})

	expectedSections := []string{"Subject", "Key", "Output"}
	if len(f.sections) != len(expectedSections) {
		t.Fatalf("expected %d sections, got %d", len(expectedSections), len(f.sections))
	}
	for i, name := range expectedSections {
		if f.sections[i].title != name {
			t.Errorf("section %d: expected %q, got %q", i, name, f.sections[i].title)
		}
	}
}

func TestBuildCreateCSRForm_KeySourceVisibility(t *testing.T) {
	initTestStyles()
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})

	// Default: "Generate new" — algo visible, key_path hidden, key_out visible
	if !f.fieldByName("algo").Visible() {
		t.Error("algo should be visible when key_source is Generate new")
	}
	if f.fieldByName("key_path").Visible() {
		t.Error("key_path should be hidden when key_source is Generate new")
	}
	if !f.fieldByName("key_out").Visible() {
		t.Error("key_out should be visible when key_source is Generate new")
	}

	// Switch to "Use existing"
	f.fieldByName("key_source").SetValue(keySourceExisting)
	f.evaluateVisibility()

	if f.fieldByName("algo").Visible() {
		t.Error("algo should be hidden when key_source is Use existing")
	}
	if !f.fieldByName("key_path").Visible() {
		t.Error("key_path should be visible when key_source is Use existing")
	}
	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden when key_source is Use existing")
	}
	if f.fieldByName("curve").Visible() {
		t.Error("curve should be hidden when key_source is Use existing")
	}
	if f.fieldByName("key_out").Visible() {
		t.Error("key_out should be hidden when key_source is Use existing")
	}

	// Switch back to "Generate new"
	f.fieldByName("key_source").SetValue(keySourceGenerate)
	f.evaluateVisibility()

	if !f.fieldByName("algo").Visible() {
		t.Error("algo should be visible after switching back to Generate new")
	}
	if f.fieldByName("key_path").Visible() {
		t.Error("key_path should be hidden after switching back to Generate new")
	}
	if !f.fieldByName("key_out").Visible() {
		t.Error("key_out should be visible after switching back to Generate new")
	}
}

func TestBuildCreateCSRForm_PrefillFromKeyNode(t *testing.T) {
	initTestStyles()
	node := &TreeNode{
		ContentType: "pem/key",
		Container:   &certlib.CertContainer{FilePath: "/tmp/my.key"},
	}
	f := buildCreateCSRForm("/tmp", node, "", "", certlib.KeyGenOptions{})

	if f.fieldValue("key_source") != keySourceExisting {
		t.Errorf("expected key_source %q, got %q", keySourceExisting, f.fieldValue("key_source"))
	}
	if f.fieldValue("key_path") != "/tmp/my.key" {
		t.Errorf("expected key_path '/tmp/my.key', got %q", f.fieldValue("key_path"))
	}
}

// TestCertForm_NameConstraintsAreCAOnly: constraints only mean something on a
// CA, so the fields appear with the CA branch and not before.
func TestCertForm_NameConstraintsAreCAOnly(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	if f.fieldByName(fieldKeyPermittedNames) == nil {
		t.Fatal("the permitted names field must exist")
	}
	if f.fieldByName(fieldKeyPermittedNames).Visible() {
		t.Error("a leaf has nothing to constrain")
	}

	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	if !f.fieldByName(fieldKeyPermittedNames).Visible() {
		t.Error("a CA must be able to say what it may issue for")
	}
	if !f.fieldByName(fieldKeyExcludedNames).Visible() {
		t.Error("the excluded side must appear with it")
	}
}

// TestCertForm_NameConstraintsValidate: a mistyped constraint is caught at the
// field rather than at signing time.
func TestCertForm_NameConstraintsValidate(t *testing.T) {
	initTestStyles()
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{}, 0, 0)

	for i, name := range f.fieldNames {
		if name != fieldKeyPermittedNames {
			continue
		}
		field := f.fields[i]
		_ = i

		field.SetValue("DNS:example.com,IP:10.0.0.0/8")
		if err := field.Validate(); err != nil {
			t.Errorf("valid constraints must be accepted: %v", err)
		}
		field.SetValue("example.com")
		if err := field.Validate(); err == nil {
			t.Error("a value without a type prefix must be rejected at the field")
		}
		field.SetValue("")
		if err := field.Validate(); err != nil {
			t.Errorf("an empty value means unconstrained: %v", err)
		}
		return
	}
	t.Fatal("field not found")
}
