package tui

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestCSRForm_EmptyOutputDefaultsToSuggestion verifies the fix for the silent
// no-write bug: when the CSR output/key fields are left blank the option builder
// must fall back to the placeholder-suggested path (so certops actually writes)
// instead of passing empty strings.
func TestCSRForm_EmptyOutputDefaultsToSuggestion(t *testing.T) {
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048})
	f.fieldByName("cn").SetValue("example.com")
	f.evaluateVisibility()

	if !f.validateAll() {
		t.Fatalf("form did not validate: %v", f.errors)
	}

	opts, err := buildCreateCSROptions(f, nil)
	if err != nil {
		t.Fatalf("buildCreateCSROptions: %v", err)
	}
	t.Logf("CSROutputPath=%q KeyOutputPath=%q", opts.CSROutputPath, opts.KeyOutputPath)

	if opts.CSROutputPath == "" || !strings.HasSuffix(opts.CSROutputPath, ".csr") {
		t.Errorf("CSROutputPath should default to a .csr path, got %q", opts.CSROutputPath)
	}
	if opts.WithKey && (opts.KeyOutputPath == "" || !strings.HasSuffix(opts.KeyOutputPath, ".key")) {
		t.Errorf("KeyOutputPath should default to a .key path when generating a key, got %q", opts.KeyOutputPath)
	}
}

// TestSignForm_EmptyOutputDefaultsToSuggestion verifies the same fix for the
// Sign CSR form.
func TestSignForm_EmptyOutputDefaultsToSuggestion(t *testing.T) {
	node := &TreeNode{
		Container: &certlib.CertContainer{FilePath: "/tmp/myrequest.csr"},
		Subject:   "CN=example.com",
	}
	f := buildSignCSRForm("/tmp", node, 365, 3650)
	if f == nil {
		t.Fatal("buildSignCSRForm returned nil")
	}
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")
	f.evaluateVisibility()

	if !f.validateAll() {
		t.Fatalf("form did not validate: %v", f.errors)
	}

	opts, err := buildSignCSROptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("buildSignCSROptions: %v", err)
	}
	t.Logf("CertOutputPath=%q", opts.CertOutputPath)
	if opts.CertOutputPath == "" || !strings.HasSuffix(opts.CertOutputPath, ".crt") {
		t.Errorf("CertOutputPath should default to a .crt path, got %q", opts.CertOutputPath)
	}
}
