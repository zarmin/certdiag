package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

func TestValidateDefaults_FingerprintFormat(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"hex", "hex"},
		{"hex-colon", "hex-colon"},
		{"base64", "base64"},
		{"HEX-COLON", "hex-colon"}, // lowercased in place
		{"bogus", ""},              // invalid resets, warning to stderr
		{"", ""},
	}
	for _, tt := range tests {
		cfg := &ConfigFile{}
		cfg.Defaults.Output.FingerprintFormat = tt.in
		cfg.ValidateDefaults()

		if got := cfg.Defaults.Output.FingerprintFormat; got != tt.want {
			t.Errorf("input %q: expected %q, got %q", tt.in, tt.want, got)
		}
	}
}

func TestFingerprintFormat_Accessor(t *testing.T) {
	if got := FingerprintFormat(nil); got != certlib.FingerprintHex {
		t.Errorf("nil config must default to hex, got %q", got)
	}

	cfg := &ConfigFile{}
	if got := FingerprintFormat(cfg); got != certlib.FingerprintHex {
		t.Errorf("unset must default to hex, got %q", got)
	}

	cfg.Defaults.Output.FingerprintFormat = "base64"
	if got := FingerprintFormat(cfg); got != certlib.FingerprintBase64 {
		t.Errorf("expected base64, got %q", got)
	}

	// An invalid value that somehow bypassed validation still degrades to hex
	// rather than producing an unusable format.
	cfg.Defaults.Output.FingerprintFormat = "nonsense"
	if got := FingerprintFormat(cfg); got != certlib.FingerprintHex {
		t.Errorf("expected a hex fallback, got %q", got)
	}
}

func TestValidateDefaults_AcceptsFingerprintColumns(t *testing.T) {
	cfg := &ConfigFile{}
	cfg.Defaults.TUI.Columns = []string{"subject", "fp_sha256", "fp_md5", "fp_bogus"}
	cfg.Defaults.TUI.TrustStoreColumns = []string{"stores", "fp_sha512", "fp_nope"}
	cfg.ValidateDefaults()

	wantCols := []string{"subject", "fp_sha256", "fp_md5"}
	if strings.Join(cfg.Defaults.TUI.Columns, ",") != strings.Join(wantCols, ",") {
		t.Errorf("expected %v, got %v", wantCols, cfg.Defaults.TUI.Columns)
	}

	wantStore := []string{"stores", "fp_sha512"}
	if strings.Join(cfg.Defaults.TUI.TrustStoreColumns, ",") != strings.Join(wantStore, ",") {
		t.Errorf("expected %v, got %v", wantStore, cfg.Defaults.TUI.TrustStoreColumns)
	}
}

func TestValidateDefaults_AllFingerprintColumnsValid(t *testing.T) {
	var cols []string
	for _, algo := range certlib.FingerprintAlgos {
		cols = append(cols, "fp_"+string(algo))
	}

	cfg := &ConfigFile{}
	cfg.Defaults.TUI.Columns = append([]string{}, cols...)
	cfg.Defaults.TUI.TrustStoreColumns = append([]string{}, cols...)
	cfg.ValidateDefaults()

	if len(cfg.Defaults.TUI.Columns) != len(cols) {
		t.Errorf("every fingerprint column must be accepted, got %v", cfg.Defaults.TUI.Columns)
	}
	if len(cfg.Defaults.TUI.TrustStoreColumns) != len(cols) {
		t.Errorf("fingerprint columns must work in the store view too, got %v",
			cfg.Defaults.TUI.TrustStoreColumns)
	}
}

func TestRewriteOutputFingerprintFormat(t *testing.T) {
	original := `kind: certdiag-config
version: "1"
defaults:
  output:
    format: "pem"
  tui:
    columns:
      - subject
passwords:
  common_plaintext:
    - "secret"
`
	out, err := RewriteOutputFingerprintFormat([]byte(original), "hex-colon")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed ConfigFile
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("result must parse: %v\n%s", err, out)
	}
	if parsed.Defaults.Output.FingerprintFormat != "hex-colon" {
		t.Errorf("expected the key written, got %q", parsed.Defaults.Output.FingerprintFormat)
	}
	// Neighbouring settings must survive the rewrite.
	if parsed.Defaults.Output.Format != "pem" {
		t.Error("expected defaults.output.format preserved")
	}
	if len(parsed.Defaults.TUI.Columns) != 1 {
		t.Error("expected tui columns preserved")
	}
	if len(parsed.Passwords.CommonPlaintext) != 1 {
		t.Error("expected passwords preserved")
	}
}

func TestRewriteOutputFingerprintFormat_UpdatesExisting(t *testing.T) {
	original := `kind: certdiag-config
version: "1"
defaults:
  output:
    fingerprint_format: "hex"
`
	out, err := RewriteOutputFingerprintFormat([]byte(original), "base64")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Count(string(out), "fingerprint_format") != 1 {
		t.Errorf("expected the key updated in place, not duplicated:\n%s", out)
	}
	if !strings.Contains(string(out), "base64") {
		t.Errorf("expected the new value:\n%s", out)
	}
}

func TestRewriteOutputFingerprintFormat_CreatesMissingSections(t *testing.T) {
	original := "kind: certdiag-config\nversion: \"1\"\n"

	out, err := RewriteOutputFingerprintFormat([]byte(original), "hex-colon")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed ConfigFile
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("result must parse: %v", err)
	}
	if parsed.Defaults.Output.FingerprintFormat != "hex-colon" {
		t.Errorf("expected defaults.output created, got %q", parsed.Defaults.Output.FingerprintFormat)
	}
}

func TestExampleConfig_DocumentsFingerprintFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := EnsureConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "fingerprint_format") {
		t.Error("the generated config should document fingerprint_format")
	}
	if !strings.Contains(string(data), "fp_sha256") {
		t.Error("the generated config should document the fingerprint columns")
	}
}
