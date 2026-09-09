package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRewriteTUIOptions_CreatesPath(t *testing.T) {
	input := []byte(`kind: certdiag-config
version: "1"
`)
	opts := TUIOptionsForSave{
		Recursive:         true,
		MaxDepth:          3,
		FileSignatureScan: false,
		AutoDiscover:      true,
	}
	out, err := RewriteTUIOptions(input, opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions error: %v", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if cfg.Defaults.TUI.Recursive == nil || !*cfg.Defaults.TUI.Recursive {
		t.Fatal("expected recursive=true")
	}
	if cfg.Defaults.TUI.MaxDepth != 3 {
		t.Fatalf("expected max_depth=3, got %d", cfg.Defaults.TUI.MaxDepth)
	}
	if cfg.Defaults.TUI.FileSignatureScan == nil || *cfg.Defaults.TUI.FileSignatureScan {
		t.Fatal("expected file_signature_scan=false")
	}
	if cfg.Defaults.TUI.AutoDiscover == nil || !*cfg.Defaults.TUI.AutoDiscover {
		t.Fatal("expected auto_discover=true")
	}
}

func TestRewriteTUIOptions_ExistingDefaults(t *testing.T) {
	input := []byte(`kind: certdiag-config
version: "1"
defaults:
  key:
    algorithm: ecdsa
`)
	opts := TUIOptionsForSave{
		Recursive: true,
		MaxDepth:  2,
	}
	out, err := RewriteTUIOptions(input, opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions error: %v", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if cfg.Defaults.TUI.Recursive == nil || !*cfg.Defaults.TUI.Recursive {
		t.Fatal("expected recursive=true")
	}
	if cfg.Defaults.TUI.MaxDepth != 2 {
		t.Fatalf("expected max_depth=2, got %d", cfg.Defaults.TUI.MaxDepth)
	}
	// key defaults should be preserved
	if cfg.Defaults.Key.Algorithm != "ecdsa" {
		t.Fatalf("expected key algorithm=ecdsa, got %q", cfg.Defaults.Key.Algorithm)
	}
}

func TestRewriteTUIOptions_ExistingTUI(t *testing.T) {
	input := []byte(`kind: certdiag-config
version: "1"
defaults:
  tui:
    recursive: false
    max_depth: 1
`)
	opts := TUIOptionsForSave{
		Recursive:         true,
		MaxDepth:          7,
		FileSignatureScan: true,
		AutoDiscover:      false,
	}
	out, err := RewriteTUIOptions(input, opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions error: %v", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if cfg.Defaults.TUI.Recursive == nil || !*cfg.Defaults.TUI.Recursive {
		t.Fatal("expected recursive=true (updated)")
	}
	if cfg.Defaults.TUI.MaxDepth != 7 {
		t.Fatalf("expected max_depth=7, got %d", cfg.Defaults.TUI.MaxDepth)
	}
	if cfg.Defaults.TUI.FileSignatureScan == nil || !*cfg.Defaults.TUI.FileSignatureScan {
		t.Fatal("expected file_signature_scan=true")
	}
	if cfg.Defaults.TUI.AutoDiscover == nil || *cfg.Defaults.TUI.AutoDiscover {
		t.Fatal("expected auto_discover=false")
	}
}

func TestRewriteTUIOptions_PreservesColumns(t *testing.T) {
	input := []byte(`kind: certdiag-config
version: "1"
defaults:
  tui:
    columns:
      - subject
      - issuer
      - expiry
    recursive: false
`)
	opts := TUIOptionsForSave{
		Recursive: true,
		MaxDepth:  5,
	}
	out, err := RewriteTUIOptions(input, opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions error: %v", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	// columns must still be present
	if len(cfg.Defaults.TUI.Columns) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(cfg.Defaults.TUI.Columns))
	}
	expected := []string{"subject", "issuer", "expiry"}
	for i, col := range expected {
		if cfg.Defaults.TUI.Columns[i] != col {
			t.Fatalf("column[%d]: expected %q, got %q", i, col, cfg.Defaults.TUI.Columns[i])
		}
	}
	// options should be updated
	if cfg.Defaults.TUI.Recursive == nil || !*cfg.Defaults.TUI.Recursive {
		t.Fatal("expected recursive=true")
	}
	if cfg.Defaults.TUI.MaxDepth != 5 {
		t.Fatalf("expected max_depth=5, got %d", cfg.Defaults.TUI.MaxDepth)
	}
}

// --- Comment preservation tests ---

const commentedYAML = `# Application config
kind: certdiag-config
version: "1"  # config version
defaults:
  # Key generation defaults
  key:
    algorithm: ecdsa  # recommended
  # TUI display settings
  tui:
    recursive: false
    max_depth: 3  # directory depth
    columns:
      - subject
      - issuer  # certificate issuer
      - expiry
# Password section
passwords:
  store: "encrypted-value-here"  # will be replaced
`

func requireContains(t *testing.T, output, comment string) {
	t.Helper()
	if !strings.Contains(output, comment) {
		t.Errorf("expected output to contain %q, got:\n%s", comment, output)
	}
}

var allComments = []string{
	"# Application config",
	"# config version",
	"# Key generation defaults",
	"# recommended",
	"# TUI display settings",
	"# directory depth",
	"# certificate issuer",
	"# Password section",
	"# will be replaced",
}

func TestCommentPreservation_RoundTrip(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(commentedYAML), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := encodeNode(&node)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	output := string(out)
	for _, c := range allComments {
		requireContains(t, output, c)
	}
}

func TestCommentPreservation_RewriteEncryptedPasswords(t *testing.T) {
	replacements := map[string]string{
		"encrypted-value-here": "new-encrypted-value",
	}
	out, err := RewriteEncryptedPasswords([]byte(commentedYAML), replacements)
	if err != nil {
		t.Fatalf("RewriteEncryptedPasswords: %v", err)
	}
	output := string(out)
	for _, c := range allComments {
		requireContains(t, output, c)
	}
	requireContains(t, output, "new-encrypted-value")
}

func TestCommentPreservation_RewriteTUIColumns(t *testing.T) {
	newColumns := []string{"subject", "expiry", "serial"}
	out, err := RewriteTUIColumns([]byte(commentedYAML), newColumns)
	if err != nil {
		t.Fatalf("RewriteTUIColumns: %v", err)
	}
	output := string(out)

	nonColumnComments := []string{
		"# Application config",
		"# config version",
		"# Key generation defaults",
		"# recommended",
		"# TUI display settings",
		"# directory depth",
		"# Password section",
		"# will be replaced",
	}
	for _, c := range nonColumnComments {
		requireContains(t, output, c)
	}
	requireContains(t, output, "serial")
}

func TestCommentPreservation_RewriteTUIOptions(t *testing.T) {
	opts := TUIOptionsForSave{
		Recursive: true,
		MaxDepth:  10,
	}
	out, err := RewriteTUIOptions([]byte(commentedYAML), opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions: %v", err)
	}
	output := string(out)

	nonTUIOptionComments := []string{
		"# Application config",
		"# config version",
		"# Key generation defaults",
		"# recommended",
		"# TUI display settings",
		"# Password section",
		"# will be replaced",
	}
	for _, c := range nonTUIOptionComments {
		requireContains(t, output, c)
	}
	requireContains(t, output, "max_depth: 10")
}

func TestCommentPreservation_InlineCommentOnModifiedValue(t *testing.T) {
	input := `port: 8080  # listen port
host: localhost  # server host
`
	replacements := map[string]string{"8080": "9090"}
	out, err := RewriteEncryptedPasswords([]byte(input), replacements)
	if err != nil {
		t.Fatalf("RewriteEncryptedPasswords: %v", err)
	}
	output := string(out)
	requireContains(t, output, "# listen port")
	requireContains(t, output, "# server host")
	requireContains(t, output, "9090")
}

func TestCommentPreservation_AddNewKeyPreservesExisting(t *testing.T) {
	input := `# App config
kind: certdiag-config
version: "1"  # config version
defaults:
  # Key settings
  key:
    algorithm: rsa  # default algo
`
	opts := TUIOptionsForSave{
		Recursive: true,
		MaxDepth:  5,
	}
	out, err := RewriteTUIOptions([]byte(input), opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions: %v", err)
	}
	output := string(out)
	requireContains(t, output, "# App config")
	requireContains(t, output, "# config version")
	requireContains(t, output, "# Key settings")
	requireContains(t, output, "# default algo")
	requireContains(t, output, "recursive: true")
}

func TestCommentPreservation_DeepNestedComments(t *testing.T) {
	input := `# Root comment
level1:
  # Level 1 comment
  level2:
    # Level 2 comment
    level3:
      # Level 3 comment
      value: original  # deep inline
`
	replacements := map[string]string{"original": "modified"}
	out, err := RewriteEncryptedPasswords([]byte(input), replacements)
	if err != nil {
		t.Fatalf("RewriteEncryptedPasswords: %v", err)
	}
	output := string(out)
	requireContains(t, output, "# Root comment")
	requireContains(t, output, "# Level 1 comment")
	requireContains(t, output, "# Level 2 comment")
	requireContains(t, output, "# Level 3 comment")
	requireContains(t, output, "# deep inline")
	requireContains(t, output, "modified")
}

func TestCommentPreservation_HeadCommentsAboveKeys(t *testing.T) {
	input := `# Server settings
server:
  # Network configuration
  port: 443
  # TLS settings
  tls: true
`
	replacements := map[string]string{"443": "8443"}
	out, err := RewriteEncryptedPasswords([]byte(input), replacements)
	if err != nil {
		t.Fatalf("RewriteEncryptedPasswords: %v", err)
	}
	output := string(out)
	requireContains(t, output, "# Server settings")
	requireContains(t, output, "# Network configuration")
	requireContains(t, output, "# TLS settings")
	requireContains(t, output, "8443")
}

func TestRewriteTUIOptions_RoundTrip(t *testing.T) {
	input := []byte(`kind: certdiag-config
version: "1"
`)
	opts := TUIOptionsForSave{
		Recursive:         true,
		MaxDepth:          8,
		FileSignatureScan: true,
		AutoDiscover:      true,
	}
	out, err := RewriteTUIOptions(input, opts)
	if err != nil {
		t.Fatalf("RewriteTUIOptions error: %v", err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	d := GetTUIScanDefaults(&cfg)
	if !d.Recursive {
		t.Fatal("expected Recursive=true")
	}
	if d.MaxDepth != 8 {
		t.Fatalf("expected MaxDepth=8, got %d", d.MaxDepth)
	}
	if !d.FileSignatureScan {
		t.Fatal("expected FileSignatureScan=true")
	}
	if !d.AutoDiscover {
		t.Fatal("expected AutoDiscover=true")
	}
}
