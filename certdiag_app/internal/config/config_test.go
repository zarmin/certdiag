package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGetTUIScanDefaults_NilConfig(t *testing.T) {
	d := GetTUIScanDefaults(nil)
	if d.Recursive {
		t.Fatal("expected Recursive=false for nil config")
	}
	if d.MaxDepth != 0 {
		t.Fatalf("expected MaxDepth=0, got %d", d.MaxDepth)
	}
	if d.FileSignatureScan {
		t.Fatal("expected FileSignatureScan=false for nil config")
	}
	if d.AutoDiscover {
		t.Fatal("expected AutoDiscover=false for nil config")
	}
}

func TestGetTUIScanDefaults_AllSet(t *testing.T) {
	tr := true
	cfg := &ConfigFile{
		Defaults: DefaultsConfig{
			TUI: TUIConfig{
				Recursive:         &tr,
				MaxDepth:          5,
				FileSignatureScan: &tr,
				AutoDiscover:      &tr,
			},
		},
	}
	d := GetTUIScanDefaults(cfg)
	if !d.Recursive {
		t.Fatal("expected Recursive=true")
	}
	if d.MaxDepth != 5 {
		t.Fatalf("expected MaxDepth=5, got %d", d.MaxDepth)
	}
	if !d.FileSignatureScan {
		t.Fatal("expected FileSignatureScan=true")
	}
	if !d.AutoDiscover {
		t.Fatal("expected AutoDiscover=true")
	}
}

func TestGetTUIScanDefaults_PartialSet(t *testing.T) {
	tr := true
	cfg := &ConfigFile{
		Defaults: DefaultsConfig{
			TUI: TUIConfig{
				Recursive: &tr,
				MaxDepth:  3,
			},
		},
	}
	d := GetTUIScanDefaults(cfg)
	if !d.Recursive {
		t.Fatal("expected Recursive=true")
	}
	if d.MaxDepth != 3 {
		t.Fatalf("expected MaxDepth=3, got %d", d.MaxDepth)
	}
	if d.FileSignatureScan {
		t.Fatal("expected FileSignatureScan=false (unset)")
	}
	if d.AutoDiscover {
		t.Fatal("expected AutoDiscover=false (unset)")
	}
}

func TestValidateDefaults_MaxDepthNegative(t *testing.T) {
	cfg := &ConfigFile{
		Kind:    "certdiag-config",
		Version: "1",
		Defaults: DefaultsConfig{
			TUI: TUIConfig{
				MaxDepth: -5,
			},
		},
	}
	cfg.ValidateDefaults()
	if cfg.Defaults.TUI.MaxDepth != 0 {
		t.Fatalf("expected MaxDepth reset to 0, got %d", cfg.Defaults.TUI.MaxDepth)
	}
}

func TestLoadConfig_TUIOptions(t *testing.T) {
	yamlContent := `kind: certdiag-config
version: "1"
defaults:
  tui:
    recursive: true
    max_depth: 4
    file_signature_scan: true
    auto_discover: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	d := GetTUIScanDefaults(cfg)
	if !d.Recursive {
		t.Fatal("expected Recursive=true")
	}
	if d.MaxDepth != 4 {
		t.Fatalf("expected MaxDepth=4, got %d", d.MaxDepth)
	}
	if !d.FileSignatureScan {
		t.Fatal("expected FileSignatureScan=true")
	}
	if d.AutoDiscover {
		t.Fatal("expected AutoDiscover=false")
	}

	// Verify round-trip: marshal back and check structure
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var roundTrip ConfigFile
	if err := yaml.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	d2 := GetTUIScanDefaults(&roundTrip)
	if d2.Recursive != d.Recursive || d2.MaxDepth != d.MaxDepth ||
		d2.FileSignatureScan != d.FileSignatureScan || d2.AutoDiscover != d.AutoDiscover {
		t.Fatal("round-trip mismatch")
	}
}

func TestValidateDefaults_TUIColumnsCaseInsensitive(t *testing.T) {
	cfg := &ConfigFile{
		Kind:    "certdiag-config",
		Version: "1",
		Defaults: DefaultsConfig{
			TUI: TUIConfig{
				Columns: []string{"SUBJECT", "Issuer", "expiry", "BOGUS"},
			},
		},
	}
	cfg.ValidateDefaults()

	want := []string{"subject", "issuer", "expiry"}
	got := cfg.Defaults.TUI.Columns
	if len(got) != len(want) {
		t.Fatalf("expected columns %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("column %d = %q, want %q", i, got[i], w)
		}
	}
}
