package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewTUISetup_CarriesTheConfig guards M20 / R2: every TUI entry point
// starts from newTUISetup, so what the config says reaches the cert lister,
// the store view and the packet analyzer alike.
func TestNewTUISetup_CarriesTheConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "certdiag.yaml")
	cfgText := "kind: certdiag-config\nversion: \"1\"\ndefaults:\n  check:\n    disabled_checks:\n      - missing_sans\n      - wildcard\n  tui:\n    path_display: relative\n    recursive: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	orig := configFile
	configFile = cfgPath
	defer func() { configFile = orig }()

	setup := newTUISetup()

	if len(setup.opts.DisabledChecks) != 2 || setup.opts.DisabledChecks[0] != "missing_sans" {
		t.Errorf("DisabledChecks = %v, want the config's two ids", setup.opts.DisabledChecks)
	}
	if setup.opts.PathDisplay != "relative" {
		t.Errorf("PathDisplay = %q, want relative from defaults.tui", setup.opts.PathDisplay)
	}
	if !setup.scan.Recursive {
		t.Error("defaults.tui.recursive must reach the scan options")
	}
	if setup.opts.BundleDir == "" {
		t.Error("BundleDir must be set for every TUI entry point, so the trust-store view sees installed bundles")
	}
	if setup.opts.ConfigPath != cfgPath {
		t.Errorf("ConfigPath = %q, want %q", setup.opts.ConfigPath, cfgPath)
	}
	if setup.opts.SaveOptions == nil || setup.opts.SaveColumns == nil || setup.opts.SaveStoreOptions == nil {
		t.Error("the save callbacks must be wired")
	}
}
