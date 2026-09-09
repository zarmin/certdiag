package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteConfigPreservingModeAtomic verifies the rewrite goes through a
// temp+rename (content fully replaced, no temp file left behind), so a crash
// mid-write cannot truncate a password-bearing config.
func TestWriteConfigPreservingModeAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("old-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := writeConfigPreservingMode(p, []byte("new-content")); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new-content" {
		t.Errorf("content = %q, want %q", data, "new-content")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temp file left behind, dir contains %v", names)
	}
}
