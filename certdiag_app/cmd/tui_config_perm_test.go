//go:build !windows

// These tests assert POSIX permission bits. On Windows os.Stat reports 0666 for
// any writable file regardless of the mode passed to os.WriteFile, so the mode
// assertions are meaningful only on Unix-like platforms.
package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteConfigPreservingMode verifies the fix: rewriting a config preserves
// its (tightened) permissions instead of widening to 0644.
func TestWriteConfigPreservingMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigPreservingMode(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("rewrite changed mode to %o, want 0600 (must not widen)", mode)
	}
}

// TestWriteConfigPreservingMode_DefaultsTo0600 verifies a new file (no prior
// mode) is created 0600.
func TestWriteConfigPreservingMode_DefaultsTo0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.yaml")
	if err := writeConfigPreservingMode(p, []byte("data")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("new config is group/world readable: mode %o", mode)
	}
}
