//go:build !windows

// This test asserts POSIX permission bits. On Windows os.Stat reports 0666 for
// any writable file regardless of the mode passed to os.WriteFile, so the mode
// assertion is meaningful only on Unix-like platforms.
package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsureConfig_Is0600 verifies the fix: config files (which may hold
// plaintext passwords) are created with owner-only permissions.
func TestEnsureConfig_Is0600(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sub", "config.yaml")
	if err := EnsureConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("config created group/world readable: mode %o", mode)
	}
}
