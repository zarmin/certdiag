//go:build !windows

// This test asserts POSIX permission bits. On Windows os.Stat reports 0666 for
// any writable file regardless of the mode passed, so the mode assertion is
// meaningful only on Unix-like platforms.
package certlib

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteToFile_PreservesModeOnOverwrite(t *testing.T) {
	dir := t.TempDir()

	t.Run("Overwrite0644", func(t *testing.T) {
		path := filepath.Join(dir, "bundle0644.pem")
		if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := WriteToFile(path, []byte("new"), true); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0644 {
			t.Fatalf("mode = %o, want 0644", got)
		}
	})

	t.Run("Overwrite0640", func(t *testing.T) {
		path := filepath.Join(dir, "bundle0640.pem")
		if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := WriteToFile(path, []byte("new"), true); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0640 {
			t.Fatalf("mode = %o, want 0640", got)
		}
	})

	t.Run("NewFileIs0600", func(t *testing.T) {
		path := filepath.Join(dir, "fresh.pem")
		if err := WriteToFile(path, []byte("new"), true); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("mode = %o, want 0600", got)
		}
	})
}
