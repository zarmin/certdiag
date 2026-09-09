package password

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPasswordFiles_MissingFile(t *testing.T) {
	_, err := ReadPasswordFiles([]string{"/nonexistent/password.txt"})
	if err == nil {
		t.Fatal("expected error for missing password file, got nil")
	}
}

func TestReadPasswordFiles_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.txt")
	if err := os.WriteFile(path, []byte("alpha\nbeta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	passwords, err := ReadPasswordFiles([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(passwords) != 2 {
		t.Fatalf("expected 2 passwords, got %d", len(passwords))
	}
	if string(passwords[0]) != "alpha" || string(passwords[1]) != "beta" {
		t.Errorf("unexpected passwords: %q, %q", passwords[0], passwords[1])
	}
}

func TestNewPasswordManager_PasswordsPreserveSpaces(t *testing.T) {
	pm, err := NewPasswordManager(PasswordManagerOpts{
		CLIPasswords: []string{"pass word with spaces"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pm.cliPasswords) != 1 {
		t.Fatalf("expected 1 password, got %d", len(pm.cliPasswords))
	}
	if string(pm.cliPasswords[0]) != "pass word with spaces" {
		t.Errorf("password was split: got %q", pm.cliPasswords[0])
	}
}

func TestNewPasswordManager_MissingPasswordFile(t *testing.T) {
	_, err := NewPasswordManager(PasswordManagerOpts{
		PasswordFiles: []string{"/nonexistent/file.txt"},
	})
	if err == nil {
		t.Fatal("expected error for missing password file")
	}
}
