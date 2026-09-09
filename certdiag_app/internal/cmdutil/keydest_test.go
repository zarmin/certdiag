package cmdutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyDestination(t *testing.T) {
	dir := t.TempDir()
	taken := filepath.Join(dir, "taken.key")
	if err := os.WriteFile(taken, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		certOut string
		keyOut  string
		withKey bool
		want    string
		wantErr string
	}{
		{"no key generated", filepath.Join(dir, "a.crt"), "", false, "", ""},
		{"explicit key output wins", filepath.Join(dir, "a.crt"), filepath.Join(dir, "k.pem"), true, filepath.Join(dir, "k.pem"), ""},
		{"stdout cert means stdout key", "", "", true, "", ""},
		{"derived from cert path", filepath.Join(dir, "site.crt"), "", true, filepath.Join(dir, "site.key"), ""},
		{"cert without extension", filepath.Join(dir, "site"), "", true, filepath.Join(dir, "site.key"), ""},
		{"cert already named .key", filepath.Join(dir, "odd.key"), "", true, filepath.Join(dir, "odd.key.key"), ""},
		{"derived path exists", filepath.Join(dir, "taken.crt"), "", true, "", "already exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyDestination(tt.certOut, tt.keyOut, tt.withKey)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
