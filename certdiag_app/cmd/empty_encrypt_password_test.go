package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptyEncryptPasswordRejected(t *testing.T) {
	dir := t.TempDir()

	baseCert := filepath.Join(dir, "base.pem")
	baseKey := filepath.Join(dir, "base.key")
	if code := runRemoteBinary(t, "create-cert", "--subject", "CN=renewme",
		"--with-key", "--key-output", baseKey, "-o", baseCert); code != 0 {
		t.Fatalf("failed to generate base cert for renew, exit=%d", code)
	}

	tests := []struct {
		name   string
		keyOut string
		args   []string
	}{
		{
			name:   "create-key",
			keyOut: filepath.Join(dir, "ck.key"),
			args:   []string{"create-key", "--encrypt-key", "-p", "", "-o", filepath.Join(dir, "ck.key")},
		},
		{
			name:   "create-csr",
			keyOut: filepath.Join(dir, "csr.key"),
			args:   []string{"create-csr", "--subject", "CN=test", "--with-key", "--encrypt-key", "-p", "", "--key-output", filepath.Join(dir, "csr.key"), "-o", filepath.Join(dir, "csr.pem")},
		},
		{
			name:   "create-cert",
			keyOut: filepath.Join(dir, "cc.key"),
			args:   []string{"create-cert", "--subject", "CN=test", "--with-key", "--encrypt-key", "-p", "", "--key-output", filepath.Join(dir, "cc.key"), "-o", filepath.Join(dir, "cc.pem")},
		},
		{
			name:   "renew",
			keyOut: filepath.Join(dir, "rn.key"),
			args:   []string{"renew", baseCert, "--key-file", baseKey, "--new-key", "--encrypt-key", "-p", "", "--key-output", filepath.Join(dir, "rn.key"), "-o", filepath.Join(dir, "rn.pem")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := runRemoteBinary(t, tt.args...)
			if code != 1 {
				t.Errorf("empty -p exit code = %d, want 1", code)
			}
			if data, err := os.ReadFile(tt.keyOut); err == nil {
				if strings.Contains(string(data), "ENCRYPTED") {
					t.Errorf("produced an encrypted key with empty password: %s", tt.keyOut)
				}
			}
		})
	}
}
