package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runRenewBinary(t *testing.T, home string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Env = append(os.Environ(), "HOME="+home, "CERTDIAG_CONFIG=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("unexpected error running binary: %v", err)
	return -1, string(out)
}

func TestRenewValidatesNewKeyParams(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "input.crt")
	keyPath := filepath.Join(dir, "input.key")

	code, out := runRenewBinary(t, home, "create-cert", "--with-key",
		"--subject", "CN=renew-test", "-o", certPath, "--key-output", keyPath, "--no-confirm")
	if code != 0 {
		t.Fatalf("create-cert setup failed (exit %d): %s", code, out)
	}

	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantMsg  string
	}{
		{
			name:     "bad_algorithm",
			args:     []string{"renew", certPath, "--new-key", "-a", "bogus", "-o", filepath.Join(dir, "r1.crt"), "--key-output", filepath.Join(dir, "r1.key"), "--no-confirm"},
			wantCode: 1,
			wantMsg:  "invalid algorithm",
		},
		{
			name:     "bad_rsa_key_size",
			args:     []string{"renew", certPath, "--new-key", "-a", "rsa", "-s", "9999", "-o", filepath.Join(dir, "r2.crt"), "--key-output", filepath.Join(dir, "r2.key"), "--no-confirm"},
			wantCode: 1,
			wantMsg:  "invalid RSA key size",
		},
		{
			name:     "valid_rsa",
			args:     []string{"renew", certPath, "--new-key", "-a", "rsa", "-s", "2048", "-o", filepath.Join(dir, "r3.crt"), "--key-output", filepath.Join(dir, "r3.key"), "--no-confirm"},
			wantCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out := runRenewBinary(t, home, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\noutput: %s", code, tt.wantCode, out)
			}
			if tt.wantMsg != "" && !strings.Contains(out, tt.wantMsg) {
				t.Errorf("output missing %q\noutput: %s", tt.wantMsg, out)
			}
		})
	}
}
