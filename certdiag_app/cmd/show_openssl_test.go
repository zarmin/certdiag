package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runShowOpenSSL(t *testing.T, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running binary: %v", err)
		}
	}
	return out.String(), errBuf.String(), code
}

func TestShowOpenSSLDryRunCreatesNoFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	stdout, _, code := runShowOpenSSL(t, dir,
		"create-key", "-a", "rsa", "-s", "2048", "-o", keyPath, "--show-openssl", "--dry-run")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048") {
		t.Errorf("stdout missing genpkey command:\n%s", stdout)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("--dry-run must not create %s (err=%v)", keyPath, err)
	}
}

func TestShowOpenSSLWithoutDryRunStillWorks(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	stdout, stderr, code := runShowOpenSSL(t, dir,
		"create-key", "-a", "ecdsa", "--curve", "p256", "-o", keyPath, "--show-openssl")
	if code != 0 {
		t.Fatalf("exit code = %d\nstderr: %s", code, stderr)
	}
	// The openssl block goes to stderr when the real work is also performed.
	if !strings.Contains(stderr, "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256") {
		t.Errorf("stderr missing genpkey command:\n%s", stderr)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected key to be written: %v", err)
	}
	if strings.Contains(stdout, "openssl") {
		t.Errorf("stdout should not carry the openssl block in non-dry-run mode:\n%s", stdout)
	}
}

func TestShowOpenSSLInspect(t *testing.T) {
	dir := t.TempDir()
	// Create a cert to inspect.
	if _, _, code := runShowOpenSSL(t, dir,
		"create-cert", "--with-key", "--subject", "CN=inspect.test",
		"-o", filepath.Join(dir, "cert.pem"), "--key-output", filepath.Join(dir, "k.key"),
		"--no-confirm"); code != 0 {
		t.Fatalf("setup create-cert failed, code=%d", code)
	}

	stdout, _, code := runShowOpenSSL(t, dir, "cert.pem", "--show-openssl", "--dry-run")
	if code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, "openssl x509 -in cert.pem -text -noout") {
		t.Errorf("stdout missing inspect command:\n%s", stdout)
	}
}
