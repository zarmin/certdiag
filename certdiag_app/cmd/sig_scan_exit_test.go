package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func runSigScanBinary(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stderr.String()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stderr.String()
	}
	t.Fatalf("unexpected error running binary: %v", err)
	return -1, stderr.String()
}

func writeValidCert(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(300 * 24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, buf, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return certPath
}

func TestSigScanReportsPathErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no", "such", "path")

	code, stderr := runSigScanBinary(t, "--file-signature-scan", missing)
	if code == 0 {
		t.Errorf("root --file-signature-scan on missing path exit code = 0, want non-zero")
	}
	if stderr == "" {
		t.Errorf("root --file-signature-scan on missing path produced no stderr, want error output")
	}

	code, stderr = runSigScanBinary(t, "check", "--file-signature-scan", missing)
	if code == 0 {
		t.Errorf("check --file-signature-scan on missing path exit code = 0, want non-zero")
	}
	if stderr == "" {
		t.Errorf("check --file-signature-scan on missing path produced no stderr, want error output")
	}
}

func TestSigScanValidFileStillSucceeds(t *testing.T) {
	certPath := writeValidCert(t)

	code, stderr := runSigScanBinary(t, "--file-signature-scan", certPath)
	if code != 0 {
		t.Errorf("root --file-signature-scan on valid cert exit code = %d, want 0 (stderr: %q)", code, stderr)
	}

	code, stderr = runSigScanBinary(t, "check", "--file-signature-scan", certPath)
	if code != 0 {
		t.Errorf("check --file-signature-scan on valid cert exit code = %d, want 0 (stderr: %q)", code, stderr)
	}
}
