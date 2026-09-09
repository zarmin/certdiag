package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeWeakCert(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "weak.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(300 * 24 * time.Hour),
		DNSNames:     []string{"weak.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "weak.pem")
	buf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, buf, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return certPath
}

func TestCheckStrictExitCodes(t *testing.T) {
	weak := writeWeakCert(t)
	clean := writeValidCert(t)

	t.Run("strict_warning_exits_2", func(t *testing.T) {
		code, stderr := runSigScanBinary(t, "check", "--strict", weak)
		if code != 2 {
			t.Errorf("check --strict on warning cert exit = %d, want 2 (stderr: %q)", code, stderr)
		}
	})

	t.Run("strict_severity_critical_still_exits_2", func(t *testing.T) {
		code, stderr := runSigScanBinary(t, "check", "--strict", "--severity", "critical", weak)
		if code != 2 {
			t.Errorf("check --strict --severity critical on warning-only cert exit = %d, want 2 (stderr: %q)", code, stderr)
		}
	})

	t.Run("severity_critical_no_strict_exits_0", func(t *testing.T) {
		code, stderr := runSigScanBinary(t, "check", "--severity", "critical", weak)
		if code != 0 {
			t.Errorf("check --severity critical on warning-only cert exit = %d, want 0 (stderr: %q)", code, stderr)
		}
	})

	t.Run("strict_clean_exits_0", func(t *testing.T) {
		code, stderr := runSigScanBinary(t, "check", "--strict", clean)
		if code != 0 {
			t.Errorf("check --strict on clean cert exit = %d, want 0 (stderr: %q)", code, stderr)
		}
	})
}
