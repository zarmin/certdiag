package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func makeSelfSigned(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "list-alias-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}
	return key, cert, der
}

func runListBinary(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("unexpected error running binary: %v", err)
	return "", -1
}

func TestListAcceptsPasswordFlagAndUnlocks(t *testing.T) {
	key, cert, _ := makeSelfSigned(t)
	data, err := gopkcs12.Modern2023.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}
	dir := t.TempDir()
	p12Path := filepath.Join(dir, "locked.p12")
	if err := os.WriteFile(p12Path, data, 0600); err != nil {
		t.Fatal(err)
	}

	out, code := runListBinary(t, dir, "list", "-p", "secret", p12Path)
	if strings.Contains(out, "unknown shorthand flag") || strings.Contains(out, "unknown flag") {
		t.Fatalf("list did not accept -p flag: %s", out)
	}
	if code != 0 {
		t.Fatalf("list -p secret exit=%d, want 0; output: %s", code, out)
	}
	if !strings.Contains(out, "list-alias-test") {
		t.Fatalf("expected unlocked cert in output, got: %s", out)
	}
}

func TestListPromptFlagAccepted(t *testing.T) {
	out, _ := runListBinary(t, t.TempDir(), "list", "--help")
	for _, flag := range []string{"--password", "-p,", "--password-file", "-P,", "--password-prompt", "-i,"} {
		if !strings.Contains(out, flag) {
			t.Errorf("list --help missing %q; help:\n%s", flag, out)
		}
	}
}

func TestListNoArgsScansCurrentDir(t *testing.T) {
	_, _, der := makeSelfSigned(t)
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "cert.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatal(err)
	}

	out, code := runListBinary(t, dir, "list")
	if code != 0 {
		t.Fatalf("list with no args exit=%d, want 0; output: %s", code, out)
	}
	if strings.Contains(out, "Alias for the root command") || strings.Contains(out, "Usage:") {
		t.Fatalf("list with no args printed help instead of scanning: %s", out)
	}
	if !strings.Contains(out, "list-alias-test") {
		t.Fatalf("expected scanned cert in output, got: %s", out)
	}
}
