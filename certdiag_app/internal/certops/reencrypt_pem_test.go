package certops

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func encryptedKeyPEM(t *testing.T, key interface{}, password string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := certlib.EncryptPKCS8(der, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: enc})
}

// TestReencryptPEM_WrongPasswordClearError verifies that reencrypting a PEM whose
// encrypted key cannot be decrypted (wrong password) fails with a clear
// wrong-password/decrypt error rather than the misleading "nil key" message.
func TestReencryptPEM_WrongPasswordClearError(t *testing.T) {
	dir := t.TempDir()
	key := mustGenECKey(t)

	keyPEM := encryptedKeyPEM(t, key, "correctpw")
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := Reencrypt(ReencryptOptions{
		InputPath:    path,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("wrongpw")}},
		NewPassword:  []byte("newpw"),
	})
	if err == nil {
		t.Fatal("expected reencrypt to fail with wrong password, got nil error")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "wrong password") && !strings.Contains(msg, "decrypt") {
		t.Errorf("error does not indicate wrong password / decrypt failure: %v", err)
	}
	if strings.Contains(msg, "nil key") {
		t.Errorf("error still reports misleading nil key message: %v", err)
	}
}

// TestReencryptPEM_PreservesUnknownBlocks verifies that non-key PEM blocks
// (certificates and unrecognized blocks like DH PARAMETERS / X509 CRL) survive
// the in-place reencrypt rewrite verbatim instead of being silently dropped.
func TestReencryptPEM_PreservesUnknownBlocks(t *testing.T) {
	dir := t.TempDir()
	caKey := mustGenECKey(t)
	caCert := mustMakeCA(t, caKey)
	leafKey := mustGenECKey(t)
	leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)

	var input []byte
	input = append(input, encryptedKeyPEM(t, leafKey, "correctpw")...)
	input = append(input, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})...)
	input = append(input, pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte("synthetic-dh-params")})...)
	input = append(input, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("synthetic-crl-bytes")})...)

	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "out.pem")
	_, err := Reencrypt(ReencryptOptions{
		InputPath:    path,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("correctpw")}},
		NewPassword:  []byte("newpw"),
		OutputPath:   outPath,
	})
	if err != nil {
		t.Fatalf("reencrypt failed: %v", err)
	}

	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)
	for _, header := range []string{
		"BEGIN ENCRYPTED PRIVATE KEY",
		"BEGIN CERTIFICATE",
		"BEGIN DH PARAMETERS",
		"BEGIN X509 CRL",
	} {
		if !strings.Contains(outStr, header) {
			t.Errorf("output is missing preserved block %q", header)
		}
	}

	// The re-encrypted key must be readable with the new password.
	c, err := certlib.ReadFile(outPath, []certlib.TaggedPassword{{Password: []byte("newpw")}})
	if err != nil {
		t.Fatal(err)
	}
	hasKey := false
	for _, it := range c.Items {
		if it.Type == certlib.ContentPrivateKey && it.PrivateKey != nil {
			hasKey = true
		}
	}
	if !hasKey {
		t.Error("re-encrypted key could not be read back with the new password")
	}
}

// TestReencryptPEM_NoKeyIsAnError verifies that a PEM file without a private
// key (a bare certificate) is refused instead of being copied and reported as
// "password changed" (harness 16.7).
func TestReencryptPEM_NoKeyIsAnError(t *testing.T) {
	dir := t.TempDir()
	cert := mustCert(t, "nokey.example")
	path := filepath.Join(dir, "cert.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.crt")

	_, err := Reencrypt(ReencryptOptions{
		InputPath:   path,
		OutputPath:  out,
		NewPassword: []byte("newpw"),
	})
	if err == nil {
		t.Fatal("expected reencrypt of a certificate-only PEM to fail, got nil error")
	}
	if !strings.Contains(err.Error(), "no private key") {
		t.Errorf("error does not say there is no private key: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Errorf("output file was written despite the error: %s", out)
	}
}
