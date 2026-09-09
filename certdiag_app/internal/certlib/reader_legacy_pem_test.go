package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeLegacyEncryptedPEM(t *testing.T, blockType string, der []byte, pass string) string {
	t.Helper()
	block, err := x509.EncryptPEMBlock(rand.Reader, blockType, der, []byte(pass), x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		t.Fatalf("EncryptPEMBlock: %v", err)
	}
	if block.Headers["Proc-Type"] != "4,ENCRYPTED" || block.Headers["DEK-Info"] == "" {
		t.Fatalf("expected legacy OpenSSL headers, got %v", block.Headers)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func tagged(pw string) []TaggedPassword {
	return []TaggedPassword{{Password: []byte(pw), Source: PasswordSourceCLI}}
}

func TestReadLegacyEncryptedRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	path := writeLegacyEncryptedPEM(t, "RSA PRIVATE KEY", der, "testpass")

	container, err := ReadFile(path, tagged("testpass"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(container.ParseErrors) != 0 {
		t.Fatalf("unexpected parse errors: %v", container.ParseErrors)
	}
	if len(container.Items) != 1 || container.Items[0].Type != ContentPrivateKey {
		t.Fatalf("expected one private key item, got %+v", container.Items)
	}
	if container.Items[0].PrivateKey == nil {
		t.Fatal("private key not decrypted")
	}
	if string(container.Password) != "testpass" {
		t.Fatalf("expected recorded password testpass, got %q", container.Password)
	}
}

func TestReadLegacyEncryptedECKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	path := writeLegacyEncryptedPEM(t, "EC PRIVATE KEY", der, "testpass")

	container, err := ReadFile(path, tagged("testpass"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(container.ParseErrors) != 0 {
		t.Fatalf("unexpected parse errors: %v", container.ParseErrors)
	}
	if len(container.Items) != 1 || container.Items[0].PrivateKey == nil {
		t.Fatalf("expected one decrypted private key item, got %+v", container.Items)
	}
}

func TestReadLegacyEncryptedRSAKeyWrongPassword(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	path := writeLegacyEncryptedPEM(t, "RSA PRIVATE KEY", der, "testpass")

	container, err := ReadFile(path, tagged("wrongpass"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(container.ParseErrors) == 0 {
		t.Fatal("expected a parse error for wrong password")
	}
	if len(container.Items) != 1 || container.Items[0].PrivateKey != nil {
		t.Fatalf("expected an encrypted, undecrypted key item, got %+v", container.Items)
	}
	if !container.Items[0].Encrypted {
		t.Fatal("expected item marked Encrypted")
	}
}
