package certlib

import (
	"os"
	"path/filepath"
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func writeLockedPKCS12(t *testing.T, password string) (string, []byte) {
	t.Helper()
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	data, err := gopkcs12.Modern2023.Encode(key, cert, nil, password)
	if err != nil {
		t.Fatalf("failed to encode PKCS#12: %v", err)
	}

	path := filepath.Join(t.TempDir(), "locked.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path, data
}

func TestSignatureScanLockedPKCS12WithoutPassword(t *testing.T) {
	path, data := writeLockedPKCS12(t, "secret")

	container, err := ReadFileBySignature(path, data, nil)
	if err != nil {
		t.Fatalf("locked PKCS#12 was dropped by signature scan: %v", err)
	}
	if container.Format != FormatPKCS12 {
		t.Fatalf("expected format %q, got %q", FormatPKCS12, container.Format)
	}
	if !HasPasswordErrors(container) {
		t.Fatalf("expected locked PKCS#12 to report a password error, got: %v", container.ParseErrors)
	}
	if len(container.Items) != 0 {
		t.Fatalf("expected no decoded items without password, got %d", len(container.Items))
	}
}

func TestSignatureScanLockedPKCS12WithPassword(t *testing.T) {
	path, data := writeLockedPKCS12(t, "secret")

	passwords := []TaggedPassword{{Password: []byte("secret"), Source: PasswordSourceCLI}}
	container, err := ReadFileBySignature(path, data, passwords)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if container.Format != FormatPKCS12 {
		t.Fatalf("expected format %q, got %q", FormatPKCS12, container.Format)
	}
	if HasPasswordErrors(container) {
		t.Fatalf("did not expect password errors with correct password: %v", container.ParseErrors)
	}
	if len(container.Items) == 0 {
		t.Fatal("expected decoded items with correct password")
	}
}

func TestSignatureScanDERCertNotMisclassifiedAsLockedP12(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, der := mustCreateSelfSignedCA(t, key)
	_ = cert

	container, err := ReadFileBySignature("cert.der", der, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if container.Format != FormatDER {
		t.Fatalf("expected DER cert to stay format %q, got %q", FormatDER, container.Format)
	}
	if HasPasswordErrors(container) {
		t.Fatalf("plain DER cert must not be flagged as locked: %v", container.ParseErrors)
	}
	if len(container.Items) != 1 {
		t.Fatalf("expected exactly one cert item, got %d", len(container.Items))
	}
}
