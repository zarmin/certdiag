package certlib

import (
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestReadPKCS12CorrectPasswordSetsPassword(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	data, err := gopkcs12.Modern2023.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatalf("failed to encode PKCS#12: %v", err)
	}

	passwords := [][]byte{[]byte("wrong"), []byte("secret")}
	container, err := readPKCS12("bundle.p12", data, passwords, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(container.Items) == 0 {
		t.Fatal("expected decoded items with correct password")
	}
	if string(container.Password) != "secret" {
		t.Fatalf("expected container.Password %q, got %q", "secret", string(container.Password))
	}
}

func TestReadPKCS12WrongPasswordLeavesNoStalePassword(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	data, err := gopkcs12.Modern2023.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatalf("failed to encode PKCS#12: %v", err)
	}

	passwords := [][]byte{[]byte("wrong")}
	container, err := readPKCS12("bundle.p12", data, passwords, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(container.Items) != 0 {
		t.Fatalf("expected no decoded items with wrong password, got %d", len(container.Items))
	}
	if len(container.Password) != 0 {
		t.Fatalf("expected no stale password after failed decode, got %q", string(container.Password))
	}
}
