package certlib

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// TestBuiltInPassword_OpensCacerts: a JDK-style cacerts (no extension, locked
// with "changeit") opens through the built-in default and says so.
func TestBuiltInPassword_OpensCacerts(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	data, err := EncodeJKS([]CertItem{{Type: ContentCertificate, Certificate: caCert}}, truststore.DefaultKeystorePassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := mustWriteTempFile(t, t.TempDir(), "cacerts", data)

	if c, err := ReadFile(path, nil); err == nil && !HasPasswordErrors(c) && len(c.Items) > 0 {
		t.Fatal("the reader itself must not guess: the provider owns the password list")
	}

	c, err := ReadFile(path, BuiltInPasswords())
	if err != nil {
		t.Fatalf("read with built-in password: %v", err)
	}
	if HasPasswordErrors(c) || len(c.Items) != 1 {
		t.Fatalf("expected one certificate, got %d items, errors %v", len(c.Items), c.ParseErrors)
	}
	if len(c.UnlockSources) != 1 || c.UnlockSources[0] != PasswordSourceBuiltIn {
		t.Errorf("unlock sources %v, want [%s]", c.UnlockSources, PasswordSourceBuiltIn)
	}
}

// TestBuiltInPassword_OpensPKCS12: the same default applies to a .p12 keystore.
func TestBuiltInPassword_OpensPKCS12(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	data, err := EncodePKCS12([]CertItem{{Type: ContentCertificate, Certificate: caCert}}, truststore.DefaultKeystorePassword, false)
	if err != nil {
		t.Fatal(err)
	}
	path := mustWriteTempFile(t, t.TempDir(), "store.p12", data)
	c, err := ReadFile(path, BuiltInPasswords())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if HasPasswordErrors(c) || len(c.UnlockSources) != 1 || c.UnlockSources[0] != PasswordSourceBuiltIn {
		t.Errorf("errors %v, unlock sources %v", c.ParseErrors, c.UnlockSources)
	}
}
