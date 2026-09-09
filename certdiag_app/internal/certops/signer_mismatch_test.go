package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func writeCSRFile(t *testing.T, dir, name string, key *rsa.PrivateKey, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSignCSR_RejectsMismatchedSignerKey(t *testing.T) {
	dir := t.TempDir()

	_, caCert := jksTestCA(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrPath := writeCSRFile(t, dir, "req.csr", leafKey, "leaf")
	caCertPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	wrongKeyPath := writePEMFile(t, dir, "wrong.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: wrongKey}})

	_, err = SignCSR(SignCSROptions{
		CSRPath:      csrPath,
		CACertPath:   caCertPath,
		CAKeyPath:    wrongKeyPath,
		Days:         30,
		OutputFormat: certlib.FormatPEM,
	})
	if err == nil {
		t.Fatal("expected mismatch error, got nil (broken cert would have been produced)")
	}
	if !strings.Contains(err.Error(), "signer key does not match signer certificate") {
		t.Fatalf("expected signer mismatch error, got: %v", err)
	}
}

func TestSignCSR_AcceptsMatchingSignerKey(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert := jksTestCA(t)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrPath := writeCSRFile(t, dir, "req.csr", leafKey, "leaf")
	caCertPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	caKeyPath := writePEMFile(t, dir, "ca.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: caKey}})

	res, err := SignCSR(SignCSROptions{
		CSRPath:      csrPath,
		CACertPath:   caCertPath,
		CAKeyPath:    caKeyPath,
		Days:         30,
		OutputFormat: certlib.FormatPEM,
	})
	if err != nil {
		t.Fatalf("expected signing to succeed, got: %v", err)
	}
	if len(res.CertBytes) == 0 {
		t.Fatal("expected a signed certificate")
	}
}

func TestCreateCert_RejectsMismatchedSignerKey(t *testing.T) {
	dir := t.TempDir()

	_, caCert := jksTestCA(t)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caCertPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	wrongKeyPath := writePEMFile(t, dir, "wrong.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: wrongKey}})

	_, err = CreateCert(CreateCertOptions{
		Subject:        pkix.Name{CommonName: "leaf"},
		WithKey:        true,
		KeyOptions:     certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048},
		SignerCertPath: caCertPath,
		SignerKeyPath:  wrongKeyPath,
		Days:           30,
		OutputFormat:   certlib.FormatPEM,
	})
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "signer key does not match signer certificate") {
		t.Fatalf("expected signer mismatch error, got: %v", err)
	}
}

func TestRenew_RejectsMismatchedSignerKey(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert := jksTestCA(t)
	leafKey, leafCert := jksTestLeaf(t, "leaf", 42, caKey, caCert)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	certPath := writePEMFile(t, dir, "leaf.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: leafCert, RawBytes: leafCert.Raw}})
	keyPath := writePEMFile(t, dir, "leaf.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: leafKey}})
	caCertPath := writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	wrongKeyPath := writePEMFile(t, dir, "wrong.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: wrongKey}})

	_, err = Renew(RenewOptions{
		CertPath:       certPath,
		KeyFilePath:    keyPath,
		SignerCertPath: caCertPath,
		SignerKeyPath:  wrongKeyPath,
		Days:           30,
		OutputFormat:   certlib.FormatPEM,
	})
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "signer key does not match signer certificate") {
		t.Fatalf("expected signer mismatch error, got: %v", err)
	}
}
