package truststore

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writePEMBundle(t *testing.T, path string, cas ...testCA) {
	t.Helper()
	var buf bytes.Buffer
	for _, ca := range cas {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadOpenSSLPEM_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	writePEMBundle(t, path, newTestCA(t, "Root A"), newTestCA(t, "Root B"), newTestCA(t, "Root C"))

	certs, err := readOpenSSLPEM(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 3 {
		t.Fatalf("expected 3 certificates, got %d", len(certs))
	}
}

func TestReadOpenSSLPEM_SkipsNonCertBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.pem")

	var buf bytes.Buffer
	ca := newTestCA(t, "Mixed Root")
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key really")}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := readOpenSSLPEM(path)
	if err != nil {
		t.Fatalf("a key block must not be fatal: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected only the certificate, got %d", len(certs))
	}
}

func TestReadOpenSSLPEM_TrailingGarbageTolerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trailing.pem")

	var buf bytes.Buffer
	ca := newTestCA(t, "Trailing Root")
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("\nthis is not PEM at all\n")

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := readOpenSSLPEM(path)
	if err != nil {
		t.Fatalf("trailing junk must not be fatal: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestReadOpenSSLPEM_UnparseableCertSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage der")}); err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, "Good Root")
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := readOpenSSLPEM(path)
	if err != nil {
		t.Fatalf("a corrupt block must not abort the read: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected the good certificate only, got %d", len(certs))
	}
}

func TestReadOpenSSLPEM_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := readOpenSSLPEM(path)
	if err != nil {
		t.Fatalf("an empty file must not error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected no certificates, got %d", len(certs))
	}
}

func TestReadOpenSSLPEM_MissingFile(t *testing.T) {
	_, err := readOpenSSLPEM(filepath.Join(t.TempDir(), "nope.pem"))
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
