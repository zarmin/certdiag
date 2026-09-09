//go:build linux

package truststore

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeLinuxPEM(t *testing.T, path string, cas ...testCA) {
	t.Helper()
	var buf bytes.Buffer
	for _, ca := range cas {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadOSStore_SSLCertFileEnvWins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-ca.pem")
	writeLinuxPEM(t, path, newTestCA(t, "Env Root A"), newTestCA(t, "Env Root B"))

	t.Setenv("SSL_CERT_FILE", path)

	stores, err := ReadOSStore()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("expected exactly one store, got %d", len(stores))
	}
	if stores[0].Info.Name != "SSL_CERT_FILE" {
		t.Errorf("expected the env store to win, got %q", stores[0].Info.Name)
	}
	if len(stores[0].Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(stores[0].Certificates))
	}
}

func TestReadOSStore_SSLCertFileMissingErrors(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "nope.pem"))

	// An explicit but unreadable SSL_CERT_FILE must be reported, not silently
	// skipped in favour of a distro default.
	if _, err := ReadOSStore(); err == nil {
		t.Fatal("expected an error for a missing SSL_CERT_FILE")
	}
}

func TestDiscoverOSStores_SSLCertFileEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "discover-ca.pem")
	writeLinuxPEM(t, path, newTestCA(t, "Discover Root"))

	t.Setenv("SSL_CERT_FILE", path)

	stores := DiscoverOSStores()
	if len(stores) != 1 {
		t.Fatalf("expected one store, got %d", len(stores))
	}
	if stores[0].CertCount != 1 {
		t.Errorf("expected CertCount 1, got %d", stores[0].CertCount)
	}
}

func TestReadPEMFile_SkipsNonCertBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.pem")

	var buf bytes.Buffer
	ca := newTestCA(t, "Mixed Root")
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nope")}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	certs, err := readPEMFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestReadPEMDir_ManyFilesBecomeOneStore(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 25; i++ {
		writeLinuxPEM(t, filepath.Join(dir, string(rune('a'+i%26))+"-root.pem"), newTestCA(t, "Dir Root"))
	}

	certs, err := readPEMDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 25 {
		t.Errorf("expected 25 certificates from 25 files, got %d", len(certs))
	}
}

func TestReadPEMDir_SkipsNonCertFiles(t *testing.T) {
	dir := t.TempDir()
	writeLinuxPEM(t, filepath.Join(dir, "real.pem"), newTestCA(t, "Real Root"))

	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "abcd1234.0"), []byte("hash link"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	certs, err := readPEMDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("expected only the .pem file to be read, got %d certificates", len(certs))
	}
}

func TestReadPEMDir_MissingDir(t *testing.T) {
	if _, err := readPEMDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}
