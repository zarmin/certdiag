package certops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeTestCerts(t *testing.T) []*x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serial2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	leaf := &x509.Certificate{
		SerialNumber: serial1,
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	ca := &x509.Certificate{
		SerialNumber:          serial2,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	caCert, _ := x509.ParseCertificate(caDER)

	return []*x509.Certificate{leafCert, caCert}
}

func TestShouldSave(t *testing.T) {
	tests := []struct {
		name string
		opts SaveRemoteOptions
		want bool
	}{
		{"no save", SaveRemoteOptions{}, false},
		{"save-chain", SaveRemoteOptions{SaveChain: true}, true},
		{"save-leaf", SaveRemoteOptions{SaveLeaf: true}, true},
		{"save-all", SaveRemoteOptions{SaveAll: true}, true},
		{"save-to", SaveRemoteOptions{SaveTo: "out.pem"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.ShouldSave(); got != tt.want {
				t.Errorf("ShouldSave() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveRemoteCertsChain(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()

	result, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveChain: true,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("SaveRemoteCerts error: %v", err)
	}

	if len(result.SavedFiles) != 1 {
		t.Fatalf("expected 1 saved file, got %d", len(result.SavedFiles))
	}

	path := result.SavedFiles[0]
	if !strings.HasSuffix(path, "_chain.pem") {
		t.Errorf("filename should end with _chain.pem, got %s", filepath.Base(path))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading saved file: %v", err)
	}
	if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
		t.Error("saved file should contain PEM certificate")
	}
}

func TestSaveRemoteCertsLeaf(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()

	result, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveLeaf:  true,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("SaveRemoteCerts error: %v", err)
	}

	if len(result.SavedFiles) != 1 {
		t.Fatalf("expected 1 saved file, got %d", len(result.SavedFiles))
	}

	if !strings.HasSuffix(result.SavedFiles[0], "_leaf.pem") {
		t.Errorf("filename should end with _leaf.pem")
	}
}

func TestSaveRemoteCertsAll(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()

	result, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveAll:   true,
		OutputDir: dir,
	})
	if err != nil {
		t.Fatalf("SaveRemoteCerts error: %v", err)
	}

	if len(result.SavedFiles) != 2 {
		t.Fatalf("expected 2 saved files, got %d", len(result.SavedFiles))
	}

	for _, path := range result.SavedFiles {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file %s does not exist", path)
		}
	}
}

func TestSaveRemoteCertsSaveTo(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "chain.pem")

	result, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveTo: outPath,
	})
	if err != nil {
		t.Fatalf("SaveRemoteCerts error: %v", err)
	}

	if len(result.SavedFiles) != 1 {
		t.Fatalf("expected 1 saved file, got %d", len(result.SavedFiles))
	}
	if result.SavedFiles[0] != outPath {
		t.Errorf("expected %s, got %s", outPath, result.SavedFiles[0])
	}
}

func TestSaveRemoteCertsNoOverwrite(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()

	// Create file first
	outPath := filepath.Join(dir, "example.com_443_chain.pem")
	os.WriteFile(outPath, []byte("existing"), 0600)

	_, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveChain: true,
		OutputDir: dir,
		Overwrite: false,
	})
	if err == nil {
		t.Fatal("expected error when overwrite=false and file exists")
	}
}

func TestSaveRemoteCertsOverwrite(t *testing.T) {
	certs := makeTestCerts(t)
	dir := t.TempDir()

	// Create file first
	outPath := filepath.Join(dir, "example.com_443_chain.pem")
	os.WriteFile(outPath, []byte("existing"), 0600)

	_, err := SaveRemoteCerts("example.com_443", certs, SaveRemoteOptions{
		SaveChain: true,
		OutputDir: dir,
		Overwrite: true,
	})
	if err != nil {
		t.Fatalf("SaveRemoteCerts error: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) == "existing" {
		t.Error("file should have been overwritten")
	}
}

func TestNoCerts(t *testing.T) {
	_, err := SaveRemoteCerts("target", nil, SaveRemoteOptions{SaveChain: true})
	if err == nil {
		t.Error("expected error for no certs")
	}
}
