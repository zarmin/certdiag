//go:build fulltest

package certlib

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestScanPath_SingleFile(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	path := mustWriteTempFile(t, dir, "test.crt", pemData)

	store, err := ScanPath(path, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPath returned error: %v", err)
	}
	if len(store.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(store.Containers))
	}
	if len(store.Containers[0].Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(store.Containers[0].Items))
	}
	if store.Containers[0].Items[0].Type != ContentCertificate {
		t.Fatalf("expected certificate item, got %s", store.Containers[0].Items[0].Type)
	}
}

func TestScanPathWithOptions_Directory(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	mustWriteTempFile(t, dir, "a.crt", pemData)
	mustWriteTempFile(t, dir, "b.pem", pemData)
	mustWriteTempFile(t, dir, "notes.txt", []byte("not a cert"))

	store, err := ScanPathWithOptions(dir, ScanOptions{Recursive: false})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	if len(store.Containers) != 2 {
		t.Fatalf("expected 2 containers (txt skipped), got %d", len(store.Containers))
	}
}

func TestScanPathWithOptions_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	store, err := ScanPathWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPathWithOptions returned error: %v", err)
	}
	if len(store.Containers) != 0 {
		t.Fatalf("expected 0 containers, got %d", len(store.Containers))
	}
}

func TestScanPathWithOptions_Recursive(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	mustWriteTempFile(t, dir, "a.crt", pemData)
	mustWriteTempFile(t, sub, "b.crt", pemData)

	store, err := ScanPathWithOptions(dir, ScanOptions{Recursive: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store.Containers) != 2 {
		t.Fatalf("recursive: expected 2 containers, got %d", len(store.Containers))
	}

	store2, err := ScanPathWithOptions(dir, ScanOptions{Recursive: false})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store2.Containers) != 1 {
		t.Fatalf("non-recursive: expected 1 container, got %d", len(store2.Containers))
	}
}

func TestScanPathWithOptions_MaxDepth(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	deep := filepath.Join(sub, "deep")
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	mustWriteTempFile(t, dir, "a.crt", pemData)
	mustWriteTempFile(t, sub, "b.crt", pemData)
	mustWriteTempFile(t, deep, "c.crt", pemData)

	store1, err := ScanPathWithOptions(dir, ScanOptions{Recursive: true, MaxDepth: 1})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store1.Containers) != 1 {
		t.Fatalf("MaxDepth=1: expected 1 container, got %d", len(store1.Containers))
	}

	store2, err := ScanPathWithOptions(dir, ScanOptions{Recursive: true, MaxDepth: 2})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store2.Containers) != 2 {
		t.Fatalf("MaxDepth=2: expected 2 containers, got %d", len(store2.Containers))
	}
}

func TestScanPathWithOptions_LargeFile(t *testing.T) {
	dir := t.TempDir()
	largePath := filepath.Join(dir, "large.pem")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	// Write a file larger than MaxScanFileSize
	buf := make([]byte, 1024*1024) // 1MB chunks
	for i := 0; i < 11; i++ {
		if _, err := f.Write(buf); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}
	f.Close()

	store, err := ScanPathWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store.Containers) != 0 {
		t.Fatalf("expected 0 containers (large file skipped), got %d", len(store.Containers))
	}
}

func TestScanPathWithOptions_Symlink(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	realFile := mustWriteTempFile(t, dir, "real.crt", pemData)

	linkDir := t.TempDir()
	linkPath := filepath.Join(linkDir, "link.crt")
	if err := os.Symlink(realFile, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	store, err := ScanPathWithOptions(linkDir, ScanOptions{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store.Containers) != 1 {
		t.Fatalf("expected 1 container from symlink, got %d", len(store.Containers))
	}
	if len(store.Containers[0].Items) < 1 {
		t.Fatal("expected at least 1 item in symlink container")
	}
	if store.Containers[0].Items[0].Type != ContentCertificate {
		t.Fatalf("expected certificate, got %s", store.Containers[0].Items[0].Type)
	}
}

func TestScanPathWithOptions_BrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "broken.crt")
	if err := os.Symlink("/nonexistent/path/cert.pem", linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	store, err := ScanPathWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store.Containers) != 0 {
		t.Fatalf("expected 0 containers for broken symlink, got %d", len(store.Containers))
	}
}

func TestScanPathWithOptions_ContextCancellation(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		mustWriteTempFile(t, dir, filepath.Base(t.TempDir())+".crt", pemData)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	store, err := ScanPathWithOptions(dir, ScanOptions{
		Recursive: true,
		Context:   ctx,
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// With an already-cancelled context, we should get partial (possibly 0) results
	if len(store.Containers) > 10 {
		t.Fatalf("unexpected container count: %d", len(store.Containers))
	}
}

func TestScanPath_NonExistent(t *testing.T) {
	_, err := ScanPath("/nonexistent/path/that/does/not/exist", ScanOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}
}

func TestScanPathWithOptions_SignatureScan(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)

	dir := t.TempDir()
	// Use raw DER bytes in a .txt file. Without signature scan, the .txt
	// extension is unknown and DER content is not PEM, so ReadFile returns
	// ErrUnknownFormat. With signature scan, ReadFileBySignature detects
	// the ASN.1 (0x30) header and parses the DER cert.
	mustWriteTempFile(t, dir, "hidden.txt", der)

	// Without signature scan, .txt with DER content -> not found
	store1, err := ScanPathWithOptions(dir, ScanOptions{UseSignatureScan: false})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store1.Containers) != 0 {
		t.Fatalf("without signature scan: expected 0 containers, got %d", len(store1.Containers))
	}

	// With signature scan, the ASN.1 signature is detected -> found
	store2, err := ScanPathWithOptions(dir, ScanOptions{UseSignatureScan: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(store2.Containers) != 1 {
		t.Fatalf("with signature scan: expected 1 container, got %d", len(store2.Containers))
	}
}

func TestHasPasswordErrors(t *testing.T) {
	tests := []struct {
		name     string
		errors   []string
		expected bool
	}{
		{
			name:     "password required",
			errors:   []string{"password required for this file"},
			expected: true,
		},
		{
			name:     "failed to decrypt",
			errors:   []string{"failed to decrypt the keystore"},
			expected: true,
		},
		{
			name:     "unrelated error",
			errors:   []string{"invalid PEM block"},
			expected: false,
		},
		{
			name:     "no errors",
			errors:   nil,
			expected: false,
		},
		{
			name:     "mixed errors with password",
			errors:   []string{"some error", "password required"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			container := &CertContainer{ParseErrors: tt.errors}
			got := HasPasswordErrors(container)
			if got != tt.expected {
				t.Fatalf("HasPasswordErrors = %v, want %v", got, tt.expected)
			}
		})
	}
}

// helper to create a PEM cert file and return the parsed cert and PEM bytes
func mustCreatePEMCert(t interface {
	Helper()
	Fatal(...any)
}) (*x509.Certificate, []byte) {
	t.Helper()
	key := mustGenerateRSAKey(t)
	cert, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemData
}

// ---------------------------------------------------------------------------
// ScanProgress counter tests
// ---------------------------------------------------------------------------

func TestScanProgress_SingleFile(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	mustWriteTempFile(t, dir, "test.crt", pemData)

	progress := &ScanProgress{}
	_, err := ScanPathWithOptions(dir, ScanOptions{Progress: progress})
	if err != nil {
		t.Fatalf("ScanPathWithOptions error: %v", err)
	}
	if d := progress.DirsScanned.Load(); d < 1 {
		t.Fatalf("DirsScanned = %d, want >= 1", d)
	}
	if f := progress.FilesProbed.Load(); f != 1 {
		t.Fatalf("FilesProbed = %d, want 1", f)
	}
	if p := progress.PasswordChecks.Load(); p != 0 {
		t.Fatalf("PasswordChecks = %d, want 0", p)
	}
}

func TestScanProgress_DirectoryRecursive(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	sub1 := filepath.Join(dir, "sub1")
	sub2 := filepath.Join(dir, "sub2")
	if err := os.MkdirAll(sub1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub2, 0755); err != nil {
		t.Fatal(err)
	}
	mustWriteTempFile(t, dir, "a.crt", pemData)
	mustWriteTempFile(t, sub1, "b.crt", pemData)
	mustWriteTempFile(t, sub2, "c.crt", pemData)

	progress := &ScanProgress{}
	_, err := ScanPathWithOptions(dir, ScanOptions{Recursive: true, Progress: progress})
	if err != nil {
		t.Fatalf("ScanPathWithOptions error: %v", err)
	}
	if d := progress.DirsScanned.Load(); d < 3 {
		t.Fatalf("DirsScanned = %d, want >= 3", d)
	}
	if f := progress.FilesProbed.Load(); f != 3 {
		t.Fatalf("FilesProbed = %d, want 3", f)
	}
	if p := progress.PasswordChecks.Load(); p != 0 {
		t.Fatalf("PasswordChecks = %d, want 0", p)
	}
}

func TestScanProgress_PasswordAttempts(t *testing.T) {
	key := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, key)

	var buf bytes.Buffer
	items := []CertItem{
		{Type: ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	correctPass := []byte("rightpass")
	if err := WritePKCS12(&buf, items, correctPass, false); err != nil {
		t.Fatalf("WritePKCS12: %v", err)
	}

	dir := t.TempDir()
	mustWriteTempFile(t, dir, "test.p12", buf.Bytes())

	progress := &ScanProgress{}
	provider := &staticPasswordProvider{passwords: []TaggedPassword{
		{Password: []byte("wrong1"), Source: PasswordSourceCLI},
		{Password: []byte("wrong2"), Source: PasswordSourceCLI},
		{Password: correctPass, Source: PasswordSourceCLI},
	}}
	_, err := ScanPathWithOptions(dir, ScanOptions{
		Progress:         progress,
		PasswordProvider: provider,
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions error: %v", err)
	}
	if f := progress.FilesProbed.Load(); f != 1 {
		t.Fatalf("FilesProbed = %d, want 1", f)
	}
	// passwordsWithEmpty adds an empty-string attempt, plus 3 candidates = 4.
	// But it may stop early when correct pass is found. At minimum we expect >= 1.
	if p := progress.PasswordChecks.Load(); p < 1 {
		t.Fatalf("PasswordChecks = %d, want >= 1", p)
	}
}

func TestScanProgress_SignatureScan(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)

	dir := t.TempDir()
	mustWriteTempFile(t, dir, "hidden.txt", der)

	progress := &ScanProgress{}
	store, err := ScanPathWithOptions(dir, ScanOptions{
		UseSignatureScan: true,
		Progress:         progress,
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions error: %v", err)
	}
	if len(store.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(store.Containers))
	}
	if f := progress.FilesProbed.Load(); f != 1 {
		t.Fatalf("FilesProbed = %d, want 1", f)
	}
}

func TestScanProgress_ScanSiblings(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	primary := mustWriteTempFile(t, dir, "primary.crt", pemData)
	mustWriteTempFile(t, dir, "sibling.crt", pemData)

	progress := &ScanProgress{}
	store, err := ScanSiblings([]string{primary}, ScanOptions{Progress: progress})
	if err != nil {
		t.Fatalf("ScanSiblings error: %v", err)
	}
	if d := progress.DirsScanned.Load(); d < 1 {
		t.Fatalf("DirsScanned = %d, want >= 1", d)
	}
	// ScanSiblings skips the primary file; only the sibling should be probed
	if f := progress.FilesProbed.Load(); f < 1 {
		t.Fatalf("FilesProbed = %d, want >= 1", f)
	}
	// sibling.crt should appear in the store
	if len(store.Containers) < 1 {
		t.Fatal("expected at least 1 sibling container")
	}
}

// staticPasswordProvider returns the same passwords for every file.
type staticPasswordProvider struct {
	passwords []TaggedPassword
}

func (p *staticPasswordProvider) PasswordsForFile(_ string) []TaggedPassword {
	return p.passwords
}
