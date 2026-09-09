package certlib

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestScanSiblings_SkipsOversizedFile(t *testing.T) {
	key := mustGenerateRSAKey(t)
	_, der := mustCreateSelfSignedCA(t, key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	primary := mustWriteTempFile(t, dir, "primary.crt", pemData)
	mustWriteTempFile(t, dir, "sibling.crt", pemData)

	hugePath := filepath.Join(dir, "huge.pem")
	if f, err := os.Create(hugePath); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	if err := os.Truncate(hugePath, MaxScanFileSize+1); err != nil {
		t.Fatal(err)
	}

	store, err := ScanSiblings([]string{primary}, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanSiblings error: %v", err)
	}

	for _, c := range store.Containers {
		if filepath.Base(c.FilePath) == "huge.pem" {
			t.Fatalf("oversized sibling was scanned, expected it to be skipped")
		}
	}

	found := false
	for _, c := range store.Containers {
		if filepath.Base(c.FilePath) == "sibling.crt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("small sibling was not scanned; cap is not selective")
	}
}
