package certops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestExtract_KeyOnlyStaysKeyOnly verifies the fix: extracting the private key
// from a JKS whose PrivateKeyEntry carries an issuer chain produces a key-only
// PEM file. Before the fix WritePEM expanded the key's Chain and the "keys"
// extract gained intermediate/root CERTIFICATE blocks.
func TestExtract_KeyOnlyStaysKeyOnly(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := jksTestCA(t)
	leafKey, leafCert := jksTestLeaf(t, "leaf", 7, caKey, caCert)

	items := []certlib.CertItem{
		{Type: certlib.ContentPrivateKey, Alias: "k", PrivateKey: leafKey, EntryPassword: []byte("pw")},
		{Type: certlib.ContentCertificate, Alias: "leaf", Certificate: leafCert, RawBytes: leafCert.Raw},
		{Type: certlib.ContentCertificate, Alias: "root", Certificate: caCert, RawBytes: caCert.Raw},
	}
	enc, err := certlib.EncodeJKS(items, []byte("pw"), map[int]string{0: "k", 1: "leaf", 2: "root"})
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	jksPath := filepath.Join(dir, "store.jks")
	if err := os.WriteFile(jksPath, enc, 0600); err != nil {
		t.Fatal(err)
	}

	// Sanity: the read key item really does carry a chain (else the test proves
	// nothing).
	c, err := certlib.ReadFile(jksPath, []certlib.TaggedPassword{{Password: []byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	carriesChain := false
	for _, it := range c.Items {
		if it.Type == certlib.ContentPrivateKey && len(it.Chain) > 0 {
			carriesChain = true
		}
	}
	if !carriesChain {
		t.Fatal("precondition: read key item does not carry a chain")
	}

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		InputPath:      jksPath,
		InputPasswords: []certlib.TaggedPassword{{Password: []byte("pw")}},
		OutputDir:      outDir,
		OutputFormat:   certlib.FormatPEM,
		TypeFilter:     "keys",
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(res.ExtractedFiles) != 1 {
		t.Fatalf("expected exactly 1 extracted key file, got %d", len(res.ExtractedFiles))
	}

	data, err := os.ReadFile(res.ExtractedFiles[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "PRIVATE KEY") {
		t.Error("extracted key file has no PRIVATE KEY block")
	}
	if strings.Contains(string(data), "CERTIFICATE") {
		t.Errorf("key-only extract leaked CERTIFICATE blocks:\n%s", data)
	}
}
