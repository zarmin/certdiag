package certops

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/smallstep/pkcs7"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func writeExtractPEMFixture(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var items []certlib.CertItem
	for _, c := range certs {
		items = append(items, certlib.CertItem{Type: certlib.ContentCertificate, Certificate: c, RawBytes: c.Raw})
	}
	enc, err := certlib.EncodePEM(items)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	path := filepath.Join(t.TempDir(), "in.pem")
	if err := os.WriteFile(path, enc, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtract_ContainerFormatsEncodeProperly verifies that extracting with a
// container format writes real container bytes, not PEM under a container name.
func TestExtract_ContainerFormatsEncodeProperly(t *testing.T) {
	caKey, caCert := jksTestCA(t)
	_, leaf := jksTestLeaf(t, "extract-leaf", 42, caKey, caCert)
	inPath := writeExtractPEMFixture(t, leaf)

	const outPw = "outpw"

	t.Run("p12", func(t *testing.T) {
		outDir := t.TempDir()
		res, err := Extract(ExtractOptions{
			InputPath:      inPath,
			OutputDir:      outDir,
			OutputFormat:   certlib.FormatPKCS12,
			OutputPassword: []byte(outPw),
		})
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		data, err := os.ReadFile(res.ExtractedFiles[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "BEGIN") {
			t.Fatalf("p12 output looks like PEM, not PKCS#12:\n%s", data)
		}
		certs, err := pkcs12.DecodeTrustStore(data, outPw)
		if err != nil {
			t.Fatalf("DecodeTrustStore: %v", err)
		}
		if len(certs) != 1 || certs[0].Subject.CommonName != "extract-leaf" {
			t.Fatalf("unexpected PKCS#12 contents: %+v", certs)
		}
	})

	t.Run("jks", func(t *testing.T) {
		outDir := t.TempDir()
		res, err := Extract(ExtractOptions{
			InputPath:      inPath,
			OutputDir:      outDir,
			OutputFormat:   certlib.FormatJKS,
			OutputPassword: []byte(outPw),
		})
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		data, err := os.ReadFile(res.ExtractedFiles[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "BEGIN") {
			t.Fatalf("jks output looks like PEM, not JKS:\n%s", data)
		}
		ks := keystore.New()
		if err := ks.Load(strings.NewReader(string(data)), []byte(outPw)); err != nil {
			t.Fatalf("keystore.Load: %v", err)
		}
		if len(ks.Aliases()) == 0 {
			t.Fatal("JKS has no entries")
		}
	})

	t.Run("p7b", func(t *testing.T) {
		outDir := t.TempDir()
		res, err := Extract(ExtractOptions{
			InputPath:    inPath,
			OutputDir:    outDir,
			OutputFormat: certlib.FormatPKCS7,
		})
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		data, err := os.ReadFile(res.ExtractedFiles[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "BEGIN") {
			t.Fatalf("p7b output looks like PEM, not PKCS#7:\n%s", data)
		}
		p7, err := pkcs7.Parse(data)
		if err != nil {
			t.Fatalf("pkcs7.Parse: %v", err)
		}
		if len(p7.Certificates) != 1 || p7.Certificates[0].Subject.CommonName != "extract-leaf" {
			t.Fatalf("unexpected PKCS#7 contents: %+v", p7.Certificates)
		}
	})

	t.Run("pem", func(t *testing.T) {
		outDir := t.TempDir()
		res, err := Extract(ExtractOptions{
			InputPath:    inPath,
			OutputDir:    outDir,
			OutputFormat: certlib.FormatPEM,
		})
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		data, err := os.ReadFile(res.ExtractedFiles[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "BEGIN CERTIFICATE") {
			t.Fatalf("pem output not a PEM certificate:\n%s", data)
		}
	})

	t.Run("der", func(t *testing.T) {
		outDir := t.TempDir()
		res, err := Extract(ExtractOptions{
			InputPath:    inPath,
			OutputDir:    outDir,
			OutputFormat: certlib.FormatDER,
		})
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		data, err := os.ReadFile(res.ExtractedFiles[0].Path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x509.ParseCertificate(data); err != nil {
			t.Fatalf("der output not a DER certificate: %v", err)
		}
	})
}

// TestExtract_OutputFileRejectsMultipleMatches verifies that --output-file with
// more than one matching item errors instead of silently overwriting.
func TestExtract_OutputFileRejectsMultipleMatches(t *testing.T) {
	caKey, caCert := jksTestCA(t)
	_, leaf := jksTestLeaf(t, "leaf", 1, caKey, caCert)
	inPath := writeExtractPEMFixture(t, leaf, caCert)

	outFile := filepath.Join(t.TempDir(), "out.pem")
	_, err := Extract(ExtractOptions{
		InputPath:    inPath,
		OutputFile:   outFile,
		OutputFormat: certlib.FormatPEM,
	})
	if err == nil {
		t.Fatal("expected error for --output-file with multiple matches, got nil")
	}
	if !strings.Contains(err.Error(), "output-file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(outFile); statErr == nil {
		t.Fatal("no file should be written when multiple matches collide")
	}
}
