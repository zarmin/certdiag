package certops

import (
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestConvertJKS_NonASCIIPasswordWarning verifies the keytool-interop warning for
// the low_jks_utf16_password bug: certdiag passes JKS passwords as raw UTF-8 to
// keystore-go (not keytool's UTF-16BE), so a non-ASCII password must produce a
// non-fatal warning, while ASCII passwords must not. The store must still read
// back within certdiag (the password is warned, not rejected).
func TestConvertJKS_NonASCIIPasswordWarning(t *testing.T) {
	dir := t.TempDir()
	caKey, caCert := jksTestCA(t)
	leafKey, leafCert := jksTestLeaf(t, "jks-pw-leaf", 7, caKey, caCert)

	pemPath := writePEMFile(t, dir, "in.pem", []certlib.CertItem{
		{Type: certlib.ContentPrivateKey, PrivateKey: leafKey},
		{Type: certlib.ContentCertificate, Certificate: leafCert, RawBytes: leafCert.Raw},
	})

	hasWarning := func(ws []string) bool {
		for _, w := range ws {
			if w == certlib.NonASCIIJKSPasswordWarning {
				return true
			}
		}
		return false
	}

	nonASCIIPass := []byte("pä55wörd")
	outNonASCII := filepath.Join(dir, "nonascii.jks")
	res, err := Convert(ConvertOptions{
		InputPath:      pemPath,
		OutputPath:     outNonASCII,
		OutputFormat:   certlib.FormatJKS,
		OutputPassword: nonASCIIPass,
	})
	if err != nil {
		t.Fatalf("Convert (non-ASCII): %v", err)
	}
	if !hasWarning(res.Warnings) {
		t.Errorf("non-ASCII JKS password: expected warning, got %v", res.Warnings)
	}

	outASCII := filepath.Join(dir, "ascii.jks")
	res, err = Convert(ConvertOptions{
		InputPath:      pemPath,
		OutputPath:     outASCII,
		OutputFormat:   certlib.FormatJKS,
		OutputPassword: []byte("pass55word"),
	})
	if err != nil {
		t.Fatalf("Convert (ASCII): %v", err)
	}
	if hasWarning(res.Warnings) {
		t.Errorf("ASCII JKS password: expected no warning, got %v", res.Warnings)
	}

	// Round-trip: the non-ASCII-password JKS still reads back within certdiag.
	container, err := certlib.ReadFile(outNonASCII, []certlib.TaggedPassword{{Password: nonASCIIPass}})
	if err != nil {
		t.Fatalf("ReadFile non-ASCII JKS: %v", err)
	}
	var keys, certs int
	for _, it := range container.Items {
		switch it.Type {
		case certlib.ContentPrivateKey:
			if it.PrivateKey != nil {
				keys++
			}
		case certlib.ContentCertificate:
			certs++
		}
	}
	if keys != 1 || certs < 1 {
		t.Errorf("round-trip: expected 1 key and >=1 cert, got keys=%d certs=%d", keys, certs)
	}
}
