package certops

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestConvert(t *testing.T) {
	t.Run("PKCS7NoKeys", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		// Create a PKCS7 file (certs only)
		p7Data, err := certlib.EncodePKCS7([]certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		if err != nil {
			t.Fatal(err)
		}
		p7Path := filepath.Join(dir, "input.p7b")
		if err := os.WriteFile(p7Path, p7Data, 0600); err != nil {
			t.Fatal(err)
		}

		outPath := filepath.Join(dir, "output.p12")
		result, err := Convert(ConvertOptions{
			InputPath:      p7Path,
			OutputPath:     outPath,
			OutputFormat:   certlib.FormatPKCS12,
			OutputPassword: []byte("test"),
			Overwrite:      true,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Should warn about no private keys
		hasWarning := false
		for _, w := range result.Warnings {
			if strings.Contains(strings.ToLower(w), "no private key") || strings.Contains(strings.ToLower(w), "trust store") {
				hasWarning = true
				break
			}
		}
		if !hasWarning {
			t.Errorf("expected warning about no keys, got warnings: %v", result.Warnings)
		}
	})

	t.Run("DERMultiItem", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)
		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)

		// Create multi-cert PEM
		pemData, err := certlib.EncodePEM([]certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		if err != nil {
			t.Fatal(err)
		}
		pemPath := filepath.Join(dir, "multi.pem")
		if err := os.WriteFile(pemPath, pemData, 0600); err != nil {
			t.Fatal(err)
		}

		outPath := filepath.Join(dir, "output.der")
		_, err = Convert(ConvertOptions{
			InputPath:    pemPath,
			OutputPath:   outPath,
			OutputFormat: certlib.FormatDER,
			Overwrite:    true,
		})
		if err == nil {
			t.Fatal("expected error converting multi-cert PEM to DER")
		}
		if !strings.Contains(err.Error(), "DER format supports only one item") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestBundle(t *testing.T) {
	t.Run("AutoChain", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		interKey := mustGenECKey(t)
		interCert, _, err := certlib.CreateSignedCert(interKey, certlib.CertGenOptions{
			Subject:    pkix.Name{CommonName: "Intermediate"},
			Days:       3650,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign,
			PathLength: 0,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		leafKey := mustGenECKey(t)
		leafCert, _, err := certlib.CreateSignedCert(leafKey, certlib.CertGenOptions{
			Subject:    pkix.Name{CommonName: "Leaf"},
			Days:       365,
			SignerCert: interCert,
			SignerKey:  interKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Write in wrong order: ca, leaf, inter
		f1 := writePEMFile(t, dir, "ca.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})
		f2 := writePEMFile(t, dir, "leaf.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
		})
		f3 := writePEMFile(t, dir, "inter.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: interCert},
		})

		outPath := filepath.Join(dir, "bundle.pem")
		result, err := Bundle(BundleOptions{
			InputPaths:   []string{f1, f2, f3},
			AutoChain:    true,
			IncludeRoot:  true,
			OutputPath:   outPath,
			OutputFormat: certlib.FormatPEM,
			Overwrite:    true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// ChainOrder should have leaf first
		if len(result.ChainOrder) == 0 {
			t.Fatal("expected non-empty ChainOrder")
		}
		if result.ChainOrder[0] != "Leaf" {
			t.Errorf("ChainOrder[0] = %q, want %q", result.ChainOrder[0], "Leaf")
		}
	})
}

func TestRenew(t *testing.T) {
	t.Run("PreservesSubject", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		// Write cert+key as PEM
		certPath := writePEMFile(t, dir, "cert.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})

		outCert := filepath.Join(dir, "renewed.pem")
		result, err := Renew(RenewOptions{
			CertPath:       certPath,
			CertOutputPath: outCert,
			OutputFormat:   certlib.FormatPEM,
			Overwrite:      true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(result.Subject, "Test CA") {
			t.Errorf("subject = %q, expected to contain %q", result.Subject, "Test CA")
		}
		if result.SerialHex == "" {
			t.Error("expected non-empty serial")
		}
	})

	t.Run("NewKeyDifferent", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		certPath := writePEMFile(t, dir, "cert.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: caCert},
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})

		outCert := filepath.Join(dir, "renewed.pem")
		outKey := filepath.Join(dir, "renewed.key")
		result, err := Renew(RenewOptions{
			CertPath:       certPath,
			NewKey:         true,
			KeyOptions:     certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
			CertOutputPath: outCert,
			KeyOutputPath:  outKey,
			OutputFormat:   certlib.FormatPEM,
			Overwrite:      true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.KeyReused {
			t.Error("expected KeyReused = false for new key")
		}

		// Read original and new key, verify they differ
		origKeyData, err := certlib.EncodePEM([]certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
		})
		if err != nil {
			t.Fatal(err)
		}
		newKeyData, err := os.ReadFile(outKey)
		if err != nil {
			t.Fatal(err)
		}
		if string(origKeyData) == string(newKeyData) {
			t.Error("new key should differ from original")
		}
	})
}

func TestReencrypt(t *testing.T) {
	t.Run("P12", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		oldPw := []byte("oldpass")
		newPw := []byte("newpass")

		p12Data, err := certlib.EncodePKCS12([]certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: caKey},
			{Type: certlib.ContentCertificate, Certificate: caCert},
		}, oldPw, false)
		if err != nil {
			t.Fatal(err)
		}
		p12Path := filepath.Join(dir, "test.p12")
		if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
			t.Fatal(err)
		}

		outPath := filepath.Join(dir, "changed.p12")
		_, err = Reencrypt(ReencryptOptions{
			InputPath:    p12Path,
			OldPasswords: []certlib.TaggedPassword{{Password: oldPw, Source: certlib.PasswordSourceCLI}},
			NewPassword:  newPw,
			OutputPath:   outPath,
			Overwrite:    true,
		})
		if err != nil {
			t.Fatal(err)
		}

		// Verify readback with new password
		container, err := certlib.ReadFile(outPath, []certlib.TaggedPassword{
			{Password: newPw, Source: certlib.PasswordSourceCLI},
		})
		if err != nil {
			t.Fatalf("readback with new password failed: %v", err)
		}
		hasCert := false
		for _, item := range container.Items {
			if item.Type == certlib.ContentCertificate && item.Certificate != nil {
				hasCert = true
			}
		}
		if !hasCert {
			t.Error("expected cert after password change readback")
		}
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		derData, err := certlib.EncodeDER(certlib.CertItem{
			Type: certlib.ContentCertificate, Certificate: caCert,
		})
		if err != nil {
			t.Fatal(err)
		}
		derPath := filepath.Join(dir, "test.der")
		if err := os.WriteFile(derPath, derData, 0600); err != nil {
			t.Fatal(err)
		}

		_, err = Reencrypt(ReencryptOptions{
			InputPath:   derPath,
			NewPassword: []byte("new"),
		})
		if err == nil {
			t.Fatal("expected error for DER format")
		}
		if !strings.Contains(err.Error(), "does not support password") {
			t.Errorf("error = %q, expected 'does not support password'", err.Error())
		}
	})
}

func TestExtract(t *testing.T) {
	t.Run("ByIndex", func(t *testing.T) {
		dir := t.TempDir()
		caKey := mustGenECKey(t)
		caCert := mustMakeCA(t, caKey)

		interKey := mustGenECKey(t)
		interCert, _, err := certlib.CreateSignedCert(interKey, certlib.CertGenOptions{
			Subject:    pkix.Name{CommonName: "Inter"},
			Days:       365,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		leafKey := mustGenECKey(t)
		leafCert := mustMakeLeaf(t, leafKey, caCert, caKey)

		pemPath := writePEMFile(t, dir, "multi.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: leafCert},
			{Type: certlib.ContentCertificate, Certificate: interCert},
			{Type: certlib.ContentCertificate, Certificate: caCert},
		})

		outDir := filepath.Join(dir, "out")
		if err := os.Mkdir(outDir, 0755); err != nil {
			t.Fatal(err)
		}

		result, err := Extract(ExtractOptions{
			InputPath: pemPath,
			OutputDir: outDir,
			Index:     2,
			Overwrite: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.ExtractedFiles) != 1 {
			t.Fatalf("extracted count = %d, want 1", len(result.ExtractedFiles))
		}
	})
}
