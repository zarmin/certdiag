package certlib

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncodePEM(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	t.Run("SingleCert", func(t *testing.T) {
		items := []CertItem{{Type: ContentCertificate, Certificate: leafCert}}
		data, err := EncodePEM(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "single.pem", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) != 1 {
			t.Fatalf("cert count = %d, want 1", len(certs))
		}
		if certFingerprint(certs[0].Certificate) != certFingerprint(leafCert) {
			t.Error("fingerprint mismatch")
		}
	})

	t.Run("CertAndKey", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentPrivateKey, PrivateKey: leafKey},
		}
		data, err := EncodePEM(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "certkey.pem", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(container.Items) != 2 {
			t.Fatalf("item count = %d, want 2", len(container.Items))
		}
	})

	t.Run("Chain", func(t *testing.T) {
		interKey := mustGenerateECKey(t)
		interCert, _ := mustCreateIntermediateCA(t, interKey, caCert, caKey)
		items := []CertItem{
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentCertificate, Certificate: interCert},
			{Type: ContentCertificate, Certificate: caCert},
		}
		data, err := EncodePEM(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "chain.pem", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) != 3 {
			t.Fatalf("cert count = %d, want 3", len(certs))
		}
		if certFingerprint(certs[0].Certificate) != certFingerprint(leafCert) {
			t.Error("first cert fingerprint mismatch (order not preserved)")
		}
	})
}

func TestEncodeDER(t *testing.T) {
	t.Run("Cert", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _ := mustCreateSelfSignedCA(t, key)
		item := CertItem{Type: ContentCertificate, Certificate: cert}
		data, err := EncodeDER(item)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "cert.der", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) != 1 {
			t.Fatalf("cert count = %d, want 1", len(certs))
		}
		if certFingerprint(certs[0].Certificate) != certFingerprint(cert) {
			t.Error("fingerprint mismatch")
		}
	})
}

func TestEncodePKCS12(t *testing.T) {
	password := []byte("test")
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}

	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	t.Run("CertKey", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
		}
		data, err := EncodePKCS12(items, password, false)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "certkey.p12", data)
		container, err := ReadFile(path, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		keys := filterKeys(container.Items)
		if len(certs) == 0 {
			t.Error("expected at least 1 cert in p12")
		}
		if len(keys) == 0 {
			t.Error("expected at least 1 key in p12")
		}
	})

	t.Run("WithChain", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentCertificate, Certificate: caCert},
		}
		data, err := EncodePKCS12(items, password, false)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "chain.p12", data)
		container, err := ReadFile(path, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) < 2 {
			t.Errorf("cert count = %d, want >= 2", len(certs))
		}
	})
}

func TestEncodePKCS12_NilPassword(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: leafCert},
	}
	data, err := EncodePKCS12(items, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := mustWriteTempFile(t, dir, "nil-pw.p12", data)

	// Should be readable with empty password fallback (passwordsWithEmpty)
	container, err := ReadFile(path, nil)
	if err != nil {
		t.Fatalf("read nil-password p12: %v", err)
	}
	certs := filterCerts(container.Items)
	if len(certs) == 0 {
		t.Error("expected at least 1 cert in nil-password p12")
	}
	keys := filterKeys(container.Items)
	if len(keys) == 0 {
		t.Error("expected at least 1 key in nil-password p12")
	}
}

func TestEncodePKCS12_EmptyPassword(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	emptyPw := []byte("")
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: leafCert},
	}
	data, err := EncodePKCS12(items, emptyPw, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := mustWriteTempFile(t, dir, "empty-pw.p12", data)

	// Should be readable with explicit empty password
	passwords := []TaggedPassword{{Password: emptyPw, Source: PasswordSourceCLI}}
	container, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatalf("read empty-password p12: %v", err)
	}
	certs := filterCerts(container.Items)
	if len(certs) == 0 {
		t.Error("expected at least 1 cert in empty-password p12")
	}
}

func TestEncodePKCS7(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	t.Run("Single", func(t *testing.T) {
		items := []CertItem{{Type: ContentCertificate, Certificate: leafCert}}
		data, err := EncodePKCS7(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "single.p7b", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) != 1 {
			t.Fatalf("cert count = %d, want 1", len(certs))
		}
	})

	t.Run("Chain", func(t *testing.T) {
		interKey := mustGenerateECKey(t)
		interCert, _ := mustCreateIntermediateCA(t, interKey, caCert, caKey)
		items := []CertItem{
			{Type: ContentCertificate, Certificate: leafCert},
			{Type: ContentCertificate, Certificate: interCert},
			{Type: ContentCertificate, Certificate: caCert},
		}
		data, err := EncodePKCS7(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "chain.p7b", data)
		container, err := ReadFile(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) != 3 {
			t.Fatalf("cert count = %d, want 3", len(certs))
		}
	})
}

func TestEncodeJKS(t *testing.T) {
	password := []byte("changeit")
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}

	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateRSAKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	t.Run("PrivateKey", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
		}
		data, err := EncodeJKS(items, password, nil)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "key.jks", data)
		container, err := ReadFile(path, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Error("expected at least 1 cert in jks")
		}
	})

	t.Run("TrustedCert", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentCertificate, Certificate: caCert},
		}
		data, err := EncodeJKS(items, password, nil)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := mustWriteTempFile(t, dir, "trust.jks", data)
		container, err := ReadFile(path, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Error("expected cert in jks trust store")
		}
		keys := filterKeys(container.Items)
		if len(keys) != 0 {
			t.Error("expected no keys in jks trust store")
		}
	})
}

func TestWriteToFile(t *testing.T) {
	t.Run("Atomic", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "atomic-test.pem")
		data := []byte("test-data")
		if err := WriteToFile(path, data, false); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(data) {
			t.Error("content mismatch")
		}
	})

	t.Run("OverwriteProtection", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "existing.pem")
		if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		err := WriteToFile(path, []byte("new"), false)
		if err == nil {
			t.Fatal("expected error for existing file, got nil")
		}
	})
}

func TestRoundTrip(t *testing.T) {
	password := []byte("test")
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}

	caKey := mustGenerateRSAKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)
	leafKey := mustGenerateRSAKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)
	origFP := certFingerprint(leafCert)

	t.Run("PEM_PKCS12_PEM", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
		}
		p12Data, err := EncodePKCS12(items, password, false)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		p12Path := mustWriteTempFile(t, dir, "rt.p12", p12Data)
		container, err := ReadFile(p12Path, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Fatal("no certs after round-trip")
		}
		if certFingerprint(certs[0].Certificate) != origFP {
			t.Error("fingerprint mismatch after PEM->PKCS12->PEM")
		}
	})

	t.Run("PEM_DER_PEM", func(t *testing.T) {
		item := CertItem{Type: ContentCertificate, Certificate: leafCert}
		derData, err := EncodeDER(item)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		derPath := mustWriteTempFile(t, dir, "rt.der", derData)
		container, err := ReadFile(derPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Fatal("no certs after round-trip")
		}
		if certFingerprint(certs[0].Certificate) != origFP {
			t.Error("fingerprint mismatch after PEM->DER->PEM")
		}
	})

	t.Run("PEM_JKS_PEM", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
		}
		jksData, err := EncodeJKS(items, password, nil)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		jksPath := mustWriteTempFile(t, dir, "rt.jks", jksData)
		container, err := ReadFile(jksPath, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Fatal("no certs after round-trip")
		}
		if certFingerprint(certs[0].Certificate) != origFP {
			t.Error("fingerprint mismatch after PEM->JKS->PEM")
		}
	})

	t.Run("PEM_PKCS7_PEM", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentCertificate, Certificate: leafCert},
		}
		p7Data, err := EncodePKCS7(items)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		p7Path := mustWriteTempFile(t, dir, "rt.p7b", p7Data)
		container, err := ReadFile(p7Path, nil)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container.Items)
		if len(certs) == 0 {
			t.Fatal("no certs after round-trip")
		}
		if certFingerprint(certs[0].Certificate) != origFP {
			t.Error("fingerprint mismatch after PEM->PKCS7->PEM")
		}
	})

	t.Run("PKCS12_JKS", func(t *testing.T) {
		items := []CertItem{
			{Type: ContentPrivateKey, PrivateKey: leafKey},
			{Type: ContentCertificate, Certificate: leafCert},
		}
		p12Data, err := EncodePKCS12(items, password, false)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		p12Path := mustWriteTempFile(t, dir, "rt.p12", p12Data)
		container, err := ReadFile(p12Path, passwords)
		if err != nil {
			t.Fatal(err)
		}

		// Re-encode to JKS
		jksData, err := EncodeJKS(container.Items, password, nil)
		if err != nil {
			t.Fatal(err)
		}
		jksPath := mustWriteTempFile(t, dir, "rt.jks", jksData)
		container2, err := ReadFile(jksPath, passwords)
		if err != nil {
			t.Fatal(err)
		}
		certs := filterCerts(container2.Items)
		if len(certs) == 0 {
			t.Fatal("no certs after PKCS12->JKS round-trip")
		}
		if certFingerprint(certs[0].Certificate) != origFP {
			t.Error("fingerprint mismatch after PKCS12->JKS")
		}
	})
}

func filterCerts(items []CertItem) []CertItem {
	var result []CertItem
	for _, item := range items {
		if item.Type == ContentCertificate && item.Certificate != nil {
			result = append(result, item)
		}
	}
	return result
}

func filterKeys(items []CertItem) []CertItem {
	var result []CertItem
	for _, item := range items {
		if item.Type == ContentPrivateKey {
			result = append(result, item)
		}
	}
	return result
}
