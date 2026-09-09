//go:build fulltest

package certlib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip_PEM_Cert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	items := []CertItem{{Type: ContentCertificate, Certificate: cert}}
	data, err := EncodePEM(items)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(c.Items))
	}
	if c.Items[0].Certificate == nil {
		t.Fatal("certificate is nil")
	}
	if certFingerprint(c.Items[0].Certificate) != certFingerprint(cert) {
		t.Fatal("fingerprint mismatch")
	}
}

func TestRoundTrip_DER_Cert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	item := CertItem{Type: ContentCertificate, Certificate: cert, RawBytes: cert.Raw}
	data, err := EncodeDER(item)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.der")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Items) < 1 {
		t.Fatalf("expected at least 1 item, got %d", len(c.Items))
	}
	var found bool
	for _, it := range c.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == certFingerprint(cert) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fingerprint mismatch after DER round-trip")
	}
}

func TestRoundTrip_PKCS12_CertAndKey(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	password := []byte("testpass")
	data, err := EncodePKCS12(items, password, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatal(err)
	}
	var certFound, keyFound bool
	for _, it := range c.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == certFingerprint(cert) {
			certFound = true
		}
		if it.PrivateKey != nil {
			keyFound = true
		}
	}
	if !certFound {
		t.Fatal("certificate fingerprint mismatch after PKCS12 round-trip")
	}
	if !keyFound {
		t.Fatal("private key not found after PKCS12 round-trip")
	}
}

func TestRoundTrip_JKS_CertChain(t *testing.T) {
	rootKey := mustGenerateRSAKey(t)
	rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
	interKey := mustGenerateRSAKey(t)
	interCert, _ := mustCreateIntermediateCA(t, interKey, rootCert, rootKey)
	leafKey := mustGenerateRSAKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, interCert, interKey)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: rootCert},
		{Type: ContentCertificate, Certificate: interCert},
		{Type: ContentCertificate, Certificate: leafCert},
	}
	password := []byte("changeit")
	aliases := map[int]string{0: "root", 1: "intermediate", 2: "leaf"}
	data, err := EncodeJKS(items, password, aliases)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jks")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatal(err)
	}

	expectedFPs := map[string]bool{
		certFingerprint(rootCert):  false,
		certFingerprint(interCert): false,
		certFingerprint(leafCert):  false,
	}
	for _, it := range c.Items {
		if it.Certificate != nil {
			fp := certFingerprint(it.Certificate)
			if _, ok := expectedFPs[fp]; ok {
				expectedFPs[fp] = true
			}
		}
	}
	for fp, found := range expectedFPs {
		if !found {
			t.Fatalf("cert with fingerprint %s not found after JKS round-trip", fp)
		}
	}
}

func TestRoundTrip_PKCS7_Cert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	items := []CertItem{{Type: ContentCertificate, Certificate: cert}}
	data, err := EncodePKCS7(items)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.p7b")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := ReadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range c.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == certFingerprint(cert) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fingerprint mismatch after PKCS7 round-trip")
	}
}

func TestRoundTrip_PEM_to_PKCS12_to_PEM(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	originalFP := certFingerprint(cert)

	pemItems := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	pemData, err := EncodePEM(pemItems)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "step1.pem")
	if err := os.WriteFile(pemPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}
	pemContainer, err := ReadFile(pemPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("roundtrip")
	p12Data, err := EncodePKCS12(pemContainer.Items, password, false)
	if err != nil {
		t.Fatal(err)
	}
	p12Path := filepath.Join(dir, "step2.p12")
	if err := os.WriteFile(p12Path, p12Data, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	p12Container, err := ReadFile(p12Path, passwords)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, it := range p12Container.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == originalFP {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fingerprint mismatch after PEM -> PKCS12 -> read round-trip")
	}
}

func TestRoundTrip_PEM_to_JKS(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	originalFP := certFingerprint(cert)

	pemItems := []CertItem{{Type: ContentCertificate, Certificate: cert}}
	pemData, err := EncodePEM(pemItems)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "input.pem")
	if err := os.WriteFile(pemPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}
	pemContainer, err := ReadFile(pemPath, nil)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("changeit")
	aliases := map[int]string{0: "mycert"}
	jksData, err := EncodeJKS(pemContainer.Items, password, aliases)
	if err != nil {
		t.Fatal(err)
	}
	jksPath := filepath.Join(dir, "output.jks")
	if err := os.WriteFile(jksPath, jksData, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	jksContainer, err := ReadFile(jksPath, passwords)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, it := range jksContainer.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == originalFP {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fingerprint mismatch after PEM -> JKS round-trip")
	}
}

func TestRelations_AfterRoundTrip_SignedByChain(t *testing.T) {
	rootKey := mustGenerateECKey(t)
	rootCert, _ := mustCreateSelfSignedCA(t, rootKey)
	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, rootCert, rootKey)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: leafCert},
		{Type: ContentCertificate, Certificate: rootCert},
		{Type: ContentPrivateKey, PrivateKey: leafKey},
	}
	data, err := EncodePEM(items)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	store := NewCertStore()
	c, err := ReadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.AddContainer(*c)
	relations := DetectRelations(store)

	var signedByFound, keyPairFound bool
	for _, r := range relations {
		if r.Type == RelationSignedBy {
			signedByFound = true
		}
		if r.Type == RelationKeyCert {
			keyPairFound = true
		}
	}
	if !signedByFound {
		t.Fatal("signed_by relation not detected after PEM round-trip")
	}
	if !keyPairFound {
		t.Fatal("key_pair relation not detected after PEM round-trip")
	}
}

func TestRelations_AfterRoundTrip_PKCS12_KeyPair(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	password := []byte("testpass")
	data, err := EncodePKCS12(items, password, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "keypair.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	store := NewCertStore()
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatal(err)
	}
	store.AddContainer(*c)
	relations := DetectRelations(store)

	var keyPairFound bool
	for _, r := range relations {
		if r.Type == RelationKeyCert {
			keyPairFound = true
			break
		}
	}
	if !keyPairFound {
		t.Fatal("key_pair relation not detected after PKCS12 round-trip")
	}
}

func TestRelations_AfterRoundTrip_DuplicateCert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{{Type: ContentCertificate, Certificate: cert}}
	data, err := EncodePEM(items)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path1 := filepath.Join(dir, "cert1.pem")
	path2 := filepath.Join(dir, "cert2.pem")
	if err := os.WriteFile(path1, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path2, data, 0600); err != nil {
		t.Fatal(err)
	}

	store := NewCertStore()
	c1, err := ReadFile(path1, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.AddContainer(*c1)
	c2, err := ReadFile(path2, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.AddContainer(*c2)

	relations := DetectRelations(store)
	var sameCertFound bool
	for _, r := range relations {
		if r.Type == RelationSameCert {
			sameCertFound = true
			break
		}
	}
	if !sameCertFound {
		t.Fatal("same_cert relation not detected for duplicate cert in two files")
	}
}

func TestPassword_EmptyPassword_PKCS12(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	data, err := EncodePKCS12(items, []byte(""), false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "empty_pass.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: []byte(""), Source: PasswordSourceCLI}}
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatal(err)
	}
	var certFound bool
	for _, it := range c.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == certFingerprint(cert) {
			certFound = true
			break
		}
	}
	if !certFound {
		t.Fatal("certificate not found after PKCS12 round-trip with empty password")
	}
}

func TestPassword_VeryLong_PKCS12(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}
	longPass := []byte(strings.Repeat("A", 1000))
	data, err := EncodePKCS12(items, longPass, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "longpass.p12")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	passwords := []TaggedPassword{{Password: longPass, Source: PasswordSourceCLI}}
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatal(err)
	}
	var certFound bool
	for _, it := range c.Items {
		if it.Certificate != nil && certFingerprint(it.Certificate) == certFingerprint(cert) {
			certFound = true
			break
		}
	}
	if !certFound {
		t.Fatal("certificate not found after PKCS12 round-trip with 1000-char password")
	}
}
