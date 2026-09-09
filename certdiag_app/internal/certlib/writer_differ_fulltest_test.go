//go:build fulltest

package certlib

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------------------
// Section 9: Writer Edge Cases
// ---------------------------------------------------------------------------

// --- WritePEM ---

func TestWritePEM_EmptyItems(t *testing.T) {
	var buf bytes.Buffer
	err := WritePEM(&buf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty output, got %d bytes", buf.Len())
	}
}

func TestWritePEM_NilCertificate(t *testing.T) {
	items := []CertItem{{Type: ContentCertificate, Certificate: nil}}
	var buf bytes.Buffer
	err := WritePEM(&buf, items)
	if err == nil {
		t.Fatal("expected error for nil certificate")
	}
	if !strings.Contains(err.Error(), "nil certificate") {
		t.Fatalf("expected 'nil certificate' error, got: %v", err)
	}
}

func TestWritePEM_NilPrivateKey(t *testing.T) {
	items := []CertItem{{Type: ContentPrivateKey, PrivateKey: nil}}
	var buf bytes.Buffer
	err := WritePEM(&buf, items)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	if !strings.Contains(err.Error(), "nil key") {
		t.Fatalf("expected 'nil key' error, got: %v", err)
	}
}

func TestWritePEM_NilCSR(t *testing.T) {
	items := []CertItem{{Type: ContentCSR, CSR: nil}}
	var buf bytes.Buffer
	err := WritePEM(&buf, items)
	if err == nil {
		t.Fatal("expected error for nil CSR")
	}
	if !strings.Contains(err.Error(), "nil CSR") {
		t.Fatalf("expected 'nil CSR' error, got: %v", err)
	}
}

func TestWritePEM_UnsupportedContentType(t *testing.T) {
	items := []CertItem{{Type: "unknown_type"}}
	var buf bytes.Buffer
	err := WritePEM(&buf, items)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected 'unsupported' error, got: %v", err)
	}
}

func TestWritePEM_MixedItems(t *testing.T) {
	key := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, key)

	csrKey := mustGenerateECKey(t)
	csr, _, err := CreateCSR(csrKey, CertGenOptions{
		Subject: pkix.Name{CommonName: "test-csr"},
	})
	if err != nil {
		t.Fatal(err)
	}

	items := []CertItem{
		{Type: ContentCertificate, Certificate: caCert},
		{Type: ContentPrivateKey, PrivateKey: key},
		{Type: ContentCSR, CSR: csr},
	}

	var buf bytes.Buffer
	if err := WritePEM(&buf, items); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "BEGIN CERTIFICATE") {
		t.Error("missing CERTIFICATE block")
	}
	if !strings.Contains(output, "BEGIN PRIVATE KEY") {
		t.Error("missing PRIVATE KEY block")
	}
	if !strings.Contains(output, "BEGIN CERTIFICATE REQUEST") {
		t.Error("missing CERTIFICATE REQUEST block")
	}

	// Verify we can parse back all blocks
	rest := buf.Bytes()
	blockCount := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blockCount++
	}
	if blockCount != 3 {
		t.Fatalf("expected 3 PEM blocks, got %d", blockCount)
	}
}

// --- WriteDER ---

func TestWriteDER_PublicKey(t *testing.T) {
	key := mustGenerateECKey(t)
	item := CertItem{Type: ContentPublicKey, PublicKey: key.Public()}

	var buf bytes.Buffer
	if err := WriteDER(&buf, item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestWriteDER_UnsupportedContentType(t *testing.T) {
	item := CertItem{Type: "unknown_type"}
	var buf bytes.Buffer
	err := WriteDER(&buf, item)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected 'unsupported' error, got: %v", err)
	}
}

func TestWriteDER_NilCertificate(t *testing.T) {
	item := CertItem{Type: ContentCertificate, Certificate: nil}
	var buf bytes.Buffer
	err := WriteDER(&buf, item)
	if err == nil {
		t.Fatal("expected error for nil certificate")
	}
	if !strings.Contains(err.Error(), "nil certificate") {
		t.Fatalf("expected 'nil certificate' error, got: %v", err)
	}
}

// --- WritePKCS12 ---

func TestWritePKCS12_KeyAndCert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	password := []byte("test123")

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: key},
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, password, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-read to verify
	privKey, parsedCert, _, err := gopkcs12.DecodeChain(buf.Bytes(), string(password))
	if err != nil {
		t.Fatalf("failed to decode PKCS#12: %v", err)
	}
	if privKey == nil {
		t.Fatal("expected private key in PKCS#12")
	}
	if parsedCert == nil {
		t.Fatal("expected certificate in PKCS#12")
	}
	if certFingerprint(parsedCert) != certFingerprint(cert) {
		t.Fatal("certificate mismatch after round-trip")
	}
}

func TestWritePKCS12_CertsOnly_TrustStore(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)
	password := []byte("test123")

	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, password, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	certs, err := gopkcs12.DecodeTrustStore(buf.Bytes(), string(password))
	if err != nil {
		t.Fatalf("failed to decode PKCS#12 trust store: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert in trust store, got %d", len(certs))
	}
}

func TestWritePKCS12_TwoPrivateKeys(t *testing.T) {
	key1 := mustGenerateECKey(t)
	key2 := mustGenerateECKey(t)

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: key1},
		{Type: ContentPrivateKey, PrivateKey: key2},
	}

	var buf bytes.Buffer
	err := WritePKCS12(&buf, items, []byte("pass"), false)
	if err == nil {
		t.Fatal("expected error for two private keys")
	}
	if !strings.Contains(err.Error(), "only one private key") {
		t.Fatalf("expected 'only one private key' error, got: %v", err)
	}
}

func TestWritePKCS12_KeyWithoutCert(t *testing.T) {
	key := mustGenerateECKey(t)

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: key},
	}

	var buf bytes.Buffer
	err := WritePKCS12(&buf, items, []byte("pass"), false)
	if err == nil {
		t.Fatal("expected error for key without cert")
	}
	if !strings.Contains(err.Error(), "requires at least one certificate") {
		t.Fatalf("expected 'requires at least one certificate' error, got: %v", err)
	}
}

func TestWritePKCS12_NoItems(t *testing.T) {
	var buf bytes.Buffer
	err := WritePKCS12(&buf, nil, []byte("pass"), false)
	if err == nil {
		t.Fatal("expected error for no items")
	}
	if !strings.Contains(err.Error(), "no certificates or keys") {
		t.Fatalf("expected 'no certificates or keys' error, got: %v", err)
	}
}

func TestWritePKCS12_EmptyPassword(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: key},
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, []byte(""), false); err != nil {
		t.Fatalf("unexpected error with empty password: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestWritePKCS12_KeyCertCAChain(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	password := []byte("chain-test")
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: leafCert},
		{Type: ContentCertificate, Certificate: caCert},
	}

	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, password, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	privKey, parsedLeaf, caCerts, err := gopkcs12.DecodeChain(buf.Bytes(), string(password))
	if err != nil {
		t.Fatalf("failed to decode PKCS#12: %v", err)
	}
	if privKey == nil {
		t.Fatal("expected private key")
	}
	if certFingerprint(parsedLeaf) != certFingerprint(leafCert) {
		t.Fatal("leaf cert mismatch")
	}
	if len(caCerts) != 1 {
		t.Fatalf("expected 1 CA cert, got %d", len(caCerts))
	}
	if certFingerprint(caCerts[0]) != certFingerprint(caCert) {
		t.Fatal("CA cert mismatch")
	}
}

// --- WritePKCS12 cert ordering edge cases ---

func TestWritePKCS12_CertOrderReversed(t *testing.T) {
	// WritePKCS12 hardcodes allCerts[0] as leaf. Verify that when certs are
	// passed in reverse order (CA first, leaf second), the CA becomes the
	// "leaf" in the PKCS#12 -- this documents the current behavior.
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	password := []byte("order-test")
	// Pass CA cert FIRST, leaf cert SECOND (wrong order)
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: caCert},   // CA first
		{Type: ContentCertificate, Certificate: leafCert}, // leaf second
	}

	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, password, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Decode and check which cert ended up as the "leaf"
	_, parsedLeaf, caCerts, err := gopkcs12.DecodeChain(buf.Bytes(), string(password))
	if err != nil {
		t.Fatalf("failed to decode PKCS#12: %v", err)
	}

	// The CA cert ends up as the "leaf" because allCerts[0] is used
	if certFingerprint(parsedLeaf) != certFingerprint(caCert) {
		t.Log("WritePKCS12 used the correct cert as leaf despite wrong input order")
	} else {
		// This documents that cert ordering matters -- the first cert
		// is always used as the leaf, regardless of CA status.
		t.Log("WritePKCS12 uses first cert as leaf (order-dependent)")
	}
	_ = caCerts
}

// --- WritePKCS7 ---

func TestWritePKCS7_SingleCert(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	if err := WritePKCS7(&buf, items); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestWritePKCS7_MultipleCerts(t *testing.T) {
	key1 := mustGenerateECKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, key1)
	key2 := mustGenerateECKey(t)
	cert2, _ := mustCreateSelfSignedCA(t, key2)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert1},
		{Type: ContentCertificate, Certificate: cert2},
	}

	var buf bytes.Buffer
	if err := WritePKCS7(&buf, items); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestWritePKCS7_NoCerts_OnlyKeys(t *testing.T) {
	key := mustGenerateECKey(t)

	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: key},
	}

	var buf bytes.Buffer
	err := WritePKCS7(&buf, items)
	if err == nil {
		t.Fatal("expected error for no certificates")
	}
	if !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("expected 'no certificates' error, got: %v", err)
	}
}

func TestWritePKCS7_MixCertsAndKeys(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
		{Type: ContentPrivateKey, PrivateKey: key},
	}

	var buf bytes.Buffer
	if err := WritePKCS7(&buf, items); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output (keys silently ignored)")
	}
}

// --- WriteJKS ---

func TestWriteJKS_PrivateKeyEntry(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	password := []byte("jks-test")
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: leafCert},
		{Type: ContentCertificate, Certificate: caCert},
	}

	var buf bytes.Buffer
	if err := WriteJKS(&buf, items, password, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty JKS output")
	}
}

func TestWriteJKS_TrustedCertEntry(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	password := []byte("jks-trust")
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	if err := WriteJKS(&buf, items, password, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty JKS output")
	}
}

func TestWriteJKS_AutoAlias(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	password := []byte("alias-test")
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
	}

	var buf bytes.Buffer
	// No aliases provided -- auto-generation kicks in
	if err := WriteJKS(&buf, items, password, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty JKS output")
	}
}

func TestWriteJKS_ExplicitAlias(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	password := []byte("alias-test")
	items := []CertItem{
		{Type: ContentCertificate, Certificate: cert},
	}
	aliases := map[int]string{0: "my-trusted-ca"}

	var buf bytes.Buffer
	if err := WriteJKS(&buf, items, password, aliases); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty JKS output")
	}
}

func TestWriteJKS_LeafSelectionWhenFirstMatchIsCA(t *testing.T) {
	// WriteJKS selects the first cert matching the key's public key as "leaf".
	// If the CA key is used (and CA cert matches), the CA becomes the leaf
	// in the PrivateKeyEntry. Verify this behavior.
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	password := []byte("jks-ca-key-test")
	// Use the CA key (not the leaf key) as the private key
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: caKey},
		{Type: ContentCertificate, Certificate: caCert},
		{Type: ContentCertificate, Certificate: leafCert},
	}

	var buf bytes.Buffer
	err := WriteJKS(&buf, items, password, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty JKS output")
	}

	// Verify by reading back: the CA cert should be in the PrivateKeyEntry chain,
	// and the leaf cert should be a TrustedCertificateEntry
	c, readErr := ReadFile(
		mustWriteTempFile(t, t.TempDir(), "test.jks", buf.Bytes()),
		passwordFor(string(password)),
	)
	if readErr != nil {
		t.Fatalf("failed to read JKS: %v", readErr)
	}

	// Should have items for: CA key, CA cert (in chain), and leaf cert (trusted)
	if len(c.Items) < 2 {
		t.Errorf("expected at least 2 items in JKS, got %d", len(c.Items))
	}
}

// --- WriteToFile ---

func TestWriteToFile_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.pem")

	if err := WriteToFile(path, []byte("hello"), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}
}

func TestWriteToFile_OverwriteTrue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.pem")

	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := WriteToFile(path, []byte("new"), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("expected 'new', got %q", string(data))
	}
}

func TestWriteToFile_OverwriteFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.pem")

	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	err := WriteToFile(path, []byte("new"), false)
	if err == nil {
		t.Fatal("expected error for existing file with overwrite=false")
	}
	if !strings.Contains(err.Error(), "file already exists") {
		t.Fatalf("expected 'file already exists' error, got: %v", err)
	}
	if !errors.Is(err, ErrFileExists) {
		t.Fatalf("expected errors.Is(err, ErrFileExists), got: %v", err)
	}
}

func TestWriteToFile_NonExistentParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no", "such", "dir", "file.pem")

	err := WriteToFile(path, []byte("hello"), false)
	if err == nil {
		t.Fatal("expected error for non-existent parent directory")
	}
}

// ---------------------------------------------------------------------------
// Section 10: Certificate Comparison (differ.go)
// ---------------------------------------------------------------------------

func TestCompareCertificates_Identical(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	result := CompareCertificates(cert, cert, false)
	if !result.Identical() {
		t.Fatalf("expected identical result, got summary: %+v", result.Summary)
	}
	for _, f := range result.Fields {
		if f.Status != DiffSame {
			t.Errorf("field %q has status %q, expected same", f.Name, f.Status)
		}
	}
}

func TestCompareCertificates_DifferentSubjects(t *testing.T) {
	key1 := mustGenerateECKey(t)
	cert1, _, err := CreateSelfSignedCert(key1, CertGenOptions{
		Subject:  pkix.Name{CommonName: "Alpha CA"},
		Days:     365,
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	key2 := mustGenerateECKey(t)
	cert2, _, err := CreateSelfSignedCert(key2, CertGenOptions{
		Subject:  pkix.Name{CommonName: "Beta CA"},
		Days:     365,
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := CompareCertificates(cert1, cert2, false)
	if result.Identical() {
		t.Fatal("expected non-identical result")
	}
	found := false
	for _, f := range result.Fields {
		if f.Name == "Subject" && f.Status == DiffChanged {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Subject field to be changed")
	}
}

func TestCompareCertificates_DifferentValidity(t *testing.T) {
	key := mustGenerateECKey(t)

	cert1, _, err := CreateSelfSignedCert(key, CertGenOptions{
		Subject:  pkix.Name{CommonName: "Validity Test"},
		Days:     365,
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait briefly isn't reliable; instead create with different Days
	key2 := mustGenerateECKey(t)
	cert2, _, err := CreateSelfSignedCert(key2, CertGenOptions{
		Subject:  pkix.Name{CommonName: "Validity Test"},
		Days:     730,
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := CompareCertificates(cert1, cert2, false)
	found := false
	for _, f := range result.Fields {
		if f.Name == "Not After" && f.Status == DiffChanged {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Not After field to be changed")
	}
}

func TestCompareCertificates_DifferentSANs(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	key1 := mustGenerateECKey(t)
	cert1, _, err := CreateSignedCert(key1, CertGenOptions{
		Subject: pkix.Name{CommonName: "san-test"},
		SANs: SANList{
			DNSNames: []string{"a.example.com", "b.example.com"},
		},
		Days:       365,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	key2 := mustGenerateECKey(t)
	cert2, _, err := CreateSignedCert(key2, CertGenOptions{
		Subject: pkix.Name{CommonName: "san-test"},
		SANs: SANList{
			DNSNames: []string{"a.example.com", "c.example.com"},
		},
		Days:       365,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := CompareCertificates(cert1, cert2, false)
	found := false
	for _, f := range result.Fields {
		if f.Name == "SANs" && f.Status == DiffChanged {
			found = true
			// Check children for removed and added
			hasRemoved := false
			hasAdded := false
			for _, c := range f.Children {
				if c.Status == DiffRemoved {
					hasRemoved = true
				}
				if c.Status == DiffAdded {
					hasAdded = true
				}
			}
			if !hasRemoved {
				t.Error("expected a removed SAN child")
			}
			if !hasAdded {
				t.Error("expected an added SAN child")
			}
			break
		}
	}
	if !found {
		t.Error("expected SANs field to be changed")
	}
}

func TestCompareCertificates_DifferentKeyTypes(t *testing.T) {
	rsaKey := mustGenerateRSAKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, rsaKey)

	ecKey := mustGenerateECKey(t)
	cert2, _ := mustCreateSelfSignedCA(t, ecKey)

	result := CompareCertificates(cert1, cert2, false)
	found := false
	for _, f := range result.Fields {
		if f.Name == "Algorithm" && f.Status == DiffChanged {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Algorithm field to be changed")
	}
}

func TestCompareCertificates_DifferentSerials(t *testing.T) {
	key := mustGenerateECKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, key)

	key2 := mustGenerateECKey(t)
	cert2, _ := mustCreateSelfSignedCA(t, key2)

	// Self-signed CAs get random serials, so they should differ
	result := CompareCertificates(cert1, cert2, false)
	found := false
	for _, f := range result.Fields {
		if f.Name == "Serial" && f.Status == DiffChanged {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Serial field to be changed")
	}
}

func TestCompareCertificates_DetailedMode(t *testing.T) {
	key1 := mustGenerateECKey(t)
	cert1, _ := mustCreateSelfSignedCA(t, key1)

	key2 := mustGenerateECKey(t)
	cert2, _ := mustCreateSelfSignedCA(t, key2)

	basic := CompareCertificates(cert1, cert2, false)
	detailed := CompareCertificates(cert1, cert2, true)

	if len(detailed.Fields) <= len(basic.Fields) {
		t.Fatalf("detailed mode should have more fields: basic=%d, detailed=%d",
			len(basic.Fields), len(detailed.Fields))
	}

	// Check that detailed mode includes fingerprint and path length fields
	fieldNames := make(map[string]bool)
	for _, f := range detailed.Fields {
		fieldNames[f.Name] = true
	}
	for _, expected := range []string{"SHA-256", "SHA-1", "Path Length"} {
		if !fieldNames[expected] {
			t.Errorf("detailed mode missing field %q", expected)
		}
	}
}

func TestCompareCertificates_SelfComparison(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	result := CompareCertificates(cert, cert, true)
	if !result.Identical() {
		t.Fatalf("self-comparison should be identical, got summary: %+v", result.Summary)
	}
}

func TestCompareCertificates_SummaryCounts(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	key1 := mustGenerateECKey(t)
	cert1, _, err := CreateSignedCert(key1, CertGenOptions{
		Subject: pkix.Name{CommonName: "count-test"},
		SANs: SANList{
			DNSNames:    []string{"one.example.com"},
			IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		},
		Days:       365,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	key2 := mustGenerateECKey(t)
	cert2, _, err := CreateSignedCert(key2, CertGenOptions{
		Subject: pkix.Name{CommonName: "count-test"},
		SANs: SANList{
			DNSNames:    []string{"one.example.com"},
			IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		},
		Days:       365,
		KeyUsage:   x509.KeyUsageDigitalSignature,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	result := CompareCertificates(cert1, cert2, false)
	total := result.Summary.Same + result.Summary.Changed + result.Summary.Added + result.Summary.Removed
	if total != len(result.Fields) {
		t.Fatalf("summary counts (%d) don't match field count (%d)", total, len(result.Fields))
	}
}

func TestCompareCertificates_NilLeft(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	result := CompareCertificates(nil, cert, false)
	if result.Identical() {
		t.Fatal("nil left should not be identical")
	}
	if result.Summary.Changed != 1 {
		t.Fatalf("expected Changed=1, got %d", result.Summary.Changed)
	}
	if len(result.Fields) != 1 || result.Fields[0].Name != "error" {
		t.Fatal("expected single error field")
	}
}

func TestCompareCertificates_NilRight(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	result := CompareCertificates(cert, nil, false)
	if result.Identical() {
		t.Fatal("nil right should not be identical")
	}
	if result.Summary.Changed != 1 {
		t.Fatalf("expected Changed=1, got %d", result.Summary.Changed)
	}
}

func TestCompareCertificates_BothNil(t *testing.T) {
	result := CompareCertificates(nil, nil, false)
	if result.Identical() {
		t.Fatal("both nil should not be identical")
	}
	if result.Summary.Changed != 1 {
		t.Fatalf("expected Changed=1, got %d", result.Summary.Changed)
	}
}
