package certlib

import (
	"testing"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestWritePKCS12_PairsKeyWithMatchingLeaf verifies the fix: when the private
// key is followed by issuer certs (the ordering expandKeyChains + bundle's
// keys-first reordering produce for a JKS-sourced key), WritePKCS12 pairs the
// key with the certificate whose public key matches it, not the first cert
// (which would be an intermediate, yielding a key/cert-mismatched archive).
func TestWritePKCS12_PairsKeyWithMatchingLeaf(t *testing.T) {
	rootKey, rootCert := chainCA(t, "root", 1, nil, nil)
	interKey, interCert := chainCA(t, "inter", 2, rootKey, rootCert)
	leafKey, leafCert := chainLeaf(t, interKey, interCert)

	// Pathological order: key first, then inter, root, and finally the leaf.
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey},
		{Type: ContentCertificate, Certificate: interCert, RawBytes: interCert.Raw},
		{Type: ContentCertificate, Certificate: rootCert, RawBytes: rootCert.Raw},
		{Type: ContentCertificate, Certificate: leafCert, RawBytes: leafCert.Raw},
	}

	p12, err := EncodePKCS12(items, []byte("pw"), false)
	if err != nil {
		t.Fatalf("EncodePKCS12: %v", err)
	}

	_, cert, caCerts, err := gopkcs12.DecodeChain(p12, "pw")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if cert.Subject.CommonName != "leaf" {
		t.Errorf("P12 leaf CN = %q, want \"leaf\" (key paired with the wrong cert)", cert.Subject.CommonName)
	}
	if !KeyMatchesCert(leafKey, cert) {
		t.Error("P12 leaf cert does not match the private key")
	}
	if len(caCerts) != 2 {
		t.Errorf("expected intermediate+root relegated to CA certs (2), got %d", len(caCerts))
	}
}
