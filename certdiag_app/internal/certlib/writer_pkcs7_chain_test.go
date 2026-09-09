package certlib

import (
	"testing"

	"github.com/smallstep/pkcs7"
)

// TestWritePKCS7_PreservesKeyChain verifies the fix: intermediates carried on a
// JKS-sourced key's Chain field are emitted into the PKCS#7 output, matching the
// PEM/P12/JKS writers, instead of being dropped so only the leaf survives.
func TestWritePKCS7_PreservesKeyChain(t *testing.T) {
	rootKey, rootCert := chainCA(t, "root-ca", 1, nil, nil)
	interKey, interCert := chainCA(t, "inter-ca", 2, rootKey, rootCert)
	leafKey, leafCert := chainLeaf(t, interKey, interCert)

	// Model a JKS read: the key carries the issuer chain (beyond the leaf) on
	// its Chain field; only the leaf is a standalone cert item.
	items := []CertItem{
		{Type: ContentPrivateKey, PrivateKey: leafKey, Chain: [][]byte{interCert.Raw, rootCert.Raw}},
		{Type: ContentCertificate, Certificate: leafCert, RawBytes: leafCert.Raw},
	}

	p7, err := EncodePKCS7(items)
	if err != nil {
		t.Fatalf("EncodePKCS7: %v", err)
	}

	parsed, err := pkcs7.Parse(p7)
	if err != nil {
		t.Fatalf("parse PKCS#7: %v", err)
	}
	got := map[string]bool{}
	for _, c := range parsed.Certificates {
		got[c.Subject.CommonName] = true
	}
	for _, cn := range []string{"leaf", "inter-ca", "root-ca"} {
		if !got[cn] {
			t.Errorf("PKCS#7 output missing %q; got %v", cn, got)
		}
	}
}
