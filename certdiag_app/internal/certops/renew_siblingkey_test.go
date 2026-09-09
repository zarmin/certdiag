package certops

import (
	"crypto"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestFindSiblingKey_RejectsUnrelatedKey verifies the fix: with ca.key+ca.crt
// siblings and a server cert whose own key is absent, findSiblingKey must NOT
// return the CA's key - it must report no matching key.
func TestFindSiblingKey_RejectsUnrelatedKey(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert := jksTestCA(t)
	_, serverCert := jksTestLeaf(t, "server", 11, caKey, caCert)

	writePEMFile(t, dir, "ca.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: caKey}})
	writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	serverPath := writePEMFile(t, dir, "server.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: serverCert, RawBytes: serverCert.Raw}})

	key, err := findSiblingKey(serverPath, nil, serverCert)
	if err == nil {
		// If it wrongly returned a key, prove it is the CA's (the bug).
		signer, _ := key.(crypto.Signer)
		got, _ := x509.MarshalPKIXPublicKey(signer.Public())
		caPub, _ := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		if string(got) == string(caPub) {
			t.Fatal("BUG: findSiblingKey returned the CA's key for a cert it does not belong to")
		}
		t.Fatal("expected an error (no matching key), got a key")
	}
	t.Logf("correctly reported no matching key: %v", err)
}

// TestFindSiblingKey_AcceptsMatchingKey is the regression guard: when the cert's
// own key is present, findSiblingKey returns it (and not a sibling CA key).
func TestFindSiblingKey_AcceptsMatchingKey(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert := jksTestCA(t)
	serverKey, serverCert := jksTestLeaf(t, "server", 12, caKey, caCert)

	// Sibling CA key/cert present too, to ensure the wrong one is not chosen.
	writePEMFile(t, dir, "ca.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: caKey}})
	writePEMFile(t, dir, "ca.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw}})
	writePEMFile(t, dir, "server.key", []certlib.CertItem{{Type: certlib.ContentPrivateKey, PrivateKey: serverKey}})
	serverPath := writePEMFile(t, dir, "server.crt", []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: serverCert, RawBytes: serverCert.Raw}})

	key, err := findSiblingKey(serverPath, nil, serverCert)
	if err != nil {
		t.Fatalf("expected to find the server's own key, got: %v", err)
	}
	if !certlib.KeyMatchesCert(key, serverCert) {
		t.Error("returned key does not match the server cert")
	}
	if certlib.KeyMatchesCert(key, caCert) {
		t.Error("returned the CA key instead of the server key")
	}
	_ = filepath.Base(serverPath)
}
