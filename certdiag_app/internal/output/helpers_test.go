package output

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func mustGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func mustGenECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func mustGenEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return priv
}

func mustSelfSignedCert(t *testing.T, key interface{}) *x509.Certificate {
	t.Helper()
	cert, _, err := certlib.CreateSelfSignedCert(key, certlib.CertGenOptions{
		Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		IsCA:    true,
		Days:    365,
	})
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}
	return cert
}

func mustLeafCert(t *testing.T, key interface{}, caCert *x509.Certificate, caKey interface{}) *x509.Certificate {
	t.Helper()
	cert, _, err := certlib.CreateSignedCert(key, certlib.CertGenOptions{
		Subject:    pkix.Name{CommonName: "leaf.example.com"},
		SANs:       certlib.SANList{DNSNames: []string{"leaf.example.com", "www.example.com"}},
		Days:       90,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return cert
}

func mustCSR(t *testing.T, key interface{}, cn string) *x509.CertificateRequest {
	t.Helper()
	csr, _, err := certlib.CreateCSR(key, certlib.CertGenOptions{
		Subject: pkix.Name{CommonName: cn},
		SANs:    certlib.SANList{DNSNames: []string{cn}},
	})
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return csr
}

func makeCertItem(cert *x509.Certificate) certlib.CertItem {
	return certlib.CertItem{
		Type:        certlib.ContentCertificate,
		Certificate: cert,
	}
}

func makeKeyItem(key interface{}) certlib.CertItem {
	return certlib.CertItem{
		Type:       certlib.ContentPrivateKey,
		PrivateKey: key,
	}
}

func makeCSRItem(csr *x509.CertificateRequest) certlib.CertItem {
	return certlib.CertItem{
		Type: certlib.ContentCSR,
		CSR:  csr,
	}
}

func makePubKeyItem(pub interface{}) certlib.CertItem {
	return certlib.CertItem{
		Type:      certlib.ContentPublicKey,
		PublicKey: pub,
	}
}

func makeContainer(path string, format certlib.FileFormat, items ...certlib.CertItem) *certlib.CertContainer {
	return &certlib.CertContainer{
		FilePath: path,
		Format:   format,
		Items:    items,
	}
}

func disableColors(t *testing.T) {
	t.Helper()
	old := ColorsEnabled
	ColorsEnabled = false
	t.Cleanup(func() { ColorsEnabled = old })
}
