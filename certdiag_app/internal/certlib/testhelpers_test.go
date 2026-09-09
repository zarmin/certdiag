package certlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func mustGenerateRSAKey(t interface {
	Helper()
	Fatal(...any)
}) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGenerateECKey(t interface {
	Helper()
	Fatal(...any)
}) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGenerateEd25519Key(t interface {
	Helper()
	Fatal(...any)
}) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustCreateSelfSignedCA(t interface {
	Helper()
	Fatal(...any)
}, key crypto.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	opts := CertGenOptions{
		Subject:    pkix.Name{CommonName: "Test CA"},
		Days:       3650,
		IsCA:       true,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PathLength: -1,
	}
	cert, der, err := CreateSelfSignedCert(key, opts)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func mustCreateLeafCert(t interface {
	Helper()
	Fatal(...any)
}, key crypto.PrivateKey, caCert *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	opts := CertGenOptions{
		Subject: pkix.Name{CommonName: "test.local"},
		SANs: SANList{
			DNSNames: []string{"test.local", "www.test.local"},
		},
		Days:        365,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignerCert:  caCert,
		SignerKey:   caKey,
	}
	cert, der, err := CreateSignedCert(key, opts)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

func mustWriteTempFile(t interface {
	Helper()
	Fatal(...any)
}, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h[:])
}

func mustCreateCSR(t interface {
	Helper()
	Fatal(...any)
}, key crypto.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	csr, _, err := CreateCSR(key, CertGenOptions{
		Subject: pkix.Name{CommonName: "test-csr.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// mustCreateIntermediateCA creates an intermediate CA signed by the given root CA.
func mustCreateIntermediateCA(t interface {
	Helper()
	Fatal(...any)
}, key crypto.PrivateKey, rootCert *x509.Certificate, rootKey crypto.PrivateKey) (*x509.Certificate, []byte) {
	t.Helper()
	now := time.Now()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	pub := key.(interface{ Public() crypto.PublicKey }).Public()
	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, pub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}
