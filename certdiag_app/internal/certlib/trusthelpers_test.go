package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Minimal in-memory certificate helpers for the trust checks. Kept local to
// this file so they cannot drift into the wider certlib test corpus.

type trustTestCert struct {
	cn   string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTrustTestCert(t *testing.T, cn string, isCA bool) *trustTestCert {
	t.Helper()
	return signTrustTestCert(t, nil, cn, isCA)
}

func newTrustTestCA(t *testing.T, cn string) *trustTestCert {
	t.Helper()
	return signTrustTestCert(t, nil, cn, true)
}

// sign issues a leaf under this CA.
func (c *trustTestCert) sign(t *testing.T, cn string) *trustTestCert {
	t.Helper()
	return signTrustTestCert(t, c, cn, false)
}

func signTrustTestCert(t *testing.T, parent *trustTestCert, cn string, isCA bool) *trustTestCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.DNSNames = []string{cn}
	}

	signerCert, signerKey := tmpl, any(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &trustTestCert{cn: cn, cert: cert, key: key}
}
