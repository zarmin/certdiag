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

// TestIsSelfSigned pins the one self-signed predicate (M31 R5): subject equals
// issuer, key identifiers agree when both are present, no signature check.
func TestIsSelfSigned_Predicate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, SubjectKeyId: []byte{9},
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(leafDER)

	cases := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"self-signed CA", ca, true},
		{"leaf", leaf, false},
		{"same names, different key ids", &x509.Certificate{
			Subject: pkix.Name{CommonName: "T"}, Issuer: pkix.Name{CommonName: "T"},
			SubjectKeyId: []byte{1}, AuthorityKeyId: []byte{2}}, false},
		{"same names, no key ids", &x509.Certificate{
			Subject: pkix.Name{CommonName: "T"}, Issuer: pkix.Name{CommonName: "T"}}, true},
		{"legacy SHA-1 style: signature not consulted", &x509.Certificate{
			Subject: pkix.Name{CommonName: "Old Root"}, Issuer: pkix.Name{CommonName: "Old Root"},
			SignatureAlgorithm: x509.SHA1WithRSA}, true},
	}
	for _, c := range cases {
		if got := IsSelfSigned(c.cert); got != c.want {
			t.Errorf("%s: IsSelfSigned = %v, want %v", c.name, got, c.want)
		}
	}
}
