package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// The oracle: certdiag's answer and x509.Verify's must agree on the same chain.
// certdiag ships that verifier, so being stricter would refuse certificates
// that work and being looser would produce certificates it then flags.

func ncCA(t *testing.T, cn string, nc NameConstraints) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,

		PermittedDNSDomainsCritical: nc.Critical,
		PermittedDNSDomains:         nc.PermittedDNS,
		ExcludedDNSDomains:          nc.ExcludedDNS,
		PermittedIPRanges:           nc.PermittedIP,
		ExcludedIPRanges:            nc.ExcludedIP,
		PermittedEmailAddresses:     nc.PermittedEmail,
		ExcludedEmailAddresses:      nc.ExcludedEmail,
		PermittedURIDomains:         nc.PermittedURI,
		ExcludedURIDomains:          nc.ExcludedURI,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func ncLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, sans SANList) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       sans.DNSNames,
		IPAddresses:    sans.IPAddresses,
		EmailAddresses: sans.EmailAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCheckNameConstraints_AgreesWithVerify is the oracle test. Each case is
// built, checked by certdiag, then verified by Go, and the two must agree.
func TestCheckNameConstraints_AgreesWithVerify(t *testing.T) {
	cases := []struct {
		name string
		nc   NameConstraints
		cn   string
		sans SANList
	}{
		{"permitted dns, inside", NameConstraints{PermittedDNS: []string{"example.com"}},
			"a.example.com", SANList{DNSNames: []string{"a.example.com"}}},
		{"permitted dns, the domain itself", NameConstraints{PermittedDNS: []string{"example.com"}},
			"example.com", SANList{DNSNames: []string{"example.com"}}},
		{"permitted dns, outside", NameConstraints{PermittedDNS: []string{"example.com"}},
			"a.other.com", SANList{DNSNames: []string{"a.other.com"}}},
		{"leading dot, subdomain", NameConstraints{PermittedDNS: []string{".corp.example.com"}},
			"a.corp.example.com", SANList{DNSNames: []string{"a.corp.example.com"}}},
		{"leading dot, the domain itself", NameConstraints{PermittedDNS: []string{".corp.example.com"}},
			"corp.example.com", SANList{DNSNames: []string{"corp.example.com"}}},
		{"excluded dns wins", NameConstraints{
			PermittedDNS: []string{"example.com"}, ExcludedDNS: []string{"secret.example.com"}},
			"secret.example.com", SANList{DNSNames: []string{"secret.example.com"}}},
		{"excluded dns, sibling is fine", NameConstraints{
			PermittedDNS: []string{"example.com"}, ExcludedDNS: []string{"secret.example.com"}},
			"open.example.com", SANList{DNSNames: []string{"open.example.com"}}},
		{"multiple sans, one outside", NameConstraints{PermittedDNS: []string{"example.com"}},
			"a.example.com", SANList{DNSNames: []string{"a.example.com", "b.other.com"}}},
		{"ip permitted, inside", NameConstraints{PermittedIP: []*net.IPNet{cidr(t, "10.0.0.0/8")}},
			"host", SANList{IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}},
		{"ip permitted, outside", NameConstraints{PermittedIP: []*net.IPNet{cidr(t, "10.0.0.0/8")}},
			"host", SANList{IPAddresses: []net.IP{net.ParseIP("192.168.1.1")}}},
		{"ip excluded", NameConstraints{ExcludedIP: []*net.IPNet{cidr(t, "10.0.0.0/8")}},
			"host", SANList{IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}},
		{"email permitted, inside", NameConstraints{PermittedEmail: []string{"example.com"}},
			"user", SANList{EmailAddresses: []string{"user@example.com"}}},
		{"email permitted, outside", NameConstraints{PermittedEmail: []string{"example.com"}},
			"user", SANList{EmailAddresses: []string{"user@other.com"}}},
		{"unconstrained", NameConstraints{}, "anything.example",
			SANList{DNSNames: []string{"anything.example"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, caKey := ncCA(t, "NC Test CA", tc.nc)
			leaf := ncLeaf(t, ca, caKey, tc.cn, tc.sans)

			certdiagErr := CheckNameConstraints(ca, tc.cn, tc.sans)

			roots := x509.NewCertPool()
			roots.AddCert(ca)
			_, verifyErr := leaf.Verify(x509.VerifyOptions{
				Roots:     roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})

			certdiagRefuses := certdiagErr != nil
			verifyRefuses := verifyErr != nil

			if certdiagRefuses != verifyRefuses {
				t.Errorf("disagreement: certdiag refuses=%v (%v), x509.Verify refuses=%v (%v)",
					certdiagRefuses, certdiagErr, verifyRefuses, verifyErr)
			}
		})
	}
}

// TestCheckNameConstraints_CNOnlyWhenNoSANs mirrors what verifiers do: the CN
// is checked as a hostname only when there is nothing better.
func TestCheckNameConstraints_CNOnlyWhenNoSANs(t *testing.T) {
	ca, _ := ncCA(t, "CN CA", NameConstraints{PermittedDNS: []string{"example.com"}})

	if err := CheckNameConstraints(ca, "outside.other.com", SANList{}); err == nil {
		t.Error("with no SANs the CN is the name, and it is outside")
	}
	if err := CheckNameConstraints(ca, "outside.other.com",
		SANList{DNSNames: []string{"inside.example.com"}}); err != nil {
		t.Errorf("with SANs present the CN is not a hostname: %v", err)
	}
}

func TestCheckNameConstraints_MessageNamesTheOffender(t *testing.T) {
	ca, _ := ncCA(t, "Msg CA", NameConstraints{PermittedDNS: []string{"example.com"}})
	err := CheckNameConstraints(ca, "bad.other.com", SANList{DNSNames: []string{"bad.other.com"}})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "bad.other.com") {
		t.Errorf("the message must name the offending name: %v", err)
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("the message must name the constraint that refused it: %v", err)
	}
}

func TestParseNameConstraints(t *testing.T) {
	nc, err := ParseNameConstraints("DNS:example.com, DNS:.corp.example.com, IP:10.0.0.0/8, email:example.com, URI:.example.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(nc.PermittedDNS) != 2 || nc.PermittedDNS[1] != ".corp.example.com" {
		t.Errorf("DNS constraints: %v", nc.PermittedDNS)
	}
	if len(nc.PermittedIP) != 1 || nc.PermittedIP[0].String() != "10.0.0.0/8" {
		t.Errorf("IP constraints: %v", nc.PermittedIP)
	}
	if len(nc.PermittedEmail) != 1 || len(nc.PermittedURI) != 1 {
		t.Errorf("email/URI constraints: %v %v", nc.PermittedEmail, nc.PermittedURI)
	}
}

func TestParseNameConstraints_Errors(t *testing.T) {
	cases := []string{
		"example.com",           // no prefix: which kind?
		"IP:10.0.0.0/255.0.0.0", // the RFC mask form, deliberately not accepted
		"IP:not-an-address",
		"DNS:",
		"telephone:555",
	}
	for _, in := range cases {
		if _, err := ParseNameConstraints(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}

	if nc, err := ParseNameConstraints(""); err != nil || !nc.Empty() {
		t.Errorf("an empty value is not an error: %v", err)
	}
}

// TestParseNameConstraints_CIDROnly documents the choice: one syntax for one
// idea. The message has to say which one.
func TestParseNameConstraints_CIDROnly(t *testing.T) {
	_, err := ParseNameConstraints("IP:10.0.0.0/255.0.0.0")
	if err == nil {
		t.Fatal("the RFC mask form is not accepted")
	}
	if !strings.Contains(err.Error(), "CIDR") {
		t.Errorf("the error must say what is expected: %v", err)
	}
}
