//go:build fulltest

package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func certWithExpiry(t *testing.T, notBefore, notAfter time.Time) *CertItem {
	t.Helper()
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "expiry-test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func certWithKeyUsage(t *testing.T, isCA bool, ku x509.KeyUsage, eku []x509.ExtKeyUsage) *CertItem {
	t.Helper()
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "keyusage-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func certWithSANs(t *testing.T, dns []string, ips []net.IP) *CertItem {
	t.Helper()
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "san-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func certWithSerial(t *testing.T, serial *big.Int) *CertItem {
	t.Helper()
	key := mustGenerateECKey(t)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "serial-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func mockRSACertItem(bits int) *CertItem {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits)-1)
	pub := &rsa.PublicKey{N: n, E: 65537}
	cert := &x509.Certificate{
		PublicKey:             pub,
		PublicKeyAlgorithm:    x509.RSA,
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-rsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func mockECCertItem(curve elliptic.Curve) *CertItem {
	x, y := curve.Params().Gx, curve.Params().Gy
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	cert := &x509.Certificate{
		PublicKey:             pub,
		PublicKeyAlgorithm:    x509.ECDSA,
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mock-ec"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func containerWith(items ...*CertItem) *CertContainer {
	c := &CertContainer{
		FilePath: "/test/test.pem",
		Format:   FormatPEM,
	}
	for _, item := range items {
		c.Items = append(c.Items, *item)
	}
	return c
}

func storeWith(containers ...*CertContainer) *CertStore {
	s := NewCertStore()
	for _, c := range containers {
		s.AddContainer(*c)
	}
	return s
}

func runCheck(t *testing.T, checkID string, container *CertContainer, item *CertItem, store *CertStore) []CheckIssue {
	t.Helper()
	ref := ItemRef{ContainerIdx: 0, ItemIdx: 0}
	opts := CheckOptions{}.Defaults()
	relIndex := BuildRelationIndex(store.Relations, store)

	for _, def := range allChecks {
		if def.ID == checkID {
			return def.check(container, item, ref, opts, relIndex, store)
		}
	}
	t.Fatalf("check %q not found", checkID)
	return nil
}

func assertIssue(t *testing.T, issues []CheckIssue, severity CheckSeverity, checkID string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Severity == severity && issue.CheckID == checkID {
			return
		}
	}
	t.Errorf("expected issue with severity=%s checkID=%s, got %v", severity, checkID, issues)
}

func assertNoIssues(t *testing.T, issues []CheckIssue) {
	t.Helper()
	if len(issues) != 0 {
		t.Errorf("expected no issues, got %d: %v", len(issues), issues)
	}
}
