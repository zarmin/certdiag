//go:build fulltest

package certlib

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestMatchesIssuer_ForgedAKISKI_NoSignedBy(t *testing.T) {
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	caName := pkix.Name{CommonName: "Shared CA Name"}

	parentKey := mustGenerateRSAKey(t)
	parentTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               caName,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
	}
	parentDer, err := x509.CreateCertificate(rand.Reader, parentTmpl, parentTmpl, parentKey.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parentCert := mustParseCert(t, parentDer)

	impostorKey := mustGenerateRSAKey(t)
	impostorTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               caName,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          ski,
	}
	impostorDer, err := x509.CreateCertificate(rand.Reader, impostorTmpl, impostorTmpl, impostorKey.Public(), impostorKey)
	if err != nil {
		t.Fatal(err)
	}
	impostorCert := mustParseCert(t, impostorDer)

	leafKey := mustGenerateRSAKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.forged"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, leafTmpl, impostorCert, leafKey.Public(), impostorKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert := mustParseCert(t, leafDer)

	if leafCert.Issuer.String() != parentCert.Subject.String() {
		t.Fatalf("test setup: leaf issuer %q != parent subject %q", leafCert.Issuer, parentCert.Subject)
	}
	if len(leafCert.AuthorityKeyId) == 0 || len(parentCert.SubjectKeyId) == 0 {
		t.Fatal("test setup: expected AKI and SKI to be present")
	}
	if string(leafCert.AuthorityKeyId) != string(parentCert.SubjectKeyId) {
		t.Fatal("test setup: expected leaf AKI to match parent SKI")
	}

	if matchesIssuer(leafCert, parentCert) {
		t.Fatal("forged AKI/SKI match must not assert signed_by without a valid signature")
	}

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "parent.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: parentCert}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: leafCert}},
	})

	relations := DetectRelations(store)
	for _, r := range relations {
		if r.Type == RelationSignedBy {
			t.Fatal("forged cert must not produce a signed_by relation to the parent")
		}
	}
}

func TestMatchesIssuer_GenuineAKISKI_SignedBy(t *testing.T) {
	caKey := mustGenerateRSAKey(t)
	caCert, caDer := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateRSAKey(t)
	leafCert, leafDer := mustCreateLeafCert(t, leafKey, caCert, caKey)

	if len(leafCert.AuthorityKeyId) == 0 || len(caCert.SubjectKeyId) == 0 {
		t.Fatal("test setup: expected AKI and SKI to be present")
	}

	if !matchesIssuer(leafCert, caCert) {
		t.Fatal("genuine child must match its issuer")
	}

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "ca.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, caDer)}},
	})
	store.AddContainer(CertContainer{
		FilePath: "leaf.crt",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: mustParseCert(t, leafDer)}},
	})

	relations := DetectRelations(store)
	found := false
	for _, r := range relations {
		if r.Type == RelationSignedBy && r.Source.ContainerIdx == 1 && r.Target.ContainerIdx == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected signed_by relation from genuine leaf to CA")
	}
}
