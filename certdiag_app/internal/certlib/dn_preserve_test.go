package certlib

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var (
	oidEmailAddress    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

func mustIA5(t *testing.T, s string) asn1.RawValue {
	t.Helper()
	b, err := asn1.MarshalWithParams(s, "ia5")
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: b}
}

func findDNValue(names []pkix.AttributeTypeAndValue, oid asn1.ObjectIdentifier) (string, bool) {
	for _, atv := range names {
		if atv.Type.Equal(oid) {
			if s, ok := atv.Value.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func TestSignCSRPreservesNonStandardDN(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	key := mustGenerateECKey(t)
	csr, _, err := CreateCSR(key, CertGenOptions{
		Subject: pkix.Name{
			CommonName: "leaf",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidDomainComponent, Value: mustIA5(t, "com")},
				{Type: oidDomainComponent, Value: mustIA5(t, "example")},
				{Type: oidEmailAddress, Value: mustIA5(t, "a@example.com")},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := SignCSR(csr, caKey, caCert, CertGenOptions{Days: 365})
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName != "leaf" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "leaf")
	}
	email, ok := findDNValue(cert.Subject.Names, oidEmailAddress)
	if !ok || email != "a@example.com" {
		t.Errorf("emailAddress = %q (found=%v), want %q", email, ok, "a@example.com")
	}
	dcs := allDNValues(cert.Subject.Names, oidDomainComponent)
	if len(dcs) != 2 || dcs[0] != "com" || dcs[1] != "example" {
		t.Errorf("domainComponents = %v, want [com example]", dcs)
	}
}

func TestTemplateFromCertPreservesNonStandardDN(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	srcKey := mustGenerateECKey(t)
	srcCert, _, err := CreateSignedCert(srcKey, CertGenOptions{
		Subject: pkix.Name{
			CommonName: "leaf",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidDomainComponent, Value: mustIA5(t, "com")},
				{Type: oidDomainComponent, Value: mustIA5(t, "example")},
				{Type: oidEmailAddress, Value: mustIA5(t, "a@example.com")},
			},
		},
		Days:       365,
		SignerCert: caCert,
		SignerKey:  caKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	genOpts := TemplateFromCert(srcCert)
	genOpts.SignerCert = caCert
	genOpts.SignerKey = caKey

	renewed, _, err := CreateSignedCert(srcKey, genOpts)
	if err != nil {
		t.Fatal(err)
	}

	email, ok := findDNValue(renewed.Subject.Names, oidEmailAddress)
	if !ok || email != "a@example.com" {
		t.Errorf("emailAddress = %q (found=%v), want %q", email, ok, "a@example.com")
	}
	dcs := allDNValues(renewed.Subject.Names, oidDomainComponent)
	if len(dcs) != 2 {
		t.Errorf("domainComponents = %v, want 2 entries", dcs)
	}
}

func allDNValues(names []pkix.AttributeTypeAndValue, oid asn1.ObjectIdentifier) []string {
	var out []string
	for _, atv := range names {
		if atv.Type.Equal(oid) {
			if s, ok := atv.Value.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
