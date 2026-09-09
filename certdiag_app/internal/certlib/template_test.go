package certlib

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTemplateFromCert(t *testing.T) {
	caKey := mustGenerateECKey(t)

	t.Run("CopiesSubject", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(caKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "tmpl-test", Organization: []string{"Org"}},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := TemplateFromCert(cert)
		if opts.Subject.CommonName != "tmpl-test" {
			t.Errorf("CN = %q, want %q", opts.Subject.CommonName, "tmpl-test")
		}
	})

	t.Run("CopiesSANs", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(caKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "san-tmpl"},
			SANs: SANList{
				DNSNames:    []string{"a.com", "b.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
			},
			Days: 365,
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := TemplateFromCert(cert)
		if len(opts.SANs.DNSNames) != 2 {
			t.Errorf("DNS count = %d, want 2", len(opts.SANs.DNSNames))
		}
		if len(opts.SANs.IPAddresses) != 1 {
			t.Errorf("IP count = %d, want 1", len(opts.SANs.IPAddresses))
		}
	})

	t.Run("CopiesKU", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(caKey, CertGenOptions{
			Subject:     pkix.Name{CommonName: "ku-tmpl"},
			Days:        365,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := TemplateFromCert(cert)
		if opts.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			t.Error("expected KeyUsageDigitalSignature")
		}
		if len(opts.ExtKeyUsage) != 1 {
			t.Errorf("EKU count = %d, want 1", len(opts.ExtKeyUsage))
		}
	})

	t.Run("CopiesCAFlag", func(t *testing.T) {
		cert, _ := mustCreateSelfSignedCA(t, caKey)
		opts := TemplateFromCert(cert)
		if !opts.IsCA {
			t.Error("expected IsCA = true")
		}
	})

	t.Run("ComputesDays", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(caKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "days-tmpl"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := TemplateFromCert(cert)
		if opts.Days != 366 {
			t.Errorf("Days = %d, want 366 (365d + clock-skew backdate, ceiled)", opts.Days)
		}
	})

	t.Run("SerialNotCopied", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(caKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "serial-tmpl"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		opts := TemplateFromCert(cert)
		if opts.Serial != nil {
			t.Error("expected Serial = nil (not copied)")
		}
	})
}

func TestTemplateFromCert_RoundsUpDays(t *testing.T) {
	now := time.Now()

	t.Run("ExactDaysUnchanged", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "exact"},
			NotBefore: now,
			NotAfter:  now.Add(365 * 24 * time.Hour),
		}
		opts := TemplateFromCert(cert)
		if opts.Days != 365 {
			t.Errorf("Days = %d, want 365", opts.Days)
		}
	})

	t.Run("FractionalDayRoundsUp", func(t *testing.T) {
		cert := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "fractional"},
			NotBefore: now,
			NotAfter:  now.Add(365*24*time.Hour + time.Hour),
		}
		opts := TemplateFromCert(cert)
		if opts.Days != 366 {
			t.Errorf("Days = %d, want 366 (ceiling, no shortening)", opts.Days)
		}
	})
}

func TestTemplateFromCert_CarriesExtensions(t *testing.T) {
	caKey := mustGenerateECKey(t)
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	source := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "ext-source"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/ca.crt"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{policyOID},
		PermittedDNSDomains:   []string{"example.com"},
	}

	opts := TemplateFromCert(source)
	if len(opts.CRLDistributionPoints) != 1 {
		t.Errorf("CRLDistributionPoints = %v", opts.CRLDistributionPoints)
	}
	if len(opts.OCSPServer) != 1 {
		t.Errorf("OCSPServer = %v", opts.OCSPServer)
	}
	if len(opts.IssuingCertificateURL) != 1 {
		t.Errorf("IssuingCertificateURL = %v", opts.IssuingCertificateURL)
	}
	if len(opts.PolicyIdentifiers) != 1 {
		t.Errorf("PolicyIdentifiers = %v", opts.PolicyIdentifiers)
	}
	if len(opts.PermittedDNSDomains) != 1 {
		t.Errorf("PermittedDNSDomains = %v", opts.PermittedDNSDomains)
	}

	renewed, _, err := CreateSelfSignedCert(caKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(renewed.CRLDistributionPoints) != 1 || renewed.CRLDistributionPoints[0] != "http://crl.example.com/ca.crl" {
		t.Errorf("renewed CRLDistributionPoints = %v", renewed.CRLDistributionPoints)
	}
	if len(renewed.OCSPServer) != 1 || renewed.OCSPServer[0] != "http://ocsp.example.com" {
		t.Errorf("renewed OCSPServer = %v", renewed.OCSPServer)
	}
	if len(renewed.IssuingCertificateURL) != 1 {
		t.Errorf("renewed IssuingCertificateURL = %v", renewed.IssuingCertificateURL)
	}
	if len(renewed.PolicyIdentifiers) == 0 && len(renewed.Policies) == 0 {
		t.Error("renewed cert lost certificate policies")
	}
	if len(renewed.PermittedDNSDomains) != 1 || renewed.PermittedDNSDomains[0] != "example.com" {
		t.Errorf("renewed PermittedDNSDomains = %v", renewed.PermittedDNSDomains)
	}
}

func TestMergeSubject(t *testing.T) {
	t.Run("FillsEmpty", func(t *testing.T) {
		target := pkix.Name{CommonName: ""}
		tmpl := pkix.Name{CommonName: "from-tmpl", Organization: []string{"Org"}}
		result := MergeSubject(target, tmpl)
		if result.CommonName != "from-tmpl" {
			t.Errorf("CN = %q, want %q", result.CommonName, "from-tmpl")
		}
		if len(result.Organization) != 1 || result.Organization[0] != "Org" {
			t.Errorf("O = %v, want [Org]", result.Organization)
		}
	})

	t.Run("NoOverwrite", func(t *testing.T) {
		target := pkix.Name{CommonName: "keep-this", Organization: []string{"OrigOrg"}}
		tmpl := pkix.Name{CommonName: "override", Organization: []string{"NewOrg"}}
		result := MergeSubject(target, tmpl)
		if result.CommonName != "keep-this" {
			t.Errorf("CN = %q, want %q", result.CommonName, "keep-this")
		}
		if result.Organization[0] != "OrigOrg" {
			t.Errorf("O = %v, want [OrigOrg]", result.Organization)
		}
	})

	t.Run("EmptyTemplate", func(t *testing.T) {
		target := pkix.Name{CommonName: "unchanged"}
		tmpl := pkix.Name{}
		result := MergeSubject(target, tmpl)
		if result.CommonName != "unchanged" {
			t.Errorf("CN = %q, want %q", result.CommonName, "unchanged")
		}
	})
}

func TestLoadCertProfile(t *testing.T) {
	t.Run("ValidProfile", func(t *testing.T) {
		dir := t.TempDir()
		content := `kind: certdiag-cert-profile
version: "1"
name: test-profile
subject:
  common_name: test.local
  organization: TestOrg
validity:
  days: 365
key:
  algorithm: ecdsa
  curve: p256
`
		path := filepath.Join(dir, "profile.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		p, err := LoadCertProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name != "test-profile" {
			t.Errorf("Name = %q, want %q", p.Name, "test-profile")
		}
		if p.Subject.CommonName != "test.local" {
			t.Errorf("CN = %q, want %q", p.Subject.CommonName, "test.local")
		}
		if p.Validity == nil || p.Validity.Days != 365 {
			t.Errorf("Days = %v, want 365", p.Validity)
		}
	})

	t.Run("InvalidKind", func(t *testing.T) {
		dir := t.TempDir()
		content := `kind: wrong-kind
version: "1"
`
		path := filepath.Join(dir, "bad.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCertProfile(path)
		if err == nil {
			t.Fatal("expected error for invalid kind")
		}
	})

	t.Run("EmptyKind", func(t *testing.T) {
		dir := t.TempDir()
		content := `version: "1"
`
		path := filepath.Join(dir, "empty-kind.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadCertProfile(path)
		if err == nil {
			t.Fatal("expected error for empty kind")
		}
	})
}

func TestProfileFromCert(t *testing.T) {
	ecKey := mustGenerateECKey(t)

	t.Run("LeafCert", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(ecKey, CertGenOptions{
			Subject: pkix.Name{
				CommonName:   "leaf.example.com",
				Organization: []string{"TestOrg"},
				Country:      []string{"US"},
			},
			SANs: SANList{
				DNSNames:    []string{"leaf.example.com", "www.example.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
			},
			Days:        365,
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Fatal(err)
		}

		p := ProfileFromCert(cert)
		if p.Kind != "certdiag-cert-profile" {
			t.Errorf("Kind = %q", p.Kind)
		}
		if p.Version != "1" {
			t.Errorf("Version = %q", p.Version)
		}
		if p.Name != "leaf.example.com" {
			t.Errorf("Name = %q", p.Name)
		}
		if p.Subject.CommonName != "leaf.example.com" {
			t.Errorf("CN = %q", p.Subject.CommonName)
		}
		if p.Subject.Organization != "TestOrg" {
			t.Errorf("O = %q", p.Subject.Organization)
		}
		if p.Subject.Country != "US" {
			t.Errorf("C = %q", p.Subject.Country)
		}
		if len(p.SANs.DNS) != 2 {
			t.Errorf("DNS count = %d, want 2", len(p.SANs.DNS))
		}
		if len(p.SANs.IPs) != 1 || p.SANs.IPs[0] != "10.0.0.1" {
			t.Errorf("IPs = %v", p.SANs.IPs)
		}
		if p.Key.Algorithm != "ecdsa" {
			t.Errorf("Algorithm = %q", p.Key.Algorithm)
		}
		if p.Key.Curve != "p256" {
			t.Errorf("Curve = %q", p.Key.Curve)
		}
		if p.Key.KeySize != 0 {
			t.Errorf("KeySize = %d, want 0 for ECDSA", p.Key.KeySize)
		}
		if p.Validity == nil || p.Validity.Days != 365 {
			t.Errorf("Days = %v", p.Validity)
		}
		if p.CA == nil || *p.CA != false {
			t.Error("expected CA = false")
		}
		if p.PathLength != nil {
			t.Errorf("PathLength = %v, want nil for leaf", p.PathLength)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KeyUsage = %v, missing digitalSignature", p.KeyUsage)
		}
		if !slices.Contains(p.KeyUsage, "keyEncipherment") {
			t.Errorf("KeyUsage = %v, missing keyEncipherment", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("ExtKeyUsage = %v, missing serverAuth", p.ExtKeyUsage)
		}
	})

	t.Run("CACert", func(t *testing.T) {
		cert, _ := mustCreateSelfSignedCA(t, ecKey)
		p := ProfileFromCert(cert)
		if p.CA == nil || *p.CA != true {
			t.Error("expected CA = true")
		}
		if p.PathLength == nil {
			t.Fatal("expected PathLength to be set for CA")
		}
		if *p.PathLength != -1 {
			t.Errorf("PathLength = %d, want -1", *p.PathLength)
		}
		if !slices.Contains(p.KeyUsage, "certSign") {
			t.Errorf("KeyUsage = %v, missing certSign", p.KeyUsage)
		}
	})

	t.Run("RSAKey", func(t *testing.T) {
		rsaKey := mustGenerateRSAKey(t)
		cert, _, err := CreateSelfSignedCert(rsaKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "rsa-test"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		p := ProfileFromCert(cert)
		if p.Key.Algorithm != "rsa" {
			t.Errorf("Algorithm = %q, want rsa", p.Key.Algorithm)
		}
		if p.Key.KeySize != 2048 {
			t.Errorf("KeySize = %d, want 2048", p.Key.KeySize)
		}
		if p.Key.Curve != "" {
			t.Errorf("Curve = %q, want empty for RSA", p.Key.Curve)
		}
	})

	t.Run("Ed25519Key", func(t *testing.T) {
		edKey := mustGenerateEd25519Key(t)
		cert, _, err := CreateSelfSignedCert(edKey, CertGenOptions{
			Subject: pkix.Name{CommonName: "ed-test"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		p := ProfileFromCert(cert)
		if p.Key.Algorithm != "ed25519" {
			t.Errorf("Algorithm = %q, want ed25519", p.Key.Algorithm)
		}
		if p.Key.KeySize != 0 {
			t.Errorf("KeySize = %d, want 0", p.Key.KeySize)
		}
		if p.Key.Curve != "" {
			t.Errorf("Curve = %q, want empty", p.Key.Curve)
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		cert, _, err := CreateSelfSignedCert(ecKey, CertGenOptions{
			Subject: pkix.Name{
				CommonName:   "roundtrip.example.com",
				Organization: []string{"RoundTrip"},
			},
			SANs:        SANList{DNSNames: []string{"roundtrip.example.com"}},
			Days:        730,
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			t.Fatal(err)
		}

		p := ProfileFromCert(cert)
		data, err := MarshalProfile(&p)
		if err != nil {
			t.Fatal(err)
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "roundtrip.yaml")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}

		loaded, err := LoadCertProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Subject.CommonName != "roundtrip.example.com" {
			t.Errorf("loaded CN = %q", loaded.Subject.CommonName)
		}
		if loaded.Validity == nil || loaded.Validity.Days != 730 {
			t.Errorf("loaded Days = %v", loaded.Validity)
		}
	})
}

func TestProfileFromCSR(t *testing.T) {
	ecKey := mustGenerateECKey(t)

	t.Run("BasicCSR", func(t *testing.T) {
		csr, _, err := CreateCSR(ecKey, CertGenOptions{
			Subject: pkix.Name{
				CommonName:   "csr.example.com",
				Organization: []string{"CSROrg"},
			},
			SANs: SANList{DNSNames: []string{"csr.example.com"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		p := ProfileFromCSR(csr)
		if p.Kind != "certdiag-cert-profile" {
			t.Errorf("Kind = %q", p.Kind)
		}
		if p.Subject.CommonName != "csr.example.com" {
			t.Errorf("CN = %q", p.Subject.CommonName)
		}
		if p.Subject.Organization != "CSROrg" {
			t.Errorf("O = %q", p.Subject.Organization)
		}
		if len(p.SANs.DNS) != 1 || p.SANs.DNS[0] != "csr.example.com" {
			t.Errorf("DNS = %v", p.SANs.DNS)
		}
		if p.Key.Algorithm != "ecdsa" {
			t.Errorf("Algorithm = %q", p.Key.Algorithm)
		}
		if p.Validity == nil || p.Validity.Days != 365 {
			t.Errorf("Days = %v, want 365 (leaf default)", p.Validity)
		}
		if p.CA == nil || *p.CA != false {
			t.Error("expected CA = false")
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KeyUsage = %v, missing digitalSignature", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("ExtKeyUsage = %v, missing serverAuth", p.ExtKeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "clientAuth") {
			t.Errorf("ExtKeyUsage = %v, missing clientAuth", p.ExtKeyUsage)
		}
	})
}

func TestProfileFromCertAs(t *testing.T) {
	ecKey := mustGenerateECKey(t)

	leafCert, _, err := CreateSelfSignedCert(ecKey, CertGenOptions{
		Subject: pkix.Name{
			CommonName:   "leaf.example.com",
			Organization: []string{"TestOrg"},
		},
		SANs:        SANList{DNSNames: []string{"leaf.example.com"}},
		Days:        365,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatal(err)
	}

	caCert, _ := mustCreateSelfSignedCA(t, ecKey)

	t.Run("CertFromLeaf", func(t *testing.T) {
		p := ProfileFromCertAs(leafCert, "cert")
		if p.CA == nil || *p.CA != false {
			t.Error("expected CA = false")
		}
		if p.Validity == nil || p.Validity.Days != 365 {
			t.Errorf("Validity = %v, want 365", p.Validity)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want digitalSignature (same-type)", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("EKU = %v, want serverAuth (same-type)", p.ExtKeyUsage)
		}
		if p.PathLength != nil {
			t.Errorf("PathLength = %v, want nil", p.PathLength)
		}
	})

	t.Run("CertFromCA", func(t *testing.T) {
		p := ProfileFromCertAs(caCert, "cert")
		if p.CA == nil || *p.CA != false {
			t.Error("expected CA = false")
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want leaf defaults (cross-type)", p.KeyUsage)
		}
		if !slices.Contains(p.KeyUsage, "keyEncipherment") {
			t.Errorf("KU = %v, want keyEncipherment (cross-type)", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("EKU = %v, want serverAuth (cross-type)", p.ExtKeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "clientAuth") {
			t.Errorf("EKU = %v, want clientAuth (cross-type)", p.ExtKeyUsage)
		}
		if p.PathLength != nil {
			t.Errorf("PathLength = %v, want nil", p.PathLength)
		}
	})

	t.Run("CAFromLeaf", func(t *testing.T) {
		p := ProfileFromCertAs(leafCert, "ca")
		if p.CA == nil || *p.CA != true {
			t.Error("expected CA = true")
		}
		if p.PathLength == nil || *p.PathLength != -1 {
			t.Errorf("PathLength = %v, want -1", p.PathLength)
		}
		if !slices.Contains(p.KeyUsage, "certSign") {
			t.Errorf("KU = %v, want certSign (cross-type CA defaults)", p.KeyUsage)
		}
		if !slices.Contains(p.KeyUsage, "crlSign") {
			t.Errorf("KU = %v, want crlSign (cross-type CA defaults)", p.KeyUsage)
		}
		if len(p.ExtKeyUsage) != 0 {
			t.Errorf("EKU = %v, want empty (CA defaults)", p.ExtKeyUsage)
		}
	})

	t.Run("CAFromCA", func(t *testing.T) {
		p := ProfileFromCertAs(caCert, "ca")
		if p.CA == nil || *p.CA != true {
			t.Error("expected CA = true")
		}
		if p.PathLength == nil {
			t.Fatal("expected PathLength set for CA-from-CA")
		}
		if !slices.Contains(p.KeyUsage, "certSign") {
			t.Errorf("KU = %v, want certSign (same-type)", p.KeyUsage)
		}
	})

	t.Run("CSRFromLeaf", func(t *testing.T) {
		p := ProfileFromCertAs(leafCert, "csr")
		if p.Validity != nil {
			t.Errorf("Validity = %v, want nil for CSR target", p.Validity)
		}
		if p.CA != nil {
			t.Errorf("CA = %v, want nil for CSR target", p.CA)
		}
		if p.PathLength != nil {
			t.Errorf("PathLength = %v, want nil for CSR target", p.PathLength)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want leaf defaults", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("EKU = %v, want leaf defaults", p.ExtKeyUsage)
		}
		if p.Subject.CommonName != "leaf.example.com" {
			t.Errorf("CN = %q, want preserved from source", p.Subject.CommonName)
		}
	})

	t.Run("CSRFromCA", func(t *testing.T) {
		p := ProfileFromCertAs(caCert, "csr")
		if p.Validity != nil {
			t.Errorf("Validity = %v, want nil for CSR target", p.Validity)
		}
		if p.CA != nil {
			t.Errorf("CA = %v, want nil for CSR target", p.CA)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want leaf defaults", p.KeyUsage)
		}
	})
}

func TestProfileFromCSRAs(t *testing.T) {
	ecKey := mustGenerateECKey(t)

	csr, _, err := CreateCSR(ecKey, CertGenOptions{
		Subject: pkix.Name{
			CommonName:   "req.example.com",
			Organization: []string{"ReqOrg"},
		},
		SANs: SANList{DNSNames: []string{"req.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("CertFromCSR", func(t *testing.T) {
		p := ProfileFromCSRAs(csr, "cert")
		if p.CA == nil || *p.CA != false {
			t.Error("expected CA = false")
		}
		if p.Validity == nil || p.Validity.Days != 365 {
			t.Errorf("Validity = %v, want 365", p.Validity)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want digitalSignature", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("EKU = %v, want serverAuth", p.ExtKeyUsage)
		}
	})

	t.Run("CAFromCSR", func(t *testing.T) {
		p := ProfileFromCSRAs(csr, "ca")
		if p.CA == nil || *p.CA != true {
			t.Error("expected CA = true")
		}
		if p.Validity == nil || p.Validity.Days != 3650 {
			t.Errorf("Validity = %v, want 3650", p.Validity)
		}
		if p.PathLength == nil || *p.PathLength != -1 {
			t.Errorf("PathLength = %v, want -1", p.PathLength)
		}
		if !slices.Contains(p.KeyUsage, "certSign") {
			t.Errorf("KU = %v, want certSign", p.KeyUsage)
		}
		if len(p.ExtKeyUsage) != 0 {
			t.Errorf("EKU = %v, want empty", p.ExtKeyUsage)
		}
	})

	t.Run("CSRFromCSR", func(t *testing.T) {
		p := ProfileFromCSRAs(csr, "csr")
		if p.Validity != nil {
			t.Errorf("Validity = %v, want nil for CSR target", p.Validity)
		}
		if p.CA != nil {
			t.Errorf("CA = %v, want nil for CSR target", p.CA)
		}
		if !slices.Contains(p.KeyUsage, "digitalSignature") {
			t.Errorf("KU = %v, want leaf defaults", p.KeyUsage)
		}
		if !slices.Contains(p.ExtKeyUsage, "serverAuth") {
			t.Errorf("EKU = %v, want serverAuth", p.ExtKeyUsage)
		}
		if p.Subject.CommonName != "req.example.com" {
			t.Errorf("CN = %q, want preserved from source", p.Subject.CommonName)
		}
	})
}

func TestCSRProfileMarshalOmitsValidityAndCA(t *testing.T) {
	ecKey := mustGenerateECKey(t)
	cert, _, err := CreateSelfSignedCert(ecKey, CertGenOptions{
		Subject: pkix.Name{CommonName: "test.example.com"},
		Days:    365,
	})
	if err != nil {
		t.Fatal(err)
	}

	p := ProfileFromCertAs(cert, "csr")
	data, err := MarshalProfile(&p)
	if err != nil {
		t.Fatal(err)
	}
	yaml := string(data)
	if strings.Contains(yaml, "validity:") {
		t.Error("CSR profile YAML should not contain validity:")
	}
	if strings.Contains(yaml, "ca:") {
		t.Error("CSR profile YAML should not contain ca:")
	}
}
