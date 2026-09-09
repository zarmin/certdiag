package certlib

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

type zeroThenRandReader struct {
	zeros int
}

func (r *zeroThenRandReader) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		n := len(p)
		if n > r.zeros {
			n = r.zeros
		}
		for i := 0; i < n; i++ {
			p[i] = 0
		}
		r.zeros -= n
		return n, nil
	}
	return rand.Reader.Read(p)
}

func TestGenerateSerialPositive(t *testing.T) {
	t.Run("GeneratedCerts", func(t *testing.T) {
		key := mustGenerateECKey(t)
		for i := 0; i < 50; i++ {
			cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
				Subject: pkix.Name{CommonName: "serial-positive"},
				Days:    365,
			})
			if err != nil {
				t.Fatal(err)
			}
			if cert.SerialNumber.Sign() <= 0 {
				t.Fatalf("serial not positive: %s", cert.SerialNumber)
			}
		}
	})

	t.Run("RetriesOnZero", func(t *testing.T) {
		serial, err := generateSerial(&zeroThenRandReader{zeros: 16})
		if err != nil {
			t.Fatal(err)
		}
		if serial.Sign() <= 0 {
			t.Fatalf("expected positive serial after retry, got %s", serial)
		}
	})
}

func TestCreateCertBackdatesNotBefore(t *testing.T) {
	key := mustGenerateECKey(t)
	before := time.Now()
	cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
		Subject: pkix.Name{CommonName: "backdate"},
		Days:    365,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !cert.NotBefore.Before(before) {
		t.Errorf("NotBefore %v not backdated before creation time %v", cert.NotBefore, before)
	}

	skew := before.Sub(cert.NotBefore)
	if skew < clockSkewBackdate-time.Minute || skew > clockSkewBackdate+time.Minute {
		t.Errorf("backdate = %v, want ~%v", skew, clockSkewBackdate)
	}

	wantAfter := before.Add(365 * 24 * time.Hour)
	if diff := cert.NotAfter.Sub(wantAfter); diff < -time.Minute || diff > time.Minute {
		t.Errorf("NotAfter = %v, want ~%v (validity not shortened by skew)", cert.NotAfter, wantAfter)
	}

	if validity := cert.NotAfter.Sub(cert.NotBefore); validity < 365*24*time.Hour {
		t.Errorf("validity %v shorter than %d days", validity, 365)
	}
}

func TestCreateSelfSignedCert(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key := mustGenerateRSAKey(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "rsa-test"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != cert.Issuer.CommonName {
			t.Error("subject != issuer for self-signed cert")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "ec-test"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != cert.Issuer.CommonName {
			t.Error("subject != issuer for self-signed cert")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		key := mustGenerateEd25519Key(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "ed-test"},
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != cert.Issuer.CommonName {
			t.Error("subject != issuer for self-signed cert")
		}
	})

	t.Run("WithSANs", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "san-test"},
			SANs: SANList{
				DNSNames:    []string{"example.com", "www.example.com"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
			},
			Days: 365,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.DNSNames) != 2 {
			t.Errorf("DNS SANs count = %d, want 2", len(cert.DNSNames))
		}
		if len(cert.IPAddresses) != 1 {
			t.Errorf("IP SANs count = %d, want 1", len(cert.IPAddresses))
		}
	})

	t.Run("CAMode", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "ca-test"},
			Days:       365,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			PathLength: -1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !cert.IsCA {
			t.Error("expected IsCA = true")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Error("expected KeyUsageCertSign")
		}
	})

	t.Run("PathLengthZero", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "pathlen-test"},
			Days:       365,
			IsCA:       true,
			KeyUsage:   x509.KeyUsageCertSign,
			PathLength: 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !cert.MaxPathLenZero {
			t.Error("expected MaxPathLenZero = true")
		}
	})
}

func TestCreateCertSetsSKID(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _, err := CreateSelfSignedCert(key, CertGenOptions{
		Subject: pkix.Name{CommonName: "skid-test"},
		Days:    365,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Fatal("SubjectKeyId not set")
	}
	want, err := computeSKID(publicKey(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.SubjectKeyId, want) {
		t.Errorf("SubjectKeyId = %x, want %x", cert.SubjectKeyId, want)
	}
}

func TestBuildTemplatePropagatesSKIDError(t *testing.T) {
	_, err := buildTemplate("not-a-public-key", CertGenOptions{
		Subject: pkix.Name{CommonName: "skid-err"},
		Days:    365,
	})
	if err == nil {
		t.Fatal("expected error from computeSKID, got nil")
	}
}

func TestCreateSignedCert(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	t.Run("IssuerMatchesCA", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "leaf"},
			Days:       365,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Issuer.CommonName != caCert.Subject.CommonName {
			t.Errorf("issuer CN = %q, want %q", cert.Issuer.CommonName, caCert.Subject.CommonName)
		}
	})

	t.Run("UniqueSerials", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert1, _, err := CreateSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "leaf1"},
			Days:       365,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		cert2, _, err := CreateSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "leaf2"},
			Days:       365,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert1.SerialNumber.Cmp(cert2.SerialNumber) == 0 {
			t.Error("two certs have the same serial")
		}
	})

	t.Run("CustomDays", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSignedCert(key, CertGenOptions{
			Subject:    pkix.Name{CommonName: "custom-days"},
			Days:       730,
			SignerCert: caCert,
			SignerKey:  caKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		diff := cert.NotAfter.Sub(cert.NotBefore)
		actualDays := int(diff.Hours() / 24)
		if actualDays != 730 {
			t.Errorf("validity days = %d, want 730", actualDays)
		}
	})

	t.Run("CustomKeyUsage", func(t *testing.T) {
		key := mustGenerateECKey(t)
		cert, _, err := CreateSignedCert(key, CertGenOptions{
			Subject:     pkix.Name{CommonName: "ku-test"},
			Days:        365,
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			SignerCert:  caCert,
			SignerKey:   caKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			t.Error("expected KeyUsageDigitalSignature")
		}
		if len(cert.ExtKeyUsage) != 2 {
			t.Errorf("ExtKeyUsage count = %d, want 2", len(cert.ExtKeyUsage))
		}
	})
}

func TestCreateCSR(t *testing.T) {
	t.Run("SubjectAndSANs", func(t *testing.T) {
		key := mustGenerateECKey(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "csr-test.local", Organization: []string{"Org"}},
			SANs: SANList{
				DNSNames: []string{"csr-test.local", "www.csr-test.local"},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if csr.Subject.CommonName != "csr-test.local" {
			t.Errorf("CSR CN = %q, want %q", csr.Subject.CommonName, "csr-test.local")
		}
		if len(csr.DNSNames) != 2 {
			t.Errorf("CSR DNS count = %d, want 2", len(csr.DNSNames))
		}
	})

	t.Run("ValidSignature", func(t *testing.T) {
		key := mustGenerateECKey(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "sig-test"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("CSR signature invalid: %v", err)
		}
	})

	t.Run("Ed25519Key", func(t *testing.T) {
		key := mustGenerateEd25519Key(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "ed-csr"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatalf("Ed25519 CSR signature invalid: %v", err)
		}
	})
}

func TestSignCSR(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	t.Run("SubjectFromCSR", func(t *testing.T) {
		key := mustGenerateECKey(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "sign-test.local"},
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, _, err := SignCSR(csr, caKey, caCert, CertGenOptions{Days: 365})
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != "sign-test.local" {
			t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "sign-test.local")
		}
	})

	t.Run("SANsPreserved", func(t *testing.T) {
		key := mustGenerateECKey(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "san-sign"},
			SANs: SANList{
				DNSNames:    []string{"san-sign.local"},
				IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, _, err := SignCSR(csr, caKey, caCert, CertGenOptions{Days: 365})
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "san-sign.local" {
			t.Errorf("DNS SANs = %v, want [san-sign.local]", cert.DNSNames)
		}
		if len(cert.IPAddresses) != 1 {
			t.Errorf("IP SANs count = %d, want 1", len(cert.IPAddresses))
		}
	})

	t.Run("CustomKU", func(t *testing.T) {
		key := mustGenerateECKey(t)
		csr, _, err := CreateCSR(key, CertGenOptions{
			Subject: pkix.Name{CommonName: "ku-sign"},
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, _, err := SignCSR(csr, caKey, caCert, CertGenOptions{
			Days:     365,
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
			t.Error("expected KeyUsageContentCommitment on signed cert")
		}
	})
}
