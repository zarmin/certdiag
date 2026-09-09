package output

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestFormatKeyAlgo(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	ecKey := mustGenECKey(t)
	edKey := mustGenEd25519Key(t)

	tests := []struct {
		name string
		key  interface{}
		want string
	}{
		{"RSA", &rsaKey.PublicKey, "RSA-2048"},
		{"ECDSA", &ecKey.PublicKey, "ECDSA-P-256"},
		{"Ed25519", edKey.Public(), "Ed25519"},
		{"nil", nil, "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatKeyAlgo(tt.key)
			if got != tt.want {
				t.Errorf("FormatKeyAlgo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatPrivateKeyAlgo(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	ecKey := mustGenECKey(t)
	edKey := mustGenEd25519Key(t)

	tests := []struct {
		name string
		key  interface{}
		want string
	}{
		{"RSA", rsaKey, "RSA-2048"},
		{"ECDSA", ecKey, "ECDSA-P-256"},
		{"Ed25519", edKey, "Ed25519"},
		{"nil", nil, "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatPrivateKeyAlgo(tt.key)
			if got != tt.want {
				t.Errorf("FormatPrivateKeyAlgo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatSubject(t *testing.T) {
	withCN := &x509.Certificate{
		Subject: pkix.Name{CommonName: "example.com", Organization: []string{"Org"}},
	}

	t.Run("with CN", func(t *testing.T) {
		got := FormatSubject(withCN)
		if got != "example.com" {
			t.Errorf("FormatSubject() = %q, want %q", got, "example.com")
		}
	})

	t.Run("without CN falls back to DN", func(t *testing.T) {
		rsaKey := mustGenRSAKey(t)
		// Use CreateSelfSignedCert so Names field is populated properly
		cert, _, err := certlib.CreateSelfSignedCert(rsaKey, certlib.CertGenOptions{
			Subject: pkix.Name{Organization: []string{"Test Org"}, Country: []string{"US"}},
			IsCA:    true,
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		got := FormatSubject(cert)
		if got == "" {
			t.Error("FormatSubject() returned empty for cert without CN")
		}
	})
}

func TestFormatSubjectDN(t *testing.T) {
	// Use a real parsed cert so Names field is populated
	rsaKey := mustGenRSAKey(t)
	cert, _, err := certlib.CreateSelfSignedCert(rsaKey, certlib.CertGenOptions{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		IsCA: true,
		Days: 365,
	})
	if err != nil {
		t.Fatal(err)
	}
	dn := certlib.FormatDNName(cert.Subject)

	t.Run("no truncation", func(t *testing.T) {
		got := FormatSubjectDN(cert, 0)
		if got != dn {
			t.Errorf("FormatSubjectDN(0) = %q, want %q", got, dn)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		got := FormatSubjectDN(cert, 10)
		if len(got) != 10 {
			t.Errorf("FormatSubjectDN(10) len = %d, want 10", len(got))
		}
		if got[len(got)-3:] != "..." {
			t.Errorf("FormatSubjectDN(10) should end with '...', got %q", got)
		}
	})

	t.Run("longer than DN", func(t *testing.T) {
		got := FormatSubjectDN(cert, 500)
		if got != dn {
			t.Errorf("FormatSubjectDN(500) = %q, want %q", got, dn)
		}
	})
}

func TestFormatIssuer(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	selfSigned := mustSelfSignedCert(t, rsaKey)

	leafKey := mustGenRSAKey(t)
	leaf := mustLeafCert(t, leafKey, selfSigned, rsaKey)

	t.Run("self-signed", func(t *testing.T) {
		got := FormatIssuer(selfSigned)
		if got != "Self-signed" {
			t.Errorf("FormatIssuer() = %q, want %q", got, "Self-signed")
		}
	})

	t.Run("issuer with CN", func(t *testing.T) {
		got := FormatIssuer(leaf)
		if got != "Test CA" {
			t.Errorf("FormatIssuer() = %q, want %q", got, "Test CA")
		}
	})

	t.Run("issuer without CN", func(t *testing.T) {
		// Create a CA without CN so we get the full DN fallback
		noCNKey := mustGenRSAKey(t)
		noCNCa, _, err := certlib.CreateSelfSignedCert(noCNKey, certlib.CertGenOptions{
			Subject: pkix.Name{Organization: []string{"Issuer Org"}, Country: []string{"DE"}},
			IsCA:    true,
			Days:    365,
		})
		if err != nil {
			t.Fatal(err)
		}
		leafKey2 := mustGenRSAKey(t)
		noCNLeaf := mustLeafCert(t, leafKey2, noCNCa, noCNKey)
		got := FormatIssuer(noCNLeaf)
		if got == "" || got == "Self-signed" {
			t.Errorf("FormatIssuer() = %q, want full DN", got)
		}
	})
}

func TestFormatSANs(t *testing.T) {
	rsaKey := mustGenRSAKey(t)
	caKey := mustGenRSAKey(t)
	caCert := mustSelfSignedCert(t, caKey)
	leaf := mustLeafCert(t, rsaKey, caCert, caKey)

	t.Run("with DNS SANs", func(t *testing.T) {
		got := FormatSANs(leaf)
		if got == "" {
			t.Error("FormatSANs() returned empty for cert with SANs")
		}
	})

	t.Run("no SANs", func(t *testing.T) {
		noSANs := &x509.Certificate{}
		got := FormatSANs(noSANs)
		if got != "" {
			t.Errorf("FormatSANs() = %q, want empty", got)
		}
	})
}

func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		name string
		n    int64
		want string
	}{
		{"zero", 0, "0 B"},
		{"bytes", 512, "512 B"},
		{"KB", 1024, "1.0 KB"},
		{"MB", 1572864, "1.5 MB"},
		{"GB", 2147483648, "2.0 GB"},
		{"KB boundary", 1023, "1023 B"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatFileSize(tt.n)
			if got != tt.want {
				t.Errorf("FormatFileSize(%d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}

func TestFormatContentType(t *testing.T) {
	tests := []struct {
		name   string
		item   certlib.CertItem
		format certlib.FileFormat
		want   string
	}{
		{"cert", certlib.CertItem{Type: certlib.ContentCertificate}, certlib.FormatPEM, "pem/cert"},
		{"key", certlib.CertItem{Type: certlib.ContentPrivateKey}, certlib.FormatPKCS12, "pkcs12/key"},
		{"pubkey", certlib.CertItem{Type: certlib.ContentPublicKey}, certlib.FormatDER, "der/pubkey"},
		{"csr", certlib.CertItem{Type: certlib.ContentCSR}, certlib.FormatPEM, "pem/csr"},
		{"unknown", certlib.CertItem{Type: "something"}, certlib.FormatPEM, "pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatContentType(&tt.item, tt.format)
			if got != tt.want {
				t.Errorf("FormatContentType() = %q, want %q", got, tt.want)
			}
		})
	}
}
