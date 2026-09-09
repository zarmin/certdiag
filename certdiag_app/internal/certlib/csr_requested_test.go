package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

func csrWithExtensions(t *testing.T, exts []pkix.Extension) *x509.CertificateRequest {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "req.test"},
		ExtraExtensions: exts,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestCSRRequestedExtensions decodes what a CSR asked for (M31 M4).
func TestCSRRequestedExtensions(t *testing.T) {
	ku, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}) // digitalSignature only
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // clientAuth
		{1, 2, 3, 4},                // unknown
	})
	bc, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: true})
	csr := csrWithExtensions(t, []pkix.Extension{
		{Id: extensions.OIDKeyUsage, Value: ku},
		{Id: extensions.OIDExtKeyUsage, Value: eku},
		{Id: extensions.OIDBasicConstraints, Value: bc},
	})

	req := CSRRequestedExtensions(csr)
	if !req.HasKeyUsage || req.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %v (has %v), want digitalSignature", req.KeyUsage, req.HasKeyUsage)
	}
	if !req.HasExtKeyUsage || len(req.ExtKeyUsage) != 1 || req.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ext key usage = %v, want [clientAuth]", req.ExtKeyUsage)
	}
	if len(req.UnknownExtKeyUsage) != 1 || req.UnknownExtKeyUsage[0] != "1.2.3.4" {
		t.Errorf("unknown EKU = %v, want [1.2.3.4]", req.UnknownExtKeyUsage)
	}
	if !req.HasBasicConstraints || !req.IsCA {
		t.Errorf("basic constraints: has=%v isCA=%v, want a CA request", req.HasBasicConstraints, req.IsCA)
	}

	plain := CSRRequestedExtensions(csrWithExtensions(t, nil))
	if plain.HasKeyUsage || plain.HasExtKeyUsage || plain.HasBasicConstraints {
		t.Errorf("a CSR without extensionRequest must report nothing requested: %+v", plain)
	}
}
