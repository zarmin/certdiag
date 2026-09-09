package certops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

// TestCSRRequestNotes says where the issued certificate departs from the CSR
// (M31 M4) and stays silent when they agree.
func TestCSRRequestNotes(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 2}})
	bc, _ := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: true})
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client.test"},
		ExtraExtensions: []pkix.Extension{
			{Id: extensions.OIDExtKeyUsage, Value: eku},
			{Id: extensions.OIDBasicConstraints, Value: bc},
		},
	}, key)
	csr, _ := x509.ParseCertificateRequest(der)

	notes := csrRequestNotes(csr, x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, false)
	joined := strings.Join(notes, "\n")
	if len(notes) != 2 {
		t.Fatalf("want two notes (CA and EKU), got %v", notes)
	}
	if !strings.Contains(joined, "requests a CA certificate, issuing a leaf") {
		t.Errorf("missing the CA note: %v", notes)
	}
	if !strings.Contains(joined, "clientAuth, issuing serverAuth,clientAuth") && !strings.Contains(joined, "clientAuth, issuing") {
		t.Errorf("missing the EKU note: %v", notes)
	}

	agree := csrRequestNotes(csr, x509.KeyUsageCertSign, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true)
	if len(agree) != 0 {
		t.Errorf("no note expected when the issued cert matches the request, got %v", agree)
	}
}
