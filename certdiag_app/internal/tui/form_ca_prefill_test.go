package tui

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestCertForm_CAPrefillKeepsKUAndEKU(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "ca.example.com"},
		IsCA:        true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	wantKU := certlib.FormatKeyUsageInternal(cert.KeyUsage)
	wantEKU := certlib.FormatExtKeyUsageInternal(cert.ExtKeyUsage)

	if wantKU == kuDefaultCA {
		t.Fatalf("precondition: source KU must differ from generic CA default")
	}
	if wantEKU == "" {
		t.Fatalf("precondition: source EKU must be non-empty")
	}

	node := &TreeNode{Item: &certlib.CertItem{Certificate: cert}}
	f := buildCreateCertForm("/tmp", node, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365, 3650)
	f.evaluateVisibility()

	if got := f.fieldByName("cert_type").Value(); got != labelCA {
		t.Fatalf("cert_type = %q, want %q", got, labelCA)
	}
	if got := f.fieldByName("key_usage").Value(); got != wantKU {
		t.Errorf("key_usage = %q, want prefilled %q (clobbered by CA default?)", got, wantKU)
	}
	if got := f.fieldByName("ext_key_usage").Value(); got != wantEKU {
		t.Errorf("ext_key_usage = %q, want prefilled %q (clobbered by CA default?)", got, wantEKU)
	}
}

func TestCertForm_InteractiveCATypeAppliesDefaults(t *testing.T) {
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365, 3650)

	if got := f.fieldByName("key_usage").Value(); got != kuDefaultLeaf {
		t.Fatalf("precondition: leaf KU = %q, want %q", got, kuDefaultLeaf)
	}

	f.fieldByName("cert_type").SetValue(labelCA)
	f.evaluateVisibility()

	if got := f.fieldByName("key_usage").Value(); got != kuDefaultCA {
		t.Errorf("key_usage = %q, want CA default %q", got, kuDefaultCA)
	}
	if got := f.fieldByName("ext_key_usage").Value(); got != "" {
		t.Errorf("ext_key_usage = %q, want CA default (empty)", got)
	}
}
