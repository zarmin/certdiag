package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func caSignedBy(t *testing.T, cn string, serial int64, parentKey *rsa.PrivateKey, parent *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	signKey, signCert := key, tmpl
	if parentKey != nil {
		signKey, signCert = parentKey, parent
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, signCert, &key.PublicKey, signKey)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// TestConvert_JKSToPKCS7PreservesChain is the convert-path regression for the
// PKCS#7 chain fix: the conversion matrix drops the key item for cert-only
// formats, so the intermediates carried on the key entry's chain must be
// materialized (ExpandKeyChains) before that drop, or JKS->P7B loses them.
func TestConvert_JKSToPKCS7PreservesChain(t *testing.T) {
	dir := t.TempDir()
	rootKey, rootCert := caSignedBy(t, "chain-root", 1, nil, nil)
	interKey, interCert := caSignedBy(t, "chain-inter", 2, rootKey, rootCert)
	leafKey, leafCert := jksTestLeaf(t, "chain-leaf", 3, interKey, interCert)

	// A JKS whose PrivateKeyEntry carries leaf->inter->root.
	items := []certlib.CertItem{
		{Type: certlib.ContentPrivateKey, Alias: "k", PrivateKey: leafKey, EntryPassword: []byte("pw")},
		{Type: certlib.ContentCertificate, Alias: "leaf", Certificate: leafCert, RawBytes: leafCert.Raw},
		{Type: certlib.ContentCertificate, Alias: "inter", Certificate: interCert, RawBytes: interCert.Raw},
		{Type: certlib.ContentCertificate, Alias: "root", Certificate: rootCert, RawBytes: rootCert.Raw},
	}
	enc, err := certlib.EncodeJKS(items, []byte("pw"), map[int]string{0: "k", 1: "leaf", 2: "inter", 3: "root"})
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	jksPath := filepath.Join(dir, "chain.jks")
	if err := os.WriteFile(jksPath, enc, 0600); err != nil {
		t.Fatal(err)
	}

	outP7B := filepath.Join(dir, "out.p7b")
	if _, err := Convert(ConvertOptions{
		InputPath:      jksPath,
		InputPasswords: []certlib.TaggedPassword{{Password: []byte("pw")}},
		OutputPath:     outP7B,
		OutputFormat:   certlib.FormatPKCS7,
	}); err != nil {
		t.Fatalf("Convert: %v", err)
	}

	data, err := os.ReadFile(outP7B)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := pkcs7.Parse(data)
	if err != nil {
		t.Fatalf("parse PKCS#7: %v", err)
	}
	got := map[string]bool{}
	for _, c := range parsed.Certificates {
		got[c.Subject.CommonName] = true
	}
	for _, cn := range []string{"chain-leaf", "chain-inter", "chain-root"} {
		if !got[cn] {
			t.Errorf("JKS->PKCS#7 dropped %q; got %v", cn, got)
		}
	}
}
