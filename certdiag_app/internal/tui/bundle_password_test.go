package tui

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

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func bundleEncP12(t *testing.T, path, pw string) {
	t.Helper()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDer, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDer)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	leafDer, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDer)

	p12, err := certlib.EncodePKCS12([]certlib.CertItem{
		{Type: certlib.ContentPrivateKey, PrivateKey: leafKey},
		{Type: certlib.ContentCertificate, Certificate: leafCert, RawBytes: leafCert.Raw},
		{Type: certlib.ContentCertificate, Certificate: caCert, RawBytes: caCert.Raw},
	}, []byte(pw), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, p12, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestSubmitBundle_UsesPasswordCache verifies the fix: submitBundle now receives
// the session password cache, so bundling an encrypted PKCS#12 input succeeds.
func TestSubmitBundle_UsesPasswordCache(t *testing.T) {
	dir := t.TempDir()
	p12 := filepath.Join(dir, "enc.p12")
	bundleEncP12(t, p12, "secret123")
	out := filepath.Join(dir, "bundle.pem")

	form := buildBundleForm(dir, nil, []string{p12})
	form.fieldByName("output").SetValue(out)

	// With the cache: succeeds.
	cmd := submitBundle(form, true, []certlib.TaggedPassword{{Password: []byte("secret123")}})
	msg := cmd()
	res, ok := msg.(FormResultMsg)
	if !ok {
		t.Fatalf("unexpected msg type %T", msg)
	}
	if res.Err != nil {
		t.Fatalf("bundle with cached password should succeed, got: %v", res.Err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("bundle output not written: %v", err)
	}
	t.Log("bundle succeeded with cached password")

	// Without the cache (empty): fails - proves the cache is what makes it work.
	os.Remove(out)
	form2 := buildBundleForm(dir, nil, []string{p12})
	form2.fieldByName("output").SetValue(out)
	msg2 := submitBundle(form2, true, nil)()
	if r, ok := msg2.(FormResultMsg); ok && r.Err == nil {
		t.Error("expected bundle to fail without the password cache")
	}
}
