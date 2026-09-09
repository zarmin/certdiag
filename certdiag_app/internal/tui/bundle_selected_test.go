package tui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	return c
}

// TestBuildBundleOptions_CarriesSelectedItems verifies the bundle form passes the
// exact selected items into BundleOptions.InputItems (not just deduped paths).
func TestBuildBundleOptions_CarriesSelectedItems(t *testing.T) {
	certA := selfSigned(t, "a")
	certB := selfSigned(t, "b")
	cont := &certlib.CertContainer{FilePath: "/tmp/multi.pem"}
	// Two items in the same file; only one is "selected".
	itemB := certlib.CertItem{Type: certlib.ContentCertificate, Certificate: certB, RawBytes: certB.Raw}
	nodes := []TreeNode{
		{Container: cont, ItemIdx: 1, Subject: "CN=b", ContentType: "pem/cert", Item: &itemB},
	}
	form := buildBundleForm("/tmp", nodes, []string{"/tmp/multi.pem"})

	opts, err := buildBundleOptions(form)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.InputItems) != 1 {
		t.Fatalf("expected 1 selected InputItem, got %d", len(opts.InputItems))
	}
	if opts.InputItems[0].Certificate.Subject.CommonName != "b" {
		t.Errorf("wrong item carried: %s", opts.InputItems[0].Certificate.Subject.CommonName)
	}
	_ = certA
}
