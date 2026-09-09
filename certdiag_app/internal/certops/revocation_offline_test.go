package certops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type countingFetcher struct{ calls int32 }

func (c *countingFetcher) Fetch(context.Context, string) ([]*x509.Certificate, error) {
	atomic.AddInt32(&c.calls, 1)
	return nil, errors.New("network is off in this test")
}

// TestComputeRevocation_CRLFileNeverTouchesTheNetwork guards M8: --crl-file is
// documented as offline, so a missing issuer must not trigger an AIA fetch.
func TestComputeRevocation_CRLFileNeverTouchesTheNetwork(t *testing.T) {
	fetcher := &countingFetcher{}
	orig := certlib.DefaultAIAFetcher
	certlib.DefaultAIAFetcher = fetcher
	t.Cleanup(func() { certlib.DefaultAIAFetcher = orig })

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.offline"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{"http://aia.offline.test/ca.der"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	// The issuer is deliberately not in the store, so only AIA could find it.
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/leaf.crt", Format: certlib.FormatPEM,
		Items: []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
	})

	computeRevocation(store, RevocationConfig{Enabled: true, Method: certlib.RevocationMethodCRLFile, CRLFile: "/nonexistent.crl"})
	if got := atomic.LoadInt32(&fetcher.calls); got != 0 {
		t.Errorf("crl_file is offline, yet the AIA fetcher was called %d times", got)
	}

	computeRevocation(store, RevocationConfig{Enabled: true, Method: certlib.RevocationMethodAuto})
	if got := atomic.LoadInt32(&fetcher.calls); got == 0 {
		t.Error("with the auto method a missing issuer is looked up over AIA (control case)")
	}
}
