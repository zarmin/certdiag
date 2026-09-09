package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func TestFetchAIAIntermediates_NilCert(t *testing.T) {
	certs, err := FetchAIAIntermediates(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Error("expected no certs for nil input")
	}
}

func TestFetchAIAIntermediates_NoURLs(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "no-aia"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	certs, err := FetchAIAIntermediates(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Error("expected no certs when no AIA URLs")
	}
}

func TestFetchAIAIntermediates_DER(t *testing.T) {
	// Create an intermediate cert to serve
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intermTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		Issuer:                pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermDER, _ := x509.CreateCertificate(rand.Reader, intermTmpl, intermTmpl, &key.PublicKey, key)

	// Serve the intermediate via HTTP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(intermDER)
	}))
	defer ts.Close()

	// Create a leaf cert with AIA pointing to our test server
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{ts.URL},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intermTmpl, &key.PublicKey, key)
	leafCert, _ := x509.ParseCertificate(leafDER)

	certs, err := FetchAIAIntermediates(leafCert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("expected to fetch intermediate cert")
	}
	if certs[0].Subject.CommonName != "Test Intermediate" {
		t.Errorf("expected 'Test Intermediate', got %q", certs[0].Subject.CommonName)
	}
}

func TestFetchAIAIntermediates_PKCS7(t *testing.T) {
	// Create a CA cert to serve as a PKCS#7 (.p7c) bundle
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Test P7C CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	p7cDER, err := pkcs7.DegenerateCertificate(caCert.Raw)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkcs7-mime")
		w.Write(p7cDER)
	}))
	defer ts.Close()

	// Leaf signed by the CA, pointing at the p7c URL
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.p7c.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{ts.URL},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	certs, err := FetchAIAIntermediates(leafCert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("expected to fetch CA cert from PKCS#7 bundle")
	}
	if certs[0].Subject.CommonName != "Test P7C CA" {
		t.Errorf("expected 'Test P7C CA', got %q", certs[0].Subject.CommonName)
	}
}

func TestFetchAIAIntermediates_NonIssuerSkipped(t *testing.T) {
	// The real CA that signs the leaf
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "Real CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// A different, unrelated cert served by the AIA endpoint
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	otherTmpl := &x509.Certificate{
		SerialNumber:          otherSerial,
		Subject:               pkix.Name{CommonName: "Impostor CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Write(otherDER)
	}))
	defer ts.Close()

	// Leaf actually signed by caCert, but AIA points at the impostor
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.impostor.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{ts.URL},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	certs, err := FetchAIAIntermediates(leafCert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Errorf("expected non-issuer cert to be skipped, got %d certs", len(certs))
	}
}

func TestFetchAIAIntermediates_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IssuingCertificateURL: []string{ts.URL},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	certs, _ := FetchAIAIntermediates(cert)
	if len(certs) != 0 {
		t.Error("expected no certs on server error")
	}
}
