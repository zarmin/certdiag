package certlib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestCertAndKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func generateTestCA(t *testing.T, cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	parent := tmpl
	signKey := key
	if issuer != nil {
		parent = issuer
		signKey = issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func generateLeafSignedBy(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-client-leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func writePEMFile(t *testing.T, dir, name string, pemType string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	block := &pem.Block{Type: pemType, Bytes: data}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadClientCert_PEM(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	dir := t.TempDir()

	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writePEMFile(t, dir, "key.pem", "PRIVATE KEY", keyDER)

	tlsCert, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected certificate in result")
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("expected private key in result")
	}
}

func TestLoadClientCert_PEM_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-rsa-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", certDER)
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writePEMFile(t, dir, "key.pem", "PRIVATE KEY", keyDER)

	tlsCert, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestLoadClientCert_CertWithoutKey(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	dir := t.TempDir()
	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)

	_, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "--client-cert requires --client-key" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadClientCert_KeyWithoutCert(t *testing.T) {
	_, key := generateTestCertAndKey(t)
	dir := t.TempDir()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := writePEMFile(t, dir, "key.pem", "PRIVATE KEY", keyDER)

	_, err := LoadClientCert(ClientCertOptions{
		KeyPath: keyPath,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "--client-key requires --client-cert" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadClientCert_NoSource(t *testing.T) {
	_, err := LoadClientCert(ClientCertOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClientCert_CertFileNotFound(t *testing.T) {
	_, err := LoadClientCert(ClientCertOptions{
		CertPath: "/nonexistent/cert.pem",
		KeyPath:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClientCert_KeyFileNotFound(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	dir := t.TempDir()
	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)

	_, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
		KeyPath:  "/nonexistent/key.pem",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClientCert_MismatchedKeyAndCert(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	_, differentKey := generateTestCertAndKey(t) // different key
	dir := t.TempDir()

	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(differentKey)
	keyPath := writePEMFile(t, dir, "key.pem", "PRIVATE KEY", keyDER)

	// tls.X509KeyPair should catch this
	_, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err == nil {
		t.Fatal("expected error for mismatched key and cert")
	}
}

func TestVerifyKeyMatchesCert_Match(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	if err := verifyKeyMatchesCert(key, cert); err != nil {
		t.Errorf("expected match: %v", err)
	}
}

func TestVerifyKeyMatchesCert_Mismatch(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	_, differentKey := generateTestCertAndKey(t)
	if err := verifyKeyMatchesCert(differentKey, cert); err == nil {
		t.Error("expected mismatch error")
	}
}

func TestExtractClientCert_NoKey(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert},
		},
	}
	_, err := extractClientCert(container, "", "test.p12")
	if err == nil {
		t.Fatal("expected error for no key")
	}
}

func TestExtractClientCert_NoCert(t *testing.T) {
	_, key := generateTestCertAndKey(t)
	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentPrivateKey, PrivateKey: key},
		},
	}
	tlsCert, err := extractClientCert(container, "", "client.p12")
	if err == nil {
		t.Fatal("expected error for key-only container")
	}
	if !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("expected 'no certificate' error, got: %v", err)
	}
	if tlsCert.Certificate != nil || tlsCert.Leaf != nil {
		t.Error("expected empty tls.Certificate on error")
	}
}

func TestExtractClientCert_WithAlias(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert, Alias: "mycert"},
			{Type: ContentPrivateKey, PrivateKey: key, Alias: "mycert"},
			{Type: ContentCertificate, Certificate: cert, Alias: "other"},
		},
	}

	tlsCert, err := extractClientCert(container, "mycert", "test.p12")
	if err != nil {
		t.Fatalf("extractClientCert: %v", err)
	}
	if tlsCert.PrivateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestExtractClientCert_AliasNotFound(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert, Alias: "other"},
		},
	}

	_, err := extractClientCert(container, "nonexistent", "test.p12")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClientCert_P12_NotFound(t *testing.T) {
	_, err := LoadClientCert(ClientCertOptions{
		P12Path:  "/nonexistent/client.p12",
		Password: []byte("test"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadClientCert_JKS_NotFound(t *testing.T) {
	_, err := LoadClientCert(ClientCertOptions{
		JKSPath:  "/nonexistent/client.jks",
		Password: []byte("test"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExtractClientCert_IncludesIntermediates_CertItems(t *testing.T) {
	root, rootKey := generateTestCA(t, "test-root", nil, nil)
	inter, interKey := generateTestCA(t, "test-intermediate", root, rootKey)
	leaf, leafKey := generateLeafSignedBy(t, inter, interKey)

	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw},
			{Type: ContentCertificate, Certificate: inter, RawBytes: inter.Raw},
			{Type: ContentCertificate, Certificate: root, RawBytes: root.Raw},
			{Type: ContentPrivateKey, PrivateKey: leafKey},
		},
	}

	tlsCert, err := extractClientCert(container, "", "client.p12")
	if err != nil {
		t.Fatalf("extractClientCert: %v", err)
	}
	if len(tlsCert.Certificate) < 2 {
		t.Fatalf("expected leaf + intermediate, got %d certs", len(tlsCert.Certificate))
	}
	if !bytes.Equal(tlsCert.Certificate[0], leaf.Raw) {
		t.Error("leaf must be first in the wire chain")
	}
	if !containsDER(tlsCert.Certificate, inter.Raw) {
		t.Error("intermediate must be included in the wire chain")
	}
	if containsDER(tlsCert.Certificate, root.Raw) {
		t.Error("self-signed root must not be sent")
	}
}

func TestExtractClientCert_IncludesIntermediates_KeyChain(t *testing.T) {
	root, rootKey := generateTestCA(t, "test-root", nil, nil)
	inter, interKey := generateTestCA(t, "test-intermediate", root, rootKey)
	leaf, leafKey := generateLeafSignedBy(t, inter, interKey)

	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw, Alias: "client"},
			{Type: ContentPrivateKey, PrivateKey: leafKey, Alias: "client", Chain: [][]byte{inter.Raw, root.Raw}},
		},
	}

	tlsCert, err := extractClientCert(container, "", "client.jks")
	if err != nil {
		t.Fatalf("extractClientCert: %v", err)
	}
	if len(tlsCert.Certificate) < 2 {
		t.Fatalf("expected leaf + intermediate, got %d certs", len(tlsCert.Certificate))
	}
	if !bytes.Equal(tlsCert.Certificate[0], leaf.Raw) {
		t.Error("leaf must be first in the wire chain")
	}
	if !containsDER(tlsCert.Certificate, inter.Raw) {
		t.Error("intermediate from key chain must be included")
	}
	if containsDER(tlsCert.Certificate, root.Raw) {
		t.Error("self-signed root from key chain must not be sent")
	}
}

func TestExtractClientCert_LeafOnly(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	container := &CertContainer{
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert, RawBytes: cert.Raw},
			{Type: ContentPrivateKey, PrivateKey: key},
		},
	}

	tlsCert, err := extractClientCert(container, "", "client.p12")
	if err != nil {
		t.Fatalf("extractClientCert: %v", err)
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("expected single-cert chain, got %d", len(tlsCert.Certificate))
	}
	if !bytes.Equal(tlsCert.Certificate[0], cert.Raw) {
		t.Error("self-signed leaf must still be sent")
	}
}

func containsDER(chain [][]byte, der []byte) bool {
	for _, c := range chain {
		if bytes.Equal(c, der) {
			return true
		}
	}
	return false
}

func TestLoadClientCert_UsedInTLSConfig(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	dir := t.TempDir()

	certPath := writePEMFile(t, dir, "cert.pem", "CERTIFICATE", cert.Raw)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := writePEMFile(t, dir, "key.pem", "PRIVATE KEY", keyDER)

	tlsCert, err := LoadClientCert(ClientCertOptions{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify the cert can be used in a tls.Config
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	if len(config.Certificates) != 1 {
		t.Fatal("expected 1 certificate in config")
	}
}
