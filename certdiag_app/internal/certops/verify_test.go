package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// verify used to hand a nil root pool to x509.Verify for the OS store, which
// routes to the platform verifier: a different engine from the TRUST column,
// with a different answer, and one that refuses to evaluate a CA at all. These
// tests pin the explicit-pool engine (M30a option A). They stub the OS store,
// so a platform call could never produce a passing result.

func verifyTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey, eku []x509.ExtKeyUsage) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           eku,
		DNSNames:              []string{cn},
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func writePEM(t *testing.T, dir, name string, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, c := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// osStoreWith returns verify options whose OS store is exactly these
// certificates and whose other readers cannot reach the machine.
func osStoreWith(certs ...*x509.Certificate) VerifyOptions {
	store := storeFixture("Stub OS Store", truststore.StoreTypeOS, "/stub", certs...)
	return VerifyOptions{
		StoreType:   truststore.StoreTypeOS,
		NoRealReads: true,
		Readers:     stubReaders([]truststore.StoreContents{store}, nil, nil),
	}
}

func TestVerify_OSStoreUsesExplicitPool(t *testing.T) {
	dir := t.TempDir()
	root, rootKey := verifyTestCert(t, "Verify Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	other, _ := verifyTestCert(t, "Other Root", true, nil, nil, nil)

	opts := osStoreWith(root)
	opts.Target = writePEM(t, dir, "chain.pem", leaf, root)
	got, err := Verify(opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.Result.Trusted {
		t.Errorf("a chain to a root in the store must verify: %v", got.Result.Reason)
	}

	unknown := osStoreWith(other)
	unknown.Target = writePEM(t, dir, "chain2.pem", leaf, root)
	got, err = Verify(unknown)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Result.Trusted {
		t.Error("a chain to a root the store does not hold must not verify")
	}
}

// TestVerify_OSStoreVerifiesCA is the proof the platform is out of the path:
// Security.framework rejects any CA evaluated as a leaf with "not standards
// compliant", so this input could not pass through the old engine.
func TestVerify_OSStoreVerifiesCA(t *testing.T) {
	dir := t.TempDir()
	root, rootKey := verifyTestCert(t, "CA Verify Root", true, nil, nil, nil)
	inter, _ := verifyTestCert(t, "CA Verify Intermediate", true, root, rootKey, nil)

	opts := osStoreWith(root)
	opts.Target = writePEM(t, dir, "inter.pem", inter)

	got, err := Verify(opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.Result.Trusted {
		t.Errorf("an intermediate under a trusted root must verify, got %q", got.Result.Reason)
	}
}

// TestVerifyChain_KeyUsageAny: a certificate issued for client auth is not
// untrusted, it is simply for a different purpose.
func TestVerifyChain_KeyUsageAny(t *testing.T) {
	dir := t.TempDir()
	root, rootKey := verifyTestCert(t, "EKU Root", true, nil, nil, nil)
	client, _ := verifyTestCert(t, "client.example", false, root, rootKey, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	opts := osStoreWith(root)
	opts.Target = writePEM(t, dir, "client.pem", client, root)

	got, err := Verify(opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.Result.Trusted {
		t.Errorf("a client-auth leaf under a trusted root must verify, got %q", got.Result.Reason)
	}
}

// TestVerify_NoOSStoreIsAnError: with nothing readable, verify says so instead
// of falling back to the platform and answering a different question.
func TestVerify_NoOSStoreIsAnError(t *testing.T) {
	dir := t.TempDir()
	root, rootKey := verifyTestCert(t, "Missing Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, nil)

	opts := VerifyOptions{
		StoreType:   truststore.StoreTypeOS,
		NoRealReads: true,
		Readers:     stubReaders(nil, nil, nil),
		Target:      writePEM(t, dir, "chain.pem", leaf, root),
	}
	if _, err := Verify(opts); err == nil {
		t.Error("an unreadable OS store must be an error, not a silent platform fallback")
	}
}

// TestCreateCert_RefusesOutOfScope: certdiag must not produce a certificate it
// would itself flag as invalid. x509.CreateCertificate does not check this, so
// the refusal has to be ours.
func TestCreateCert_RefusesOutOfScope(t *testing.T) {
	dir := t.TempDir()

	_, err := CreateCert(CreateCertOptions{
		Subject:         pkix.Name{CommonName: "Scoped CA"},
		WithKey:         true,
		KeyOptions:      certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
		IsCA:            true,
		PathLength:      -1,
		Days:            365,
		NameConstraints: certlib.NameConstraints{Critical: true, PermittedDNS: []string{"example.com"}},
		CertOutputPath:  filepath.Join(dir, "ca.crt"),
		KeyOutputPath:   filepath.Join(dir, "ca.key"),
		OutputFormat:    certlib.FormatPEM,
		Overwrite:       true,
	})
	if err != nil {
		t.Fatalf("creating the CA: %v", err)
	}
	caContainer, err := certlib.ReadFile(filepath.Join(dir, "ca.crt"), nil)
	if err != nil {
		t.Fatalf("reading the CA back: %v", err)
	}
	if got := caContainer.Items[0].Certificate.PermittedDNSDomains; len(got) != 1 {
		t.Fatalf("the CA must carry its constraints, got %v", got)
	}

	inScope := CreateCertOptions{
		Subject:        pkix.Name{CommonName: "ok.example.com"},
		SANs:           certlib.SANList{DNSNames: []string{"ok.example.com"}},
		WithKey:        true,
		KeyOptions:     certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"},
		SignerCertPath: filepath.Join(dir, "ca.crt"),
		SignerKeyPath:  filepath.Join(dir, "ca.key"),
		Days:           30,
		PathLength:     -1,
		CertOutputPath: filepath.Join(dir, "ok.crt"),
		KeyOutputPath:  filepath.Join(dir, "ok.key"),
		OutputFormat:   certlib.FormatPEM,
		Overwrite:      true,
	}
	if _, err := CreateCert(inScope); err != nil {
		t.Errorf("a name inside the constraint must be signed: %v", err)
	}

	outOfScope := inScope
	outOfScope.Subject = pkix.Name{CommonName: "bad.other.com"}
	outOfScope.SANs = certlib.SANList{DNSNames: []string{"bad.other.com"}}
	outOfScope.CertOutputPath = filepath.Join(dir, "bad.crt")
	outOfScope.KeyOutputPath = filepath.Join(dir, "bad.key")

	_, err = CreateCert(outOfScope)
	if err == nil {
		t.Fatal("a name outside the constraint must be refused")
	}
	if !strings.Contains(err.Error(), "bad.other.com") {
		t.Errorf("the refusal must name the offending name: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "bad.crt")); statErr == nil {
		t.Error("a refused certificate must not be written")
	}
}
