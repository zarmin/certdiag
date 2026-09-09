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
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

func namedSelfSignedCA(t *testing.T, cn string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func readBundleCNs(t *testing.T, path string) []string {
	t.Helper()
	c, err := certlib.ReadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cns []string
	for _, it := range c.Items {
		if it.Type == certlib.ContentCertificate && it.Certificate != nil {
			cns = append(cns, it.Certificate.Subject.CommonName)
		}
	}
	return cns
}

// (A) The no-chain fallback path must honor IncludeRoot=false: a self-signed
// root present in the scanned directory must NOT leak into the bundle when
// IncludeRoot is false, and must be kept when IncludeRoot is true.
func TestBundle_FallbackHonorsIncludeRoot(t *testing.T) {
	dir := t.TempDir()

	// A self-signed root, and an orphan leaf whose issuing CA is absent from the
	// directory -> no chain can be assembled, so the fallback path fires.
	root := namedSelfSignedCA(t, "fallback-root", 100)
	absentCAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	absentCATmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: "absent-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	absentCADER, err := x509.CreateCertificate(rand.Reader, absentCATmpl, absentCATmpl, &absentCAKey.PublicKey, absentCAKey)
	if err != nil {
		t.Fatal(err)
	}
	absentCA, _ := x509.ParseCertificate(absentCADER)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(300), Subject: pkix.Name{CommonName: "orphan-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, absentCA, &leafKey.PublicKey, absentCAKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)

	writeCertPEM(t, filepath.Join(dir, "root.pem"), root)
	writeCertPEM(t, filepath.Join(dir, "leaf.pem"), leaf)

	// IncludeRoot=false -> root excluded
	outNoRoot := filepath.Join(dir, "no-root.pem")
	res, err := Bundle(BundleOptions{
		AutoAssembleDir: dir,
		IncludeRoot:     false,
		OutputPath:      outNoRoot,
		OutputFormat:    certlib.FormatPEM,
	})
	if err != nil {
		t.Fatalf("Bundle (no root): %v", err)
	}
	foundFallback := false
	for _, w := range res.Warnings {
		if w == "no certificate chain found, collecting all certificates" {
			foundFallback = true
		}
	}
	if !foundFallback {
		t.Fatalf("expected the no-chain fallback to fire, warnings=%v", res.Warnings)
	}
	cns := readBundleCNs(t, outNoRoot)
	for _, cn := range cns {
		if cn == "fallback-root" {
			t.Errorf("self-signed root leaked into bundle with IncludeRoot=false: %v", cns)
		}
	}

	// IncludeRoot=true -> root kept
	outWithRoot := filepath.Join(dir, "with-root.pem")
	if _, err := Bundle(BundleOptions{
		AutoAssembleDir: dir,
		IncludeRoot:     true,
		OutputPath:      outWithRoot,
		OutputFormat:    certlib.FormatPEM,
	}); err != nil {
		t.Fatalf("Bundle (with root): %v", err)
	}
	cnsWith := readBundleCNs(t, outWithRoot)
	hasRoot := false
	for _, cn := range cnsWith {
		if cn == "fallback-root" {
			hasRoot = true
		}
	}
	if !hasRoot {
		t.Errorf("self-signed root missing from bundle with IncludeRoot=true: %v", cnsWith)
	}
}

// (B) With two equally-good chain candidates, the produced bundle must be
// byte-for-byte identical across repeated runs (deterministic tie-break).
func TestBundle_DeterministicBestChain(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert := jksTestCA(t)
	_, leafA := jksTestLeaf(t, "det-leaf-A", 1, caKey, caCert)
	_, leafB := jksTestLeaf(t, "det-leaf-B", 2, caKey, caCert)

	// Two leaves both signed by the same CA -> two chains of equal length 2.
	writeCertPEM(t, filepath.Join(dir, "ca.pem"), caCert)
	writeCertPEM(t, filepath.Join(dir, "leafA.pem"), leafA)
	writeCertPEM(t, filepath.Join(dir, "leafB.pem"), leafB)

	var first []byte
	for i := 0; i < 25; i++ {
		out := filepath.Join(dir, "out.pem")
		if _, err := Bundle(BundleOptions{
			AutoAssembleDir: dir,
			IncludeRoot:     true,
			OutputPath:      out,
			OutputFormat:    certlib.FormatPEM,
			Overwrite:       true,
		}); err != nil {
			t.Fatalf("Bundle run %d: %v", i, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = data
			continue
		}
		if string(data) != string(first) {
			t.Fatalf("nondeterministic bundle output at run %d", i)
		}
	}
}
