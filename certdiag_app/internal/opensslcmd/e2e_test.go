package opensslcmd

import (
	"crypto/x509"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// These tests run the generated openssl commands end-to-end and verify the
// produced artifacts, guaranteeing the emitted commands are not just
// plausible-looking but actually valid and behaviourally correct.

func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found in PATH; skipping e2e")
	}
}

func run(t *testing.T, dir string, c Command) {
	t.Helper()
	cmd := exec.Command(c.Tool, c.Args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v\noutput: %s", c.String(), err, out)
	}
}

func readOne(t *testing.T, path string) certlib.CertItem {
	t.Helper()
	container, err := certlib.ReadFile(path, nil)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(container.Items) == 0 {
		t.Fatalf("read %s: no items", path)
	}
	return container.Items[0]
}

func TestE2EKeyGen(t *testing.T) {
	requireOpenSSL(t)
	cases := []struct {
		name string
		opts certlib.KeyGenOptions
	}{
		{"rsa2048", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}},
		{"ecdsa-p256", certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}},
		{"ed25519", certlib.KeyGenOptions{Algorithm: "ed25519"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "key.pem")
			run(t, dir, KeyGen(tc.opts, keyPath, certlib.FormatPEM, false))
			item := readOne(t, keyPath)
			if item.Type != certlib.ContentPrivateKey {
				t.Fatalf("expected a private key, got %s", item.Type)
			}
		})
	}
}

func TestE2ECSR(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	csrPath := filepath.Join(dir, "req.csr")

	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}, keyPath, certlib.FormatPEM, false))

	name, _ := certlib.ParseDN("CN=example.com,O=Example")
	sans, _ := certlib.ParseSANString("DNS:example.com,IP:127.0.0.1")
	run(t, dir, CSR(name, sans, keyPath, csrPath, certlib.FormatPEM))

	item := readOne(t, csrPath)
	if item.CSR == nil {
		t.Fatal("expected a CSR item")
	}
	if item.CSR.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want example.com", item.CSR.Subject.CommonName)
	}
	if len(item.CSR.DNSNames) != 1 || item.CSR.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", item.CSR.DNSNames)
	}
	if len(item.CSR.IPAddresses) != 1 || item.CSR.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", item.CSR.IPAddresses)
	}
}

func TestE2ESelfSignedCert(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}, keyPath, certlib.FormatPEM, false))

	name, _ := certlib.ParseDN("CN=leaf.local")
	sans, _ := certlib.ParseSANString("DNS:leaf.local,DNS:www.leaf.local")
	spec := CertSpec{
		Subject:     name,
		SANs:        sans,
		Days:        365,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Serial:      big.NewInt(0xabcdef),
		KeyPath:     keyPath,
		OutputPath:  certPath,
	}
	run(t, dir, SelfSignedCert(spec))

	item := readOne(t, certPath)
	cert := item.Certificate
	if cert == nil {
		t.Fatal("expected a certificate item")
	}
	if cert.Subject.CommonName != "leaf.local" {
		t.Errorf("CN = %q, want leaf.local", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want 2 entries", cert.DNSNames)
	}
	if cert.SerialNumber.Cmp(big.NewInt(0xabcdef)) != 0 {
		t.Errorf("serial = %s, want %d", cert.SerialNumber, 0xabcdef)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected digitalSignature key usage")
	}
}

func TestE2ESignCSR(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	caKey := filepath.Join(dir, "ca.key")
	caCert := filepath.Join(dir, "ca.crt")
	leafKey := filepath.Join(dir, "leaf.key")
	csr := filepath.Join(dir, "leaf.csr")
	leafCert := filepath.Join(dir, "leaf.crt")

	// Build a CA (key + self-signed CA cert).
	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, caKey, certlib.FormatPEM, false))
	caName, _ := certlib.ParseDN("CN=Test CA")
	run(t, dir, SelfSignedCert(CertSpec{
		Subject: caName, Days: 3650, IsCA: true, PathLength: -1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		KeyPath:  caKey, OutputPath: caCert,
	}))

	// Build a leaf key + CSR, then sign it with the CA.
	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}, leafKey, certlib.FormatPEM, false))
	leafName, _ := certlib.ParseDN("CN=leaf.example.com")
	leafSANs, _ := certlib.ParseSANString("DNS:leaf.example.com")
	run(t, dir, CSR(leafName, leafSANs, leafKey, csr, certlib.FormatPEM))
	run(t, dir, SignCSR(csr, caCert, caKey, leafCert, 365, nil, certlib.FormatPEM, nil))

	caItem := readOne(t, caCert)
	leafItem := readOne(t, leafCert)
	if leafItem.Certificate == nil || caItem.Certificate == nil {
		t.Fatal("expected certificate items")
	}
	if err := leafItem.Certificate.CheckSignatureFrom(caItem.Certificate); err != nil {
		t.Errorf("signed leaf does not verify against CA: %v", err)
	}
	if leafItem.Certificate.Issuer.CommonName != "Test CA" {
		t.Errorf("issuer CN = %q, want Test CA", leafItem.Certificate.Issuer.CommonName)
	}
	// -copy_extensions copy should carry the CSR's SAN into the signed cert.
	if len(leafItem.Certificate.DNSNames) != 1 || leafItem.Certificate.DNSNames[0] != "leaf.example.com" {
		t.Errorf("DNSNames = %v, want [leaf.example.com]", leafItem.Certificate.DNSNames)
	}
}

// TestE2ESignCSRAsCA runs the CA-signing recipe with the -extfile the generator
// prescribes and confirms the produced certificate is actually a CA - the
// HIGH-6 regression, end-to-end with real openssl.
func TestE2ESignCSRAsCA(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	rootKey := filepath.Join(dir, "root.key")
	rootCert := filepath.Join(dir, "root.crt")
	subKey := filepath.Join(dir, "sub.key")
	subCSR := filepath.Join(dir, "sub.csr")
	subCert := filepath.Join(dir, "sub.crt")

	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, rootKey, certlib.FormatPEM, false))
	rootName, _ := certlib.ParseDN("CN=Root CA")
	run(t, dir, SelfSignedCert(CertSpec{
		Subject: rootName, Days: 3650, IsCA: true, PathLength: -1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		KeyPath:  rootKey, OutputPath: rootCert,
	}))

	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}, subKey, certlib.FormatPEM, false))
	subName, _ := certlib.ParseDN("CN=Sub CA")
	run(t, dir, CSR(subName, certlib.SANList{}, subKey, subCSR, certlib.FormatPEM))

	// The generator prescribes -extfile ext.cnf; create it to match the notes.
	extCnf := filepath.Join(dir, "ext.cnf")
	if err := os.WriteFile(extCnf, []byte("[v3_certdiag]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, dir, SignCSR(subCSR, rootCert, rootKey, subCert, 1825, nil, certlib.FormatPEM, &SignExtSpec{
		IsCA: true, PathLength: 0,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}))

	sub := readOne(t, subCert)
	if sub.Certificate == nil {
		t.Fatal("expected a certificate")
	}
	if !sub.Certificate.IsCA {
		t.Error("signed sub-CA is not a CA - the emitted command dropped basicConstraints")
	}
	if sub.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("signed sub-CA lacks keyCertSign")
	}
}

func TestE2EConvertRoundTrips(t *testing.T) {
	requireOpenSSL(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := filepath.Join(dir, "cert.pem")

	run(t, dir, KeyGen(certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p256"}, keyPath, certlib.FormatPEM, false))
	name, _ := certlib.ParseDN("CN=convert.test")
	run(t, dir, SelfSignedCert(CertSpec{Subject: name, Days: 1, KeyPath: keyPath, OutputPath: certPEM}))

	// PEM -> DER -> PEM
	certDER := filepath.Join(dir, "cert.der")
	backPEM := filepath.Join(dir, "back.pem")
	runAll(t, dir, Convert(certPEM, certlib.FormatPEM, certDER, certlib.FormatDER, "all", false))
	runAll(t, dir, Convert(certDER, certlib.FormatDER, backPEM, certlib.FormatPEM, "all", false))
	if readOne(t, backPEM).Certificate.Subject.CommonName != "convert.test" {
		t.Error("DER round-trip lost the subject")
	}

	// PEM -> PKCS7 -> PEM
	p7b := filepath.Join(dir, "certs.p7b")
	fromP7 := filepath.Join(dir, "fromp7.pem")
	runAll(t, dir, Convert(certPEM, certlib.FormatPEM, p7b, certlib.FormatPKCS7, "all", false))
	runAll(t, dir, Convert(p7b, certlib.FormatPKCS7, fromP7, certlib.FormatPEM, "all", false))
	if readOne(t, fromP7).Certificate.Subject.CommonName != "convert.test" {
		t.Error("PKCS7 round-trip lost the subject")
	}
}

func runAll(t *testing.T, dir string, cmds []Command) {
	t.Helper()
	for _, c := range cmds {
		if c.Tool == "" {
			t.Fatalf("no-equivalent command: %v", c.Notes)
		}
		run(t, dir, c)
	}
}
