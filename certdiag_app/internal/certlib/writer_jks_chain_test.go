package certlib

import (
	"bytes"
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
)

func chainCA(t *testing.T, cn string, serial int64, parentKey *rsa.PrivateKey, parent *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	sk, sc := key, tmpl
	if parentKey != nil {
		sk, sc = parentKey, parent
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, sc, &key.PublicKey, sk)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func chainLeaf(t *testing.T, caKey *rsa.PrivateKey, caCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// buildChainJKS writes a JKS whose single PrivateKeyEntry carries a full
// leaf->intermediate->root chain, and returns the path.
func buildChainJKS(t *testing.T, path string) (inter, root *x509.Certificate) {
	t.Helper()
	rootKey, rootCert := chainCA(t, "root-ca", 1, nil, nil)
	interKey, interCert := chainCA(t, "inter-ca", 2, rootKey, rootCert)
	leafKey, leafCert := chainLeaf(t, interKey, interCert)

	items := []CertItem{
		{Type: ContentPrivateKey, Alias: "k", PrivateKey: leafKey, EntryPassword: []byte("pw")},
		{Type: ContentCertificate, Alias: "leaf", Certificate: leafCert, RawBytes: leafCert.Raw},
		{Type: ContentCertificate, Alias: "inter", Certificate: interCert, RawBytes: interCert.Raw},
		{Type: ContentCertificate, Alias: "root", Certificate: rootCert, RawBytes: rootCert.Raw},
	}
	enc, err := EncodeJKS(items, []byte("pw"), map[int]string{0: "k", 1: "leaf", 2: "inter", 3: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, enc, 0600); err != nil {
		t.Fatal(err)
	}
	return interCert, rootCert
}

func subjects(items []CertItem) map[string]bool {
	m := map[string]bool{}
	for _, it := range items {
		if it.Type == ContentCertificate && it.Certificate != nil {
			m[it.Certificate.Subject.CommonName] = true
		}
	}
	return m
}

// TestJKS_ReadCarriesChain verifies the key item carries the issuer chain after read.
func TestJKS_ReadCarriesChain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.jks")
	buildChainJKS(t, p)

	c, err := ReadFile(p, []TaggedPassword{{Password: []byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	var keyChainLen int
	for _, it := range c.Items {
		if it.Type == ContentPrivateKey {
			keyChainLen = len(it.Chain)
		}
	}
	if keyChainLen < 2 {
		t.Errorf("key item Chain should carry intermediate+root (2), got %d", keyChainLen)
	}
}

// TestJKS_ReencodePreservesIntermediate verifies a JKS->JKS re-encode keeps the intermediate.
func TestJKS_ReencodePreservesIntermediate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.jks")
	inter, _ := buildChainJKS(t, p)

	c, err := ReadFile(p, []TaggedPassword{{Password: []byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncodeJKS(c.Items, []byte("pw2"), extractAliasesForTest(c.Items))
	if err != nil {
		t.Fatal(err)
	}
	p2 := filepath.Join(dir, "c2.jks")
	os.WriteFile(p2, enc, 0600)

	// The entry keeps its original per-entry password ("pw"); the store password
	// is "pw2". Supply both to unlock.
	c2, err := ReadFile(p2, []TaggedPassword{{Password: []byte("pw2")}, {Password: []byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range c2.Items {
		if it.Type == ContentPrivateKey {
			for _, der := range it.Chain {
				if bytes.Equal(der, inter.Raw) {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("intermediate lost after JKS re-encode")
	}
}

// TestJKS_ToPEMIncludesIntermediate verifies JKS->PEM conversion keeps the intermediate.
func TestJKS_ToPEMIncludesIntermediate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.jks")
	buildChainJKS(t, p)

	c, err := ReadFile(p, []TaggedPassword{{Password: []byte("pw")}})
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := EncodePEM(c.Items)
	if err != nil {
		t.Fatal(err)
	}
	// Parse all certs from the PEM and check the intermediate is present.
	got := map[string]bool{}
	rest := pemBytes
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(b.Bytes); err == nil {
				got[cert.Subject.CommonName] = true
			}
		}
	}
	if !got["inter-ca"] {
		t.Errorf("JKS->PEM dropped the intermediate; got certs %v", got)
	}
	if !got["leaf"] {
		t.Errorf("JKS->PEM missing the leaf; got certs %v", got)
	}
	_ = subjects
}

func extractAliasesForTest(items []CertItem) map[int]string {
	m := map[int]string{}
	for i, it := range items {
		if it.Alias != "" {
			m[i] = it.Alias
		}
	}
	return m
}
