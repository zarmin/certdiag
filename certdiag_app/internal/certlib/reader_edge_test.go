package certlib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func edgeSelfSigned(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func writeEdgeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func certCount(c *CertContainer) int {
	n := 0
	for _, it := range c.Items {
		if it.Type == ContentCertificate {
			n++
		}
	}
	return n
}

// TestReadPEM_LineEndingsAndBOM: CRLF and a UTF-8 BOM are what Windows
// editors produce; both must read as the plain file does.
func TestReadPEM_LineEndingsAndBOM(t *testing.T) {
	_, der := edgeSelfSigned(t, "crlf.test")
	plain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	crlf := bytes.ReplaceAll(plain, []byte("\n"), []byte("\r\n"))
	bom := append([]byte{0xEF, 0xBB, 0xBF}, plain...)
	for name, data := range map[string][]byte{"crlf.pem": crlf, "bom.pem": bom, "bom-crlf.pem": append([]byte{0xEF, 0xBB, 0xBF}, crlf...)} {
		c, err := ReadFile(writeEdgeTemp(t, name, data), nil)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if certCount(c) != 1 {
			t.Errorf("%s: %d certificates, want 1 (errors %v)", name, certCount(c), c.ParseErrors)
		}
	}
}

// TestReadPEM_MalformedBlockBetweenGoodOnes: one bad block must not hide the
// good ones around it.
func TestReadPEM_MalformedBlockBetweenGoodOnes(t *testing.T) {
	_, a := edgeSelfSigned(t, "a.test")
	_, b := edgeSelfSigned(t, "b.test")
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: a})
	buf.WriteString("-----BEGIN CERTIFICATE-----\nthis is not base64 !!!\n-----END CERTIFICATE-----\n")
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	c, err := ReadFile(writeEdgeTemp(t, "mixed.pem", buf.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if certCount(c) != 2 {
		t.Errorf("%d certificates parsed, want the 2 good ones (errors %v)", certCount(c), c.ParseErrors)
	}
}

// TestReadPEM_UnknownBlocksOnly: a PEM made only of block types certdiag does
// not read must say which types it saw, not "unknown format".
func TestReadPEM_UnknownBlocksOnly(t *testing.T) {
	for _, typ := range []string{"TRUSTED CERTIFICATE", "RSA PUBLIC KEY", "OPENSSH PRIVATE KEY", "X509 CRL"} {
		data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: []byte("not really")})
		_, err := ReadFile(writeEdgeTemp(t, "only.pem", data), nil)
		if err == nil || !strings.Contains(err.Error(), typ) {
			t.Errorf("%s: error %v should name the block type", typ, err)
		}
	}
}

func TestReadFile_EmptyFile(t *testing.T) {
	c, err := ReadFile(writeEdgeTemp(t, "empty.pem", nil), nil)
	if err == nil && (c == nil || len(c.ParseErrors) == 0) {
		t.Error("a 0-byte file must be reported, not read as an empty container")
	}
}

// TestReadDER_CRLAndPublicKey: DER that is not a certificate, key or request
// is reported, never mistaken for one.
func TestReadDER_CRLAndPublicKey(t *testing.T) {
	key, der := edgeSelfSigned(t, "issuer.test")
	issuer, _ := x509.ParseCertificate(der)
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for name, data := range map[string][]byte{"list.crl": crl, "list.der": crl, "pub.der": spki} {
		c, err := ReadFile(writeEdgeTemp(t, name, data), nil)
		if err == nil && c != nil && len(c.ParseErrors) == 0 && len(c.Items) > 0 {
			t.Errorf("%s: parsed as %d items, want an error or a parse error", name, len(c.Items))
		}
	}
}

// TestReadJKS_EntryPasswordDiffersFromStore: both passwords supplied, the
// entry unlocks with the second one.
func TestReadJKS_EntryPasswordDiffersFromStore(t *testing.T) {
	key, der := edgeSelfSigned(t, "jks.test")
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry("web", keystore.PrivateKeyEntry{
		CreationTime: time.Now(), PrivateKey: pkcs8,
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: der}},
	}, []byte("entrypw")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte("storepw")); err != nil {
		t.Fatal(err)
	}
	c, err := readJKS("/tmp/two.jks", buf.Bytes(), [][]byte{[]byte("storepw"), []byte("entrypw")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range c.Items {
		if it.Type == ContentPrivateKey && it.Alias == "web" && it.PrivateKey != nil {
			found = true
		}
	}
	if !found {
		t.Errorf("entry not unlocked with its own password: items %+v, errors %v", c.Items, c.ParseErrors)
	}
	c, _ = readJKS("/tmp/two.jks", buf.Bytes(), [][]byte{[]byte("storepw")}, nil)
	locked := false
	for _, it := range c.Items {
		if it.Type == ContentPrivateKey && it.Alias == "web" && it.Encrypted && it.PrivateKey == nil {
			locked = true
		}
	}
	if !locked {
		t.Errorf("with only the store password the entry must be a locked placeholder, got %+v", c.Items)
	}
}

// TestReadJCEKS_ClearError guards decision D4: JCEKS is recognised and refused
// with the conversion hint.
func TestReadJCEKS_ClearError(t *testing.T) {
	data := append([]byte{0xCE, 0xCE, 0xCE, 0xCE, 0x00, 0x00, 0x00, 0x02}, bytes.Repeat([]byte{0}, 32)...)
	_, err := ReadFile(writeEdgeTemp(t, "store.jceks", data), nil)
	if err == nil || !strings.Contains(err.Error(), "JCEKS") || !strings.Contains(err.Error(), "keytool") {
		t.Errorf("want the JCEKS conversion hint, got %v", err)
	}
}
