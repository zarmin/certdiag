package certlib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// TestReadJKS_BadPKCS8EntryIsReported guards M19: a key entry whose bytes are
// not PKCS#8 used to yield a silent key item with a nil key.
func TestReadJKS_BadPKCS8EntryIsReported(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jks.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	ks := keystore.New()
	pass := []byte("changeit")
	if err := ks.SetPrivateKeyEntry("broken", keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       []byte("definitely not PKCS#8 bytes"),
		CertificateChain: []keystore.Certificate{{Type: "X509", Content: der}},
	}, pass); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := ks.Store(&buf, pass); err != nil {
		t.Fatal(err)
	}

	container, err := readJKS("/tmp/broken.jks", buf.Bytes(), [][]byte{pass}, nil)
	if err != nil {
		t.Fatalf("readJKS: %v", err)
	}
	found := false
	for _, e := range container.ParseErrors {
		if strings.Contains(e, "broken") && strings.Contains(e, "PKCS#8") {
			found = true
		}
	}
	if !found {
		t.Errorf("a non-PKCS#8 key entry must be reported in ParseErrors, got %v", container.ParseErrors)
	}
	for _, item := range container.Items {
		if item.Type == ContentPrivateKey && item.Alias == "broken" && item.PrivateKey == nil {
			// The item may still be listed for its chain; a nil key is fine as
			// long as the error above names it.
			_ = item
		}
	}
}
