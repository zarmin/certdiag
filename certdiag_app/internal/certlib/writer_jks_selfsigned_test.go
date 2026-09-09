package certlib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func selfSignedLeaf(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "self-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// TestJKS_SelfSignedKeyNotDropped verifies a self-signed leaf that both matches a
// private key and is emitted standalone does not clobber the PrivateKeyEntry.
// It runs both item orderings to prove order-independence (bug #53).
func TestJKS_SelfSignedKeyNotDropped(t *testing.T) {
	key, cert := selfSignedLeaf(t)

	orderings := []struct {
		name  string
		items []CertItem
	}{
		{
			name: "key-first",
			items: []CertItem{
				{Type: ContentPrivateKey, Alias: "leaf", PrivateKey: key},
				{Type: ContentCertificate, Alias: "leaf", Certificate: cert, RawBytes: cert.Raw},
			},
		},
		{
			name: "cert-first",
			items: []CertItem{
				{Type: ContentCertificate, Alias: "leaf", Certificate: cert, RawBytes: cert.Raw},
				{Type: ContentPrivateKey, Alias: "leaf", PrivateKey: key},
			},
		},
	}

	for _, tc := range orderings {
		t.Run(tc.name, func(t *testing.T) {
			aliases := map[int]string{}
			for i, it := range tc.items {
				aliases[i] = it.Alias
			}
			enc, err := EncodeJKS(tc.items, []byte("pw"), aliases)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			p := filepath.Join(dir, "c.jks")
			if err := os.WriteFile(p, enc, 0600); err != nil {
				t.Fatal(err)
			}

			c, err := ReadFile(p, []TaggedPassword{{Password: []byte("pw")}})
			if err != nil {
				t.Fatal(err)
			}

			var keyCount int
			var haveKey bool
			aliasSet := map[string]bool{}
			for _, it := range c.Items {
				aliasSet[it.Alias] = true
				if it.Type == ContentPrivateKey {
					keyCount++
					if it.PrivateKey != nil {
						haveKey = true
					}
				}
			}
			if keyCount != 1 {
				t.Fatalf("expected exactly 1 private key entry, got %d", keyCount)
			}
			if !haveKey {
				t.Fatal("private key was dropped from the JKS (bug #53)")
			}
			if !aliasSet["leaf"] {
				t.Fatalf("expected alias %q to survive, got aliases %v", "leaf", aliasSet)
			}
		})
	}
}
