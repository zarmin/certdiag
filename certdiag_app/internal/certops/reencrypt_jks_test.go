package certops

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func jksTestCA(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "reenc-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func jksTestLeaf(t *testing.T, cn string, serial int64, caKey *rsa.PrivateKey, caCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// buildTwoPasswordJKS writes a JKS with two key entries: "ka" protected by the
// store password, "kb" protected by a distinct password ("passB").
func buildTwoPasswordJKS(t *testing.T, path string) {
	t.Helper()
	caKey, caCert := jksTestCA(t)
	keyA, certA := jksTestLeaf(t, "entryA", 1, caKey, caCert)
	keyB, certB := jksTestLeaf(t, "entryB", 2, caKey, caCert)

	items := []certlib.CertItem{
		{Type: certlib.ContentPrivateKey, Alias: "ka", PrivateKey: keyA, EntryPassword: []byte("storepw")},
		{Type: certlib.ContentCertificate, Alias: "ca", Certificate: certA, RawBytes: certA.Raw},
		{Type: certlib.ContentPrivateKey, Alias: "kb", PrivateKey: keyB, EntryPassword: []byte("passB")},
		{Type: certlib.ContentCertificate, Alias: "cb", Certificate: certB, RawBytes: certB.Raw},
		{Type: certlib.ContentCertificate, Alias: "root", Certificate: caCert, RawBytes: caCert.Raw},
	}
	aliases := map[int]string{0: "ka", 1: "ca", 2: "kb", 3: "cb", 4: "root"}
	encoded, err := certlib.EncodeJKS(items, []byte("storepw"), aliases)
	if err != nil {
		t.Fatalf("EncodeJKS: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestReencryptJKS_RefusesWhenEntryUnlockable verifies the fix for the data-loss
// bug: reencrypting a JKS whose entries have per-entry passwords not all supplied
// must refuse (error) and leave the input file untouched, rather than silently
// dropping the un-decryptable key entries.
func TestReencryptJKS_RefusesWhenEntryUnlockable(t *testing.T) {
	dir := t.TempDir()
	jksPath := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, jksPath)

	before, err := os.ReadFile(jksPath)
	if err != nil {
		t.Fatal(err)
	}

	// Reencrypt supplying only the store password ("passB" is unknown -> kb is a
	// locked placeholder).
	_, err = Reencrypt(ReencryptOptions{
		InputPath:    jksPath,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}},
		NewPassword:  []byte("newpw"),
	})
	if err == nil {
		t.Fatal("expected reencrypt to refuse (locked key entry would be lost), got nil error")
	}
	t.Logf("reencrypt correctly refused: %v", err)

	// Input file must be unchanged (no destructive in-place rewrite).
	after, err := os.ReadFile(jksPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("input JKS was modified despite the refusal - in-place rewrite must not happen")
	}
}

// TestReencryptJKS_SucceedsWhenAllEntriesUnlockable is the regression guard: when
// all entry passwords are supplied, reencrypt still succeeds and keeps both keys.
func TestReencryptJKS_SucceedsWhenAllEntriesUnlockable(t *testing.T) {
	dir := t.TempDir()
	jksPath := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, jksPath)

	res, err := Reencrypt(ReencryptOptions{
		InputPath:    jksPath,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}, {Password: []byte("passB")}},
		NewPassword:  []byte("newpw"),
	})
	if err != nil {
		t.Fatalf("reencrypt with all passwords should succeed, got: %v", err)
	}

	// ka was protected by the store password -> rekeyed to newpw; kb kept passB.
	c, err := certlib.ReadFile(jksPath, []certlib.TaggedPassword{{Password: []byte("newpw")}, {Password: []byte("passB")}})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	keys := 0
	for _, it := range c.Items {
		if it.Type == certlib.ContentPrivateKey && it.PrivateKey != nil {
			keys++
		}
	}
	if keys != 2 {
		t.Errorf("expected 2 keys preserved after reencrypt, got %d (ItemCount=%d)", keys, res.ItemCount)
	}
}
