package certops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestReencryptJKS_RefusalOmitsEntryDeadEnd verifies the store-level refusal no
// longer advises '--entry', which cannot help: reencryptEntry re-encodes the
// whole store and drops any locked entry just the same.
func TestReencryptJKS_RefusalOmitsEntryDeadEnd(t *testing.T) {
	dir := t.TempDir()
	jksPath := filepath.Join(dir, "store.jks")
	buildTwoPasswordJKS(t, jksPath) // ka=storepw, kb=passB

	_, err := Reencrypt(ReencryptOptions{
		InputPath:    jksPath,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}}, // passB missing
		NewPassword:  []byte("newpw"),
	})
	if err == nil {
		t.Fatal("expected reencrypt to refuse, got nil error")
	}
	if strings.Contains(err.Error(), "--entry") {
		t.Errorf("refusal message still suggests the dead-end --entry workaround: %v", err)
	}
}

// buildUnparseableKeyJKS writes a JKS with one PrivateKeyEntry whose key bytes
// decrypt correctly (keystore-go only XOR-decrypts and verifies a digest) but
// are not valid PKCS#8, simulating a key algorithm Go cannot parse (e.g. DSA).
// The reader surfaces such an entry as a ContentPrivateKey item with
// PrivateKey==nil and Encrypted==false.
func buildUnparseableKeyJKS(t *testing.T, path, pw string) {
	t.Helper()
	caKey, caCert := jksTestCA(t)
	_, leafCert := jksTestLeaf(t, "leaf", 5, caKey, caCert)

	ks := keystore.New()
	err := ks.SetPrivateKeyEntry("badkey", keystore.PrivateKeyEntry{
		PrivateKey: []byte("this-is-not-valid-pkcs8-der"),
		CertificateChain: []keystore.Certificate{
			{Type: "X.509", Content: leafCert.Raw},
		},
	}, []byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := ks.Store(f, []byte(pw)); err != nil {
		t.Fatal(err)
	}
}

// TestReencryptJKS_RefusesUnparseableKeyEntry verifies the widened guard: a key
// entry that decrypted but could not be parsed (nil key, Encrypted==false) is
// still a data-loss risk on re-encode, so reencrypt must refuse and leave the
// input untouched instead of silently dropping the entry.
func TestReencryptJKS_RefusesUnparseableKeyEntry(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.jks")
	buildUnparseableKeyJKS(t, p, "storepw")

	// Precondition: the reader yields a nil-key, NON-Encrypted private entry
	// (the exact shape the old guard missed).
	c, err := certlib.ReadFile(p, []certlib.TaggedPassword{{Password: []byte("storepw")}})
	if err != nil {
		t.Fatal(err)
	}
	foundNilKey := false
	for _, it := range c.Items {
		if it.Type == certlib.ContentPrivateKey && it.PrivateKey == nil {
			foundNilKey = true
			if it.Encrypted {
				t.Fatal("precondition: wanted a decrypted-but-unparseable key (Encrypted=false)")
			}
		}
	}
	if !foundNilKey {
		t.Fatal("precondition: reader did not produce a nil-key private entry")
	}

	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Reencrypt(ReencryptOptions{
		InputPath:    p,
		OldPasswords: []certlib.TaggedPassword{{Password: []byte("storepw")}},
		NewPassword:  []byte("newpw"),
	})
	if err == nil {
		t.Fatal("expected reencrypt to refuse (unparseable key would be lost), got nil error")
	}
	t.Logf("reencrypt correctly refused: %v", err)

	after, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("input JKS was modified despite the refusal")
	}
}
