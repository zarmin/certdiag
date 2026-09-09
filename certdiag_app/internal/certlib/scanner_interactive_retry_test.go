package certlib

import (
	"path/filepath"
	"testing"
)

// buildTwoPasswordJKS writes a JKS whose store password differs from the
// per-entry key password, so both are required to fully unlock it.
func buildTwoPasswordJKS(t *testing.T, path string, storePass, keyPass []byte) {
	t.Helper()
	key := mustGenerateRSAKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	items := []CertItem{
		{Type: ContentPrivateKey, Alias: "k", PrivateKey: key, EntryPassword: keyPass},
		{Type: ContentCertificate, Alias: "k", Certificate: cert, RawBytes: cert.Raw},
	}
	enc, err := EncodeJKS(items, storePass, map[int]string{0: "k", 1: "k"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteToFile(path, enc, true); err != nil {
		t.Fatal(err)
	}
}

func privateKeyItem(c *CertContainer) *CertItem {
	for i := range c.Items {
		if c.Items[i].Type == ContentPrivateKey {
			return &c.Items[i]
		}
	}
	return nil
}

// TestInteractiveRetry_MergesKnownAndInteractivePasswords verifies that the
// interactive retry accumulates the file's already-known passwords with the
// newly-entered one, so a JKS needing distinct store + key passwords unlocks.
func TestInteractiveRetry_MergesKnownAndInteractivePasswords(t *testing.T) {
	storePass := []byte("storepw")
	keyPass := []byte("keypw")

	dir := t.TempDir()
	p := filepath.Join(dir, "two.jks")
	buildTwoPasswordJKS(t, p, storePass, keyPass)

	// Baseline: the interactive store password alone leaves the key locked,
	// because the key entry needs the different key password too.
	only := readFileMust(t, p, []TaggedPassword{{Password: storePass, Source: PasswordSourceInteractive}})
	if item := privateKeyItem(only); item == nil || !item.Encrypted {
		t.Fatalf("expected the private key to stay locked with store password only")
	}

	// The key password is already known/cached for this file; the interactive
	// retry supplies the store password. The merge of the two must unlock both
	// the store and the key entry.
	provider := fixedPasswordProvider{
		{Password: keyPass, Source: PasswordSourceCLI},
	}

	store, err := ScanPathWithOptions(p, ScanOptions{
		PasswordProvider: provider,
		InteractiveRetry: func(_ string, retryFn func([]byte) bool) bool {
			return retryFn(storePass)
		},
	})
	if err != nil {
		t.Fatalf("ScanPathWithOptions: %v", err)
	}
	if len(store.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(store.Containers))
	}

	item := privateKeyItem(&store.Containers[0])
	if item == nil {
		t.Fatal("no private key item in scanned container")
	}
	if item.Encrypted || item.PrivateKey == nil {
		t.Fatalf("private key not unlocked after merged retry: encrypted=%v hasKey=%v", item.Encrypted, item.PrivateKey != nil)
	}
}

type fixedPasswordProvider []TaggedPassword

func (p fixedPasswordProvider) PasswordsForFile(_ string) []TaggedPassword {
	return p
}

func readFileMust(t *testing.T, path string, passwords []TaggedPassword) *CertContainer {
	t.Helper()
	c, err := ReadFile(path, passwords)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return c
}
