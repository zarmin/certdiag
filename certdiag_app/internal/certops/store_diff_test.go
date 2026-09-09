package certops

import (
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

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

var diffSerial int64 = 100

func makeDiffCert(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	diffSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(diffSerial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeDiffBundle(t *testing.T, dir, name string, pems ...[]byte) string {
	t.Helper()
	var data []byte
	for _, p := range pems {
		data = append(data, p...)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseStoreSpec(t *testing.T) {
	dir := t.TempDir()
	existing := writeDiffBundle(t, dir, "bundle.pem", makeDiffCert(t, "Spec Test CA"))

	tests := []struct {
		spec       string
		wantType   truststore.StoreType
		wantHome   string
		wantFile   string
		wantBundle string
		wantErr    bool
	}{
		{spec: "os", wantType: truststore.StoreTypeOS},
		{spec: "java", wantType: truststore.StoreTypeJava},
		{spec: "java:/opt/jdk21", wantType: truststore.StoreTypeJava, wantHome: "/opt/jdk21"},
		{spec: "openssl", wantType: truststore.StoreTypeOpenSSL},
		{spec: "nss", wantType: truststore.StoreTypeNSS},
		{spec: "mozilla", wantType: truststore.StoreTypeBundle, wantBundle: truststore.BundleMozilla},
		{spec: "chrome", wantType: truststore.StoreTypeBundle, wantBundle: truststore.BundleChrome},
		{spec: "file:" + existing, wantType: truststore.StoreTypeCustom, wantFile: existing},
		{spec: "file:/nonexistent/x.pem", wantType: truststore.StoreTypeCustom, wantFile: "/nonexistent/x.pem"},
		{spec: existing, wantType: truststore.StoreTypeCustom, wantFile: existing},
		{spec: "bogus", wantErr: true},
		{spec: "/nonexistent/path.pem", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			opts, err := parseStoreSpec(tt.spec, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseStoreSpec(%q) err = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if opts.StoreType != tt.wantType {
				t.Errorf("type = %s, want %s", opts.StoreType, tt.wantType)
			}
			if opts.JavaHome != tt.wantHome {
				t.Errorf("javaHome = %q, want %q", opts.JavaHome, tt.wantHome)
			}
			if opts.FilePath != tt.wantFile {
				t.Errorf("filePath = %q, want %q", opts.FilePath, tt.wantFile)
			}
			if opts.BundleID != tt.wantBundle {
				t.Errorf("bundleID = %q, want %q", opts.BundleID, tt.wantBundle)
			}
		})
	}
}

// The rejection message is the only place a user learns the accepted specs, so
// it must name every one the parser actually handles.
func TestParseStoreSpecErrorListsEverySpec(t *testing.T) {
	_, err := parseStoreSpec("bogus", nil)
	if err == nil {
		t.Fatal("want an error for an unknown spec")
	}
	for _, spec := range []string{"os", "java", "openssl", "nss", "mozilla", "chrome", "file:"} {
		if !strings.Contains(err.Error(), spec) {
			t.Errorf("error %q does not mention spec %q", err, spec)
		}
	}
}

func TestStoreDiff(t *testing.T) {
	dir := t.TempDir()

	shared := makeDiffCert(t, "Shared Root CA")
	onlyA := makeDiffCert(t, "Only In A CA")
	onlyB := makeDiffCert(t, "Only In B CA")
	rotatedV1 := makeDiffCert(t, "Rotated CA")
	rotatedV2 := makeDiffCert(t, "Rotated CA")

	t.Run("identical", func(t *testing.T) {
		a := writeDiffBundle(t, dir, "ident-a.pem", shared, onlyA)
		b := writeDiffBundle(t, dir, "ident-b.pem", shared, onlyA)
		res, err := StoreDiff(StoreDiffOptions{SpecA: a, SpecB: b})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Identical || res.Common != 2 {
			t.Fatalf("want identical with 2 common, got %+v", res)
		}
	})

	t.Run("only in each side", func(t *testing.T) {
		a := writeDiffBundle(t, dir, "only-a.pem", shared, onlyA)
		b := writeDiffBundle(t, dir, "only-b.pem", shared, onlyB)
		res, err := StoreDiff(StoreDiffOptions{SpecA: a, SpecB: b})
		if err != nil {
			t.Fatal(err)
		}
		if res.Identical {
			t.Fatal("must not be identical")
		}
		if res.Common != 1 || len(res.OnlyInA) != 1 || len(res.OnlyInB) != 1 || len(res.Rotated) != 0 {
			t.Fatalf("want 1/1/1/0, got common=%d onlyA=%d onlyB=%d rotated=%d",
				res.Common, len(res.OnlyInA), len(res.OnlyInB), len(res.Rotated))
		}
		if res.OnlyInA[0].Subject != "CN=Only In A CA" {
			t.Errorf("onlyA subject = %q", res.OnlyInA[0].Subject)
		}
		if res.OnlyInB[0].Subject != "CN=Only In B CA" {
			t.Errorf("onlyB subject = %q", res.OnlyInB[0].Subject)
		}
	})

	t.Run("rotated root moves out of only lists", func(t *testing.T) {
		a := writeDiffBundle(t, dir, "rot-a.pem", shared, rotatedV1)
		b := writeDiffBundle(t, dir, "rot-b.pem", shared, rotatedV2)
		res, err := StoreDiff(StoreDiffOptions{SpecA: a, SpecB: b})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Rotated) != 1 || res.Rotated[0].Subject != "CN=Rotated CA" {
			t.Fatalf("want 1 rotated CN=Rotated CA, got %+v", res.Rotated)
		}
		if len(res.OnlyInA) != 0 || len(res.OnlyInB) != 0 {
			t.Fatalf("rotated cert must not appear in only lists: onlyA=%+v onlyB=%+v", res.OnlyInA, res.OnlyInB)
		}
		if res.Identical {
			t.Fatal("rotated stores are not identical")
		}
		if len(res.Rotated[0].FingerprintsA) != 1 || len(res.Rotated[0].FingerprintsB) != 1 ||
			res.Rotated[0].FingerprintsA[0] == res.Rotated[0].FingerprintsB[0] {
			t.Fatalf("rotation fingerprints wrong: %+v", res.Rotated[0])
		}
	})

	t.Run("duplicates within a side are deduplicated", func(t *testing.T) {
		a := writeDiffBundle(t, dir, "dup-a.pem", shared, shared, shared)
		b := writeDiffBundle(t, dir, "dup-b.pem", shared)
		res, err := StoreDiff(StoreDiffOptions{SpecA: a, SpecB: b})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Identical || res.Common != 1 || res.SideA.CertCount != 1 {
			t.Fatalf("dedupe failed: %+v", res)
		}
	})

	t.Run("bad spec errors", func(t *testing.T) {
		if _, err := StoreDiff(StoreDiffOptions{SpecA: "bogus", SpecB: "os"}); err == nil {
			t.Fatal("expected error for bad spec")
		}
	})

	t.Run("unreadable file errors", func(t *testing.T) {
		garbage := writeDiffBundle(t, dir, "garbage.bin", []byte("not a certificate at all"))
		if _, err := StoreDiff(StoreDiffOptions{SpecA: garbage, SpecB: garbage}); err == nil {
			t.Fatal("expected error for unparseable store")
		}
	})
}

// TestStoreDiffRealOSStore exercises the platform OS-store reader on every OS
// the tests run on (macOS keychain, Linux bundle paths, Windows syscall store).
// A store diffed against itself must be identical.
func TestStoreDiffRealOSStore(t *testing.T) {
	if _, err := truststore.ReadOSStore(); err != nil {
		t.Skipf("OS store not readable on this system: %v", err)
	}
	res, err := StoreDiff(StoreDiffOptions{SpecA: "os", SpecB: "os"})
	if err != nil {
		t.Fatalf("StoreDiff(os, os): %v", err)
	}
	if !res.Identical {
		t.Fatalf("os store diffed against itself must be identical: %+v", res)
	}
	if res.SideA.CertCount == 0 {
		t.Fatal("OS store returned zero certificates")
	}
}
