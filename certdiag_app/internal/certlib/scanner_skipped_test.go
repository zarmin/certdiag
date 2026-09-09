package certlib

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
	"runtime"
	"strings"
	"testing"
	"time"
)

func skippedPEMCert(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "good.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestScan_ReportsWhatItSkips guards M19 / E2 (T14): every candidate a
// directory scan cannot read is named with a reason, while files that were
// never candidates (no certificate extension) stay silent.
func TestScan_ReportsWhatItSkips(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("good.crt", skippedPEMCert(t), 0o600)
	write("garbage.crt", []byte("this is not a certificate\n"), 0o600)
	write("empty.pem", nil, 0o600)
	write("crlonly.pem", []byte("-----BEGIN X509 CRL-----\nMAA=\n-----END X509 CRL-----\n"), 0o600)
	write("README.txt", []byte("not a candidate"), 0o600)
	huge := write("huge.crt", nil, 0o600)
	if err := os.Truncate(huge, MaxScanFileSize+1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "dangling.crt")); err != nil {
		t.Fatal(err)
	}
	unixPerms := runtime.GOOS != "windows" && os.Geteuid() != 0
	if unixPerms {
		write("noperm.crt", skippedPEMCert(t), 0o000)
		sub := filepath.Join(dir, "locked")
		if err := os.Mkdir(sub, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0o700) })
	}

	store, err := ScanPathWithOptions(dir, ScanOptions{Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Containers) != 1 {
		t.Errorf("only good.crt is readable, got %d containers", len(store.Containers))
	}

	reasons := map[string]string{}
	for _, sk := range store.Skipped {
		reasons[filepath.Base(sk.Path)] = sk.Reason
	}
	want := map[string]string{
		"garbage.crt":  "unsupported",
		"empty.pem":    "unsupported",
		"crlonly.pem":  "X509 CRL",
		"huge.crt":     "scan limit",
		"dangling.crt": "broken symlink",
	}
	if unixPerms {
		want["noperm.crt"] = "permission denied"
		want["locked"] = "cannot read"
	}
	for name, fragment := range want {
		got, ok := reasons[name]
		if !ok {
			t.Errorf("%s was not reported as skipped (skipped: %v)", name, reasons)
			continue
		}
		if !strings.Contains(got, fragment) {
			t.Errorf("%s: reason %q does not mention %q", name, got, fragment)
		}
	}
	if _, ok := reasons["README.txt"]; ok {
		t.Error("a file without a certificate extension was never a candidate and must not be reported")
	}
	if _, ok := reasons["good.crt"]; ok {
		t.Error("a readable file must not be reported as skipped")
	}
}
