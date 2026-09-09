package certlib

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

// TestReadPKCS12_FriendlyNameBecomesAlias (M31 WP12): `extract --alias` on a
// PKCS#12 needs the friendlyName attributes surfaced as aliases. The archive
// is made with openssl, since go-pkcs12 cannot write a named key bag.
func TestReadPKCS12_FriendlyNameBecomesAlias(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	key, der := edgeSelfSigned(t, "alias.test")
	dir := t.TempDir()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	os.WriteFile(filepath.Join(dir, "k.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	os.WriteFile(filepath.Join(dir, "c.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	p12 := filepath.Join(dir, "a.p12")
	out, err := exec.Command(openssl, "pkcs12", "-export", "-in", filepath.Join(dir, "c.pem"), "-inkey", filepath.Join(dir, "k.pem"),
		"-name", "my-alias", "-passout", "pass:pw", "-out", p12).CombinedOutput()
	if err != nil {
		t.Skipf("openssl pkcs12: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(p12)
	c, err := readPKCS12(p12, data, [][]byte{[]byte("pw")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range c.Items {
		if it.Alias != "my-alias" {
			t.Errorf("%s item alias = %q, want my-alias", it.Type, it.Alias)
		}
	}
	if len(c.Items) < 2 {
		t.Errorf("expected key and certificate, got %d items", len(c.Items))
	}
	// The go-pkcs12 trust-store form has attributes ToPEM refuses; reading
	// it must still succeed, alias or not.
	cert, _ := x509.ParseCertificate(der)
	ts, _ := pkcs12.Modern2023.EncodeTrustStoreEntries([]pkcs12.TrustStoreEntry{{Cert: cert, FriendlyName: "ts"}}, "pw")
	if c, err := readPKCS12("/tmp/ts.p12", ts, [][]byte{[]byte("pw")}, nil); err != nil || len(c.Items) != 1 {
		t.Errorf("trust-store P12: %v, %d items", err, len(c.Items))
	}
}
