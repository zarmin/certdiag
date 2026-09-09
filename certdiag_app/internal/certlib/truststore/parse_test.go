package truststore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestParseCertCopy_DoesNotAliasInput verifies that parseCertCopy returns a
// certificate independent of the source buffer: mutating (or freeing/reusing)
// the buffer afterwards must not corrupt cert.Raw. This guards the Windows
// use-after-free where the CERT_CONTEXT buffer is reused after parsing.
func TestParseCertCopy_DoesNotAliasInput(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "alias-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an OS-owned buffer.
	buf := make([]byte, len(der))
	copy(buf, der)

	cert, err := parseCertCopy(buf)
	if err != nil {
		t.Fatalf("parseCertCopy: %v", err)
	}

	// The returned cert.Raw must not point into buf.
	if len(cert.Raw) > 0 && len(buf) > 0 && &cert.Raw[0] == &buf[0] {
		t.Fatal("cert.Raw aliases the input buffer - clone did not happen")
	}

	// Now "free"/reuse the buffer; cert.Raw must remain the original DER.
	for i := range buf {
		buf[i] = 0
	}
	if !bytes.Equal(cert.Raw, der) {
		t.Error("cert.Raw was corrupted when the source buffer was overwritten")
	}
	if cert.Subject.CommonName != "alias-test" {
		t.Errorf("unexpected CN after buffer reuse: %q", cert.Subject.CommonName)
	}
}
