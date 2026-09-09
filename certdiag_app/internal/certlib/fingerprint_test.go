package certlib

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// fixedCert returns a certificate with stable DER, so digests are reproducible.
func fixedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	cert, _ := generateTestCertAndKey(t)
	return cert
}

func TestFingerprint_DigestLengths(t *testing.T) {
	cert := fixedCert(t)

	want := map[FingerprintAlgo]int{
		FingerprintMD5:    16,
		FingerprintSHA1:   20,
		FingerprintSHA256: 32,
		FingerprintSHA384: 48,
		FingerprintSHA512: 64,
	}
	for algo, n := range want {
		if got := len(Fingerprint(cert, algo)); got != n {
			t.Errorf("%s: expected %d bytes, got %d", algo, n, got)
		}
	}
}

func TestFingerprint_AlgorithmsAreDistinct(t *testing.T) {
	cert := fixedCert(t)

	seen := make(map[string]FingerprintAlgo)
	for _, algo := range FingerprintAlgos {
		v := CertFingerprint(cert, algo, FingerprintHex)
		if prev, dup := seen[v]; dup {
			t.Errorf("%s and %s produced the same digest -- algorithms are miswired", prev, algo)
		}
		seen[v] = algo
	}
}

func TestFingerprint_MatchesStdlibDigests(t *testing.T) {
	// Guards against an algorithm being wired to the wrong hash.
	cert := fixedCert(t)

	if got := CertFingerprint(cert, FingerprintSHA256, FingerprintHex); got != knownHex(t, cert, "sha256") {
		t.Errorf("sha256 mismatch: %s", got)
	}
	if got := CertFingerprint(cert, FingerprintSHA1, FingerprintHex); got != knownHex(t, cert, "sha1") {
		t.Errorf("sha1 mismatch: %s", got)
	}
}

func TestFingerprint_NilCertIsSafe(t *testing.T) {
	for _, algo := range FingerprintAlgos {
		if got := Fingerprint(nil, algo); got != nil {
			t.Errorf("%s: expected nil for a nil certificate, got %v", algo, got)
		}
		if got := CertFingerprint(nil, algo, FingerprintHex); got != "" {
			t.Errorf("%s: expected empty string for a nil certificate, got %q", algo, got)
		}
	}
}

func TestFingerprint_UnknownAlgoFallsBackToSHA256(t *testing.T) {
	cert := fixedCert(t)
	got := CertFingerprint(cert, FingerprintAlgo("whirlpool"), FingerprintHex)
	if got != CertFingerprint(cert, FingerprintSHA256, FingerprintHex) {
		t.Error("an unknown algorithm should fall back to SHA-256")
	}
}

func TestFormatFingerprintBytes_Formats(t *testing.T) {
	sum := []byte{0xab, 0xcd, 0xef, 0x01, 0x23}

	tests := []struct {
		format FingerprintFormat
		want   string
	}{
		{FingerprintHex, "abcdef0123"},
		{FingerprintHexColon, "ab:cd:ef:01:23"},
		{FingerprintBase64, base64.StdEncoding.EncodeToString(sum)},
		{FingerprintFormat(""), "abcdef0123"},         // zero value is hex
		{FingerprintFormat("nonsense"), "abcdef0123"}, // unknown falls back
	}
	for _, tt := range tests {
		if got := FormatFingerprintBytes(sum, tt.format); got != tt.want {
			t.Errorf("format %q: expected %q, got %q", tt.format, tt.want, got)
		}
	}
}

func TestFormatFingerprintBytes_LowercaseHex(t *testing.T) {
	// The project prints lowercase everywhere (see FormatSerial); an uppercase
	// digest would silently change every existing output line.
	cert := fixedCert(t)
	for _, format := range []FingerprintFormat{FingerprintHex, FingerprintHexColon} {
		got := CertFingerprint(cert, FingerprintSHA256, format)
		if got != strings.ToLower(got) {
			t.Errorf("format %q produced uppercase output: %s", format, got)
		}
	}
}

func TestFormatFingerprintBytes_Shapes(t *testing.T) {
	cert := fixedCert(t)

	hexValue := CertFingerprint(cert, FingerprintSHA256, FingerprintHex)
	if len(hexValue) != 64 {
		t.Errorf("expected 64 hex chars for sha256, got %d", len(hexValue))
	}

	colon := CertFingerprint(cert, FingerprintSHA256, FingerprintHexColon)
	if strings.Count(colon, ":") != 31 {
		t.Errorf("expected 31 separators for a 32-byte digest, got %d", strings.Count(colon, ":"))
	}
	if strings.ReplaceAll(colon, ":", "") != hexValue {
		t.Error("hex-colon must be the hex form with separators inserted")
	}

	b64 := CertFingerprint(cert, FingerprintSHA256, FingerprintBase64)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 output must decode: %v", err)
	}
	if hex.EncodeToString(raw) != hexValue {
		t.Error("base64 must encode the same digest as hex")
	}
}

func TestFormatFingerprintBytes_EmptyInput(t *testing.T) {
	for _, format := range FingerprintFormats {
		if got := FormatFingerprintBytes(nil, format); got != "" {
			t.Errorf("format %q: expected empty output for no digest, got %q", format, got)
		}
	}
}

func TestReformatFingerprint_RoundTrips(t *testing.T) {
	cert := fixedCert(t)
	canonical := CertFingerprint(cert, FingerprintSHA256, FingerprintHex)

	for _, format := range FingerprintFormats {
		want := CertFingerprint(cert, FingerprintSHA256, format)
		if got := ReformatFingerprint(canonical, format); got != want {
			t.Errorf("format %q: reformat gave %q, direct gave %q", format, got, want)
		}
	}
}

func TestReformatFingerprint_InvalidInputUnchanged(t *testing.T) {
	for _, in := range []string{"", "not-hex", "abc"} {
		if got := ReformatFingerprint(in, FingerprintHexColon); got != in {
			t.Errorf("expected %q unchanged, got %q", in, got)
		}
	}
}

func TestParseFingerprintFormat(t *testing.T) {
	tests := map[string]FingerprintFormat{
		"hex":        FingerprintHex,
		"hex-colon":  FingerprintHexColon,
		"HEX-COLON":  FingerprintHexColon,
		"  base64  ": FingerprintBase64,
		"":           FingerprintHex,
		"nonsense":   FingerprintHex,
	}
	for in, want := range tests {
		if got := ParseFingerprintFormat(in); got != want {
			t.Errorf("ParseFingerprintFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFingerprintAlgo_Labels(t *testing.T) {
	want := map[FingerprintAlgo]string{
		FingerprintMD5:    "MD5",
		FingerprintSHA1:   "SHA-1",
		FingerprintSHA256: "SHA-256",
		FingerprintSHA384: "SHA-384",
		FingerprintSHA512: "SHA-512",
	}
	for algo, label := range want {
		if got := algo.Label(); got != label {
			t.Errorf("%s: expected label %q, got %q", algo, label, got)
		}
	}
}

func TestFingerprintAlgos_CanonicalOrder(t *testing.T) {
	want := []FingerprintAlgo{
		FingerprintMD5, FingerprintSHA1, FingerprintSHA256,
		FingerprintSHA384, FingerprintSHA512,
	}
	if len(FingerprintAlgos) != len(want) {
		t.Fatalf("expected %d algorithms, got %d", len(want), len(FingerprintAlgos))
	}
	for i := range want {
		if FingerprintAlgos[i] != want[i] {
			t.Errorf("position %d: expected %q, got %q", i, want[i], FingerprintAlgos[i])
		}
	}
}

// knownHex computes a digest independently of the production helper, so a
// miswiring in Fingerprint cannot make the assertion vacuously true.
func knownHex(t *testing.T, cert *x509.Certificate, algo string) string {
	t.Helper()
	switch algo {
	case "sha256":
		sum := sha256.Sum256(cert.Raw)
		return hex.EncodeToString(sum[:])
	case "sha1":
		sum := sha1.Sum(cert.Raw)
		return hex.EncodeToString(sum[:])
	}
	t.Fatalf("unsupported test algo %q", algo)
	return ""
}
