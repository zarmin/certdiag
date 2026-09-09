package certlib

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// FingerprintAlgo is a digest algorithm used for certificate fingerprints.
type FingerprintAlgo string

const (
	FingerprintMD5    FingerprintAlgo = "md5"
	FingerprintSHA1   FingerprintAlgo = "sha1"
	FingerprintSHA256 FingerprintAlgo = "sha256"
	FingerprintSHA384 FingerprintAlgo = "sha384"
	FingerprintSHA512 FingerprintAlgo = "sha512"
)

// FingerprintAlgos is the canonical display order: weakest first, so the
// strongest and most commonly quoted digests end up nearest the eye when a
// detail pane lists all of them.
var FingerprintAlgos = []FingerprintAlgo{
	FingerprintMD5,
	FingerprintSHA1,
	FingerprintSHA256,
	FingerprintSHA384,
	FingerprintSHA512,
}

// Label is the human-facing name, matching how openssl and keytool spell it.
func (a FingerprintAlgo) Label() string {
	switch a {
	case FingerprintMD5:
		return "MD5"
	case FingerprintSHA1:
		return "SHA-1"
	case FingerprintSHA256:
		return "SHA-256"
	case FingerprintSHA384:
		return "SHA-384"
	case FingerprintSHA512:
		return "SHA-512"
	}
	return strings.ToUpper(string(a))
}

// FingerprintFormat is how a digest is rendered for display. It never affects
// JSON/YAML output, which always carries the canonical lowercase hex form.
type FingerprintFormat string

const (
	FingerprintHex      FingerprintFormat = "hex"       // abcdef0123
	FingerprintHexColon FingerprintFormat = "hex-colon" // ab:cd:ef:01:23
	FingerprintBase64   FingerprintFormat = "base64"    // q83vASM=
)

var FingerprintFormats = []FingerprintFormat{
	FingerprintHex,
	FingerprintHexColon,
	FingerprintBase64,
}

// ParseFingerprintFormat maps a config or flag value to a format, falling back
// to plain hex for empty or unrecognised input so a bad value degrades to the
// historical output rather than failing.
func ParseFingerprintFormat(s string) FingerprintFormat {
	switch FingerprintFormat(strings.ToLower(strings.TrimSpace(s))) {
	case FingerprintHexColon:
		return FingerprintHexColon
	case FingerprintBase64:
		return FingerprintBase64
	}
	return FingerprintHex
}

// Fingerprint hashes the DER encoding of a certificate. An unknown algorithm
// falls back to SHA-256.
func Fingerprint(cert *x509.Certificate, algo FingerprintAlgo) []byte {
	if cert == nil {
		return nil
	}
	switch algo {
	case FingerprintMD5:
		sum := md5.Sum(cert.Raw)
		return sum[:]
	case FingerprintSHA1:
		sum := sha1.Sum(cert.Raw)
		return sum[:]
	case FingerprintSHA384:
		sum := sha512.Sum384(cert.Raw)
		return sum[:]
	case FingerprintSHA512:
		sum := sha512.Sum512(cert.Raw)
		return sum[:]
	}
	sum := sha256.Sum256(cert.Raw)
	return sum[:]
}

// FormatFingerprintBytes renders a digest. FingerprintHex is the canonical
// form used in JSON/YAML and stored in the structured output model.
func FormatFingerprintBytes(sum []byte, format FingerprintFormat) string {
	if len(sum) == 0 {
		return ""
	}
	switch format {
	case FingerprintHexColon:
		return hexColon(sum)
	case FingerprintBase64:
		return base64.StdEncoding.EncodeToString(sum)
	}
	return hex.EncodeToString(sum)
}

// ReformatFingerprint re-renders an already-canonical hex digest. Display
// layers that only hold the structured output model (the TUI detail pane) use
// this rather than re-hashing the certificate. Input that is not valid hex is
// returned unchanged.
func ReformatFingerprint(canonicalHex string, format FingerprintFormat) string {
	if canonicalHex == "" || format == FingerprintHex {
		return canonicalHex
	}
	raw, err := hex.DecodeString(canonicalHex)
	if err != nil {
		return canonicalHex
	}
	return FormatFingerprintBytes(raw, format)
}

// CertFingerprint hashes and formats in one step, for callers that hold the
// certificate itself.
func CertFingerprint(cert *x509.Certificate, algo FingerprintAlgo, format FingerprintFormat) string {
	return FormatFingerprintBytes(Fingerprint(cert, algo), format)
}

// hexColon renders lowercase hex byte pairs joined by colons, matching
// FormatSerial in dn.go.
func hexColon(sum []byte) string {
	var sb strings.Builder
	sb.Grow(len(sum) * 3)
	const digits = "0123456789abcdef"
	for i, b := range sum {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteByte(digits[b>>4])
		sb.WriteByte(digits[b&0x0f])
	}
	return sb.String()
}
