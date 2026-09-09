package tls

import (
	"fmt"
	"testing"
)

func TestLookupCipherSuite(t *testing.T) {
	tests := []struct {
		code     uint16
		name     string
		weak     bool
		isKnown  bool
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256", false, true},
		{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, true},
		{0x0005, "TLS_RSA_WITH_RC4_128_SHA", true, true},
		{0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256", true, true},
		{0xFFFF, fmt.Sprintf("Unknown(0x%04x)", uint16(0xFFFF)), false, false},
		{0xBEEF, fmt.Sprintf("Unknown(0x%04x)", uint16(0xBEEF)), false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs := LookupCipherSuite(tc.code)
			if cs.Code != tc.code {
				t.Errorf("Code: expected 0x%04x, got 0x%04x", tc.code, cs.Code)
			}
			if cs.Name != tc.name {
				t.Errorf("Name: expected '%s', got '%s'", tc.name, cs.Name)
			}
			if cs.Weak != tc.weak {
				t.Errorf("Weak: expected %v, got %v", tc.weak, cs.Weak)
			}
		})
	}
}

func TestCipherSuiteName(t *testing.T) {
	tests := []struct {
		code     uint16
		expected string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
		{0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{0xDEAD, "Unknown(0xdead)"},
		{0x0000, "TLS_NULL_WITH_NULL_NULL"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("0x%04x", tc.code), func(t *testing.T) {
			got := CipherSuiteName(tc.code)
			if got != tc.expected {
				t.Errorf("CipherSuiteName(0x%04x): expected '%s', got '%s'", tc.code, tc.expected, got)
			}
		})
	}
}

func TestNamedGroupName(t *testing.T) {
	tests := []struct {
		code     uint16
		expected string
	}{
		{0x001d, "x25519"},
		{0x0017, "secp256r1"},
		{0x0018, "secp384r1"},
		{0x0019, "secp521r1"},
		{0x001e, "x448"},
		{0x0100, "ffdhe2048"},
		{0x0102, "ffdhe4096"},
		{0x9999, "Unknown(0x9999)"},
		{0x0000, "Unknown(0x0000)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := NamedGroupName(tc.code)
			if got != tc.expected {
				t.Errorf("NamedGroupName(0x%04x): expected '%s', got '%s'", tc.code, tc.expected, got)
			}
		})
	}
}

func TestSignatureAlgorithmName(t *testing.T) {
	tests := []struct {
		code     uint16
		expected string
	}{
		{0x0804, "rsa_pss_rsae_sha256"},
		{0x0403, "ecdsa_secp256r1_sha256"},
		{0x0201, "rsa_pkcs1_sha1"},
		{0x0401, "rsa_pkcs1_sha256"},
		{0x0503, "ecdsa_secp384r1_sha384"},
		{0x0807, "ed25519"},
		{0x0808, "ed448"},
		{0xAAAA, "Unknown(0xaaaa)"},
		{0x0000, "Unknown(0x0000)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := SignatureAlgorithmName(tc.code)
			if got != tc.expected {
				t.Errorf("SignatureAlgorithmName(0x%04x): expected '%s', got '%s'", tc.code, tc.expected, got)
			}
		})
	}
}
