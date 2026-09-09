package tls

import (
	"encoding/binary"
	"testing"
)

func TestParseExtensions_Multiple(t *testing.T) {
	// Build two extensions: SNI (type 0) and ALPN (type 16)
	sniData := buildSNIExtension("test.example.com")
	alpnData := buildALPNExtension([]string{"h2"})

	block := buildExtensionBlock([]Extension{
		{Type: ExtServerName, Data: sniData},
		{Type: ExtALPN, Data: alpnData},
	})

	exts, err := ParseExtensions(block)
	if err != nil {
		t.Fatalf("ParseExtensions error: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(exts))
	}
	if exts[0].Type != ExtServerName {
		t.Errorf("ext[0] type: expected %d, got %d", ExtServerName, exts[0].Type)
	}
	if exts[1].Type != ExtALPN {
		t.Errorf("ext[1] type: expected %d, got %d", ExtALPN, exts[1].Type)
	}
}

func TestParseExtensions_Empty(t *testing.T) {
	// Empty extensions block: total length = 0
	block := []byte{0x00, 0x00}
	exts, err := ParseExtensions(block)
	if err != nil {
		t.Fatalf("ParseExtensions error: %v", err)
	}
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(exts))
	}
}

func TestParseExtensions_TooShort(t *testing.T) {
	// Less than 2 bytes -> should return nil, nil
	exts, err := ParseExtensions([]byte{0x00})
	if err != nil {
		t.Fatalf("expected no error for short input, got %v", err)
	}
	if exts != nil {
		t.Errorf("expected nil extensions, got %d", len(exts))
	}
}

func TestParseExtensions_Truncated(t *testing.T) {
	// Claim 100 bytes but only provide 2
	block := []byte{0x00, 0x64, 0x00, 0x00}
	_, err := ParseExtensions(block)
	if err != ErrTruncated {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{"valid hostname", "example.com", "example.com"},
		{"subdomain", "sub.domain.example.com", "sub.domain.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildSNIExtension(tc.host)
			got := ExtractSNI(data)
			if got != tc.expected {
				t.Errorf("ExtractSNI: expected '%s', got '%s'", tc.expected, got)
			}
		})
	}
}

func TestExtractSNI_Empty(t *testing.T) {
	got := ExtractSNI([]byte{})
	if got != "" {
		t.Errorf("expected empty string for empty data, got '%s'", got)
	}
}

func TestExtractSNI_TooShort(t *testing.T) {
	got := ExtractSNI([]byte{0x00, 0x01, 0x00})
	if got != "" {
		t.Errorf("expected empty string for truncated data, got '%s'", got)
	}
}

func TestExtractSupportedVersions_Client(t *testing.T) {
	// Client mode: 1-byte listLen + version codes
	versions := []uint16{0x0304, 0x0303} // TLS 1.3, TLS 1.2
	data := buildSupportedVersionsClientExtension(versions)

	got := ExtractSupportedVersions(data, false)
	if len(got) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(got))
	}
	if got[0] != VersionTLS13 {
		t.Errorf("version[0]: expected TLS 1.3, got %s", got[0])
	}
	if got[1] != VersionTLS12 {
		t.Errorf("version[1]: expected TLS 1.2, got %s", got[1])
	}
}

func TestExtractSupportedVersions_Server(t *testing.T) {
	// Server mode: single 2-byte version
	data := buildSupportedVersionsServerExtension(0x0304)

	got := ExtractSupportedVersions(data, true)
	if len(got) != 1 {
		t.Fatalf("expected 1 version, got %d", len(got))
	}
	if got[0] != VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %s", got[0])
	}
}

func TestExtractSupportedVersions_EmptyClient(t *testing.T) {
	got := ExtractSupportedVersions([]byte{}, false)
	if got != nil {
		t.Errorf("expected nil for empty client data, got %v", got)
	}
}

func TestExtractSupportedVersions_EmptyServer(t *testing.T) {
	got := ExtractSupportedVersions([]byte{}, true)
	if got != nil {
		t.Errorf("expected nil for empty server data, got %v", got)
	}
}

func TestExtractALPN(t *testing.T) {
	tests := []struct {
		name     string
		protos   []string
		expected []string
	}{
		{"single protocol", []string{"h2"}, []string{"h2"}},
		{"multiple protocols", []string{"h2", "http/1.1"}, []string{"h2", "http/1.1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildALPNExtension(tc.protos)
			got := ExtractALPN(data)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %d protocols, got %d", len(tc.expected), len(got))
			}
			for i, p := range tc.expected {
				if got[i] != p {
					t.Errorf("protocol[%d]: expected '%s', got '%s'", i, p, got[i])
				}
			}
		})
	}
}

func TestExtractALPN_Empty(t *testing.T) {
	got := ExtractALPN([]byte{})
	if got != nil {
		t.Errorf("expected nil for empty data, got %v", got)
	}
}

func TestExtractSupportedGroups(t *testing.T) {
	groups := []uint16{0x0017, 0x001d, 0x0018} // secp256r1, x25519, secp384r1
	listLen := len(groups) * 2
	data := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(data[:2], uint16(listLen))
	for i, g := range groups {
		binary.BigEndian.PutUint16(data[2+i*2:], g)
	}

	got := ExtractSupportedGroups(data)
	if len(got) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(got))
	}
	for i, expected := range groups {
		if got[i] != expected {
			t.Errorf("group[%d]: expected 0x%04x, got 0x%04x", i, expected, got[i])
		}
	}
}

func TestExtractSupportedGroups_Empty(t *testing.T) {
	got := ExtractSupportedGroups([]byte{})
	if got != nil {
		t.Errorf("expected nil for empty data, got %v", got)
	}
}

func TestExtractSupportedGroups_ZeroLength(t *testing.T) {
	data := []byte{0x00, 0x00}
	got := ExtractSupportedGroups(data)
	if len(got) != 0 {
		t.Errorf("expected 0 groups, got %d", len(got))
	}
}

func TestExtractSignatureAlgorithms(t *testing.T) {
	algs := []uint16{0x0804, 0x0403, 0x0201} // rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, rsa_pkcs1_sha1
	listLen := len(algs) * 2
	data := make([]byte, 2+listLen)
	binary.BigEndian.PutUint16(data[:2], uint16(listLen))
	for i, a := range algs {
		binary.BigEndian.PutUint16(data[2+i*2:], a)
	}

	got := ExtractSignatureAlgorithms(data)
	if len(got) != 3 {
		t.Fatalf("expected 3 algorithms, got %d", len(got))
	}
	for i, expected := range algs {
		if got[i] != expected {
			t.Errorf("alg[%d]: expected 0x%04x, got 0x%04x", i, expected, got[i])
		}
	}
}

func TestExtractSignatureAlgorithms_Empty(t *testing.T) {
	got := ExtractSignatureAlgorithms([]byte{})
	if got != nil {
		t.Errorf("expected nil for empty data, got %v", got)
	}
}

func TestExtractSignatureAlgorithms_ZeroLength(t *testing.T) {
	data := []byte{0x00, 0x00}
	got := ExtractSignatureAlgorithms(data)
	if len(got) != 0 {
		t.Errorf("expected 0 algorithms, got %d", len(got))
	}
}
