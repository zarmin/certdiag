package tls

import (
	"crypto/md5"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

func TestIsGREASE(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xaaaa, 0xfafa, 0xdada}
	for _, v := range grease {
		if !isGREASE(v) {
			t.Errorf("0x%04x should be GREASE", v)
		}
	}
	notGrease := []uint16{0x1301, 0xc02f, 0x0000, 0x0b0b, 0x0a0b, 0x1234}
	for _, v := range notGrease {
		if isGREASE(v) {
			t.Errorf("0x%04x should not be GREASE", v)
		}
	}
}

func sampleClientHello() *ClientHelloMsg {
	return &ClientHelloMsg{
		Version:      VersionTLS12, // legacy 0x0303 = 771
		CipherSuites: []uint16{0x1301, 0x0a0a, 0xc02f}, // includes a GREASE value
		Extensions: []Extension{
			{Type: 0x1a1a}, // GREASE
			{Type: ExtServerName},
			{Type: ExtSupportedGroups},
			{Type: extECPointFormats, Data: []byte{0x01, 0x00}}, // 1 format: 0
			{Type: ExtALPN},
			{Type: ExtSignatureAlgs},
		},
		SupportedGroups:   []uint16{0x001d, 0x0a0a}, // x25519 + GREASE
		SNI:               "example.com",
		ALPNProtocols:     []string{"h2"},
		SignatureAlgs:     []uint16{0x0403},
		SupportedVersions: []Version{VersionTLS13, VersionTLS12},
	}
}

func TestJA3(t *testing.T) {
	ch := sampleClientHello()
	fp, raw := JA3(ch)

	wantRaw := "771,4865-49199,0-10-11-16-13,29,0"
	if raw != wantRaw {
		t.Errorf("JA3 raw = %q, want %q", raw, wantRaw)
	}
	sum := md5.Sum([]byte(wantRaw))
	if fp != hex.EncodeToString(sum[:]) {
		t.Errorf("JA3 fingerprint not md5 of raw")
	}
	if len(fp) != 32 {
		t.Errorf("JA3 fingerprint length = %d, want 32", len(fp))
	}
}

func TestJA4(t *testing.T) {
	ch := sampleClientHello()
	ja4 := JA4(ch)

	// Part a: t + version(13) + sni(d) + ciphers(02) + exts(05) + alpn(h2)
	// exts = 5 non-GREASE (ServerName, SupportedGroups, ECPointFormats, ALPN, SignatureAlgs)
	wantA := "t13d0205h2"
	if got := ja4[:len(wantA)]; got != wantA {
		t.Errorf("JA4 part a = %q, want %q", got, wantA)
	}
	re := regexp.MustCompile(`^t13d0205h2_[0-9a-f]{12}_[0-9a-f]{12}$`)
	if !re.MatchString(ja4) {
		t.Errorf("JA4 = %q does not match expected structure", ja4)
	}
	// Determinism.
	if JA4(sampleClientHello()) != ja4 {
		t.Error("JA4 is not deterministic")
	}
}

// TestJA4NoSignatureAlgs verifies the FoxIO rule: with no signature_algorithms
// extension the JA4_c string ends without a trailing underscore, so the _c hash
// is sha12 of the bare extension list.
// TestJA4ALPN covers the LOW ALPN rules: normal alphanumeric ALPNs take first
// and last chars; a non-alphanumeric first/last byte uses the hex fallback
// without UTF-8-mangling.
func TestJA4ALPN(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"h", "hh"},
		{"", "00"},
		{"\xab\xcd", "ad"}, // hex "abcd" -> first 'a', last 'd'
	}
	for _, tc := range cases {
		var in []string
		if tc.alpn != "" {
			in = []string{tc.alpn}
		}
		if got := ja4ALPN(in); got != tc.want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", tc.alpn, got, tc.want)
		}
		if len(ja4ALPN(in)) != 2 {
			t.Errorf("ja4ALPN(%q) must be exactly 2 chars, got %q", tc.alpn, ja4ALPN(in))
		}
	}
}

// TestJA4EmptySections is the LOW regression: an empty _b/_c section must be
// twelve zeros, not the hash of the empty string.
func TestJA4EmptySections(t *testing.T) {
	ch := &ClientHelloMsg{
		Version:      VersionTLS12,
		CipherSuites: nil, // no ciphers -> _b is 000000000000
		Extensions: []Extension{
			{Type: ExtServerName},
			{Type: ExtALPN}, // both stripped from _c -> _c is 000000000000
		},
		SNI:           "x",
		ALPNProtocols: []string{"h2"},
	}
	ja4 := JA4(ch)
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("unexpected JA4 shape: %q", ja4)
	}
	if parts[1] != "000000000000" {
		t.Errorf("_b = %q, want 000000000000", parts[1])
	}
	if parts[2] != "000000000000" {
		t.Errorf("_c = %q, want 000000000000", parts[2])
	}
}

func TestJA4NoSignatureAlgs(t *testing.T) {
	ch := sampleClientHello()
	// Drop the sig-algs extension and its values.
	var exts []Extension
	for _, e := range ch.Extensions {
		if e.Type != ExtSignatureAlgs {
			exts = append(exts, e)
		}
	}
	ch.Extensions = exts
	ch.SignatureAlgs = nil

	ja4 := JA4(ch)
	gotC := ja4[len(ja4)-12:]

	// _c extensions after removing SNI + ALPN: SupportedGroups(0x000a),
	// ECPointFormats(0x000b), sorted and comma-joined.
	wantC := sha12("000a,000b")
	if gotC != wantC {
		t.Errorf("JA4_c = %q, want %q (no trailing underscore when sig-algs empty)", gotC, wantC)
	}
	if withUnderscore := sha12("000a,000b_"); gotC == withUnderscore {
		t.Error("JA4_c still hashed the trailing underscore")
	}
}

func TestJA3JA4RealClientHello(t *testing.T) {
	c2s, _, _, _ := captureTLS13(t, 0)
	recs, _, err := ParseRecords(c2s)
	if err != nil || len(recs) == 0 {
		t.Fatalf("parse records: %v", err)
	}
	msgs, _ := ParseHandshakeMessages(recs[0].Payload)
	if len(msgs) == 0 || msgs[0].Type != HandshakeClientHello {
		t.Fatal("no ClientHello")
	}
	ch, err := ParseClientHello(msgs[0].Payload)
	if err != nil {
		t.Fatal(err)
	}

	fp, _ := JA3(ch)
	if len(fp) != 32 {
		t.Errorf("real JA3 length = %d", len(fp))
	}
	ja4 := JA4(ch)
	// A real Go ClientHello includes GREASE; a well-formed JA4 must still result.
	if !regexp.MustCompile(`^t(13|12)[di]\d{2}\d{2}..?_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(ja4) {
		t.Errorf("real JA4 malformed: %q", ja4)
	}
}
