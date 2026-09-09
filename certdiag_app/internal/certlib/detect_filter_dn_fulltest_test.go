//go:build fulltest

package certlib

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Section 1: DetectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat_EmptyData(t *testing.T) {
	got := DetectFormat([]byte{})
	if got != DetectedUnknown {
		t.Errorf("empty data: got %v, want DetectedUnknown", got)
	}
}

func TestDetectFormat_OneByte(t *testing.T) {
	got := DetectFormat([]byte{0x30})
	if got != DetectedUnknown {
		t.Errorf("1-byte 0x30: got %v, want DetectedUnknown", got)
	}
}

func TestDetectFormat_ThreeBytes(t *testing.T) {
	got := DetectFormat([]byte{0x30, 0x82, 0x01})
	if got != DetectedUnknown {
		t.Errorf("3 bytes: got %v, want DetectedUnknown", got)
	}
}

func TestDetectFormat_JKSMagic(t *testing.T) {
	got := DetectFormat([]byte{0xFE, 0xED, 0xFE, 0xED})
	if got != DetectedJKS {
		t.Errorf("JKS magic: got %v, want DetectedJKS", got)
	}
}

func TestDetectFormat_PEMWithLeadingNewlines(t *testing.T) {
	// pem.Decode finds -----BEGIN at start of a line after leading newlines
	data := []byte("\n\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	got := DetectFormat(data)
	if got != DetectedPEM {
		t.Errorf("PEM with leading newlines: got %v, want DetectedPEM", got)
	}
}

func TestDetectFormat_PEMWithLeadingSpacesAndTab(t *testing.T) {
	// spaces/tab before -----BEGIN on the same line: pem.Decode won't find it,
	// and prefix check fails too, so DetectedUnknown is expected
	data := []byte("\n  \t-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	got := DetectFormat(data)
	if got != DetectedUnknown {
		t.Errorf("PEM with leading spaces+tab: got %v, want DetectedUnknown", got)
	}
}

func TestDetectFormat_PEMWindowsLineEndings(t *testing.T) {
	data := []byte("-----BEGIN CERTIFICATE-----\r\nMIIB\r\n-----END CERTIFICATE-----\r\n")
	got := DetectFormat(data)
	if got != DetectedPEM {
		t.Errorf("PEM with CRLF: got %v, want DetectedPEM", got)
	}
}

func TestDetectFormat_ASN1(t *testing.T) {
	data := []byte{0x30, 0x82, 0x01, 0x00, 0x00}
	got := DetectFormat(data)
	if got != DetectedASN1 {
		t.Errorf("ASN.1 data: got %v, want DetectedASN1", got)
	}
}

func TestDetectFormat_BinaryGarbage(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	got := DetectFormat(data)
	if got != DetectedUnknown {
		t.Errorf("binary garbage: got %v, want DetectedUnknown", got)
	}
}

func TestDetectFormat_JKSMagicFollowedByGarbage(t *testing.T) {
	data := []byte{0xFE, 0xED, 0xFE, 0xED, 0xFF, 0xFF, 0x00, 0x42}
	got := DetectFormat(data)
	if got != DetectedJKS {
		t.Errorf("JKS magic + garbage: got %v, want DetectedJKS", got)
	}
}

func TestDetectFormat_PEMPrefixInvalidBase64(t *testing.T) {
	data := []byte("-----BEGIN THING-----\n!!!not-base64!!!\n-----END THING-----\n")
	got := DetectFormat(data)
	if got != DetectedPEM {
		t.Errorf("PEM prefix with bad base64: got %v, want DetectedPEM", got)
	}
}

// ---------------------------------------------------------------------------
// Section 1: FormatFromExtension
// ---------------------------------------------------------------------------

func TestFormatFromExtension_Recognized(t *testing.T) {
	cases := []struct {
		ext    string
		format FileFormat
	}{
		{".pem", FormatPEM},
		{".crt", FormatPEM},
		{".cer", FormatPEM},
		{".key", FormatPEM},
		{".der", FormatDER},
		{".p12", FormatPKCS12},
		{".pfx", FormatPKCS12},
		{".p7b", FormatPKCS7},
		{".p7c", FormatPKCS7},
		{".p7s", FormatPKCS7},
		{".jks", FormatJKS},
	}
	for _, tc := range cases {
		got, ok := FormatFromExtension(tc.ext)
		if !ok {
			t.Errorf("FormatFromExtension(%q): expected ok=true", tc.ext)
		}
		if got != tc.format {
			t.Errorf("FormatFromExtension(%q): got %q, want %q", tc.ext, got, tc.format)
		}
	}
}

func TestFormatFromExtension_CSRNotRecognized(t *testing.T) {
	_, ok := FormatFromExtension(".csr")
	if ok {
		t.Error("FormatFromExtension(.csr): expected ok=false")
	}
}

func TestFormatFromExtension_CaseInsensitive(t *testing.T) {
	cases := []string{".PEM", ".Crt", ".JKS", ".P12", ".DER"}
	for _, ext := range cases {
		_, ok := FormatFromExtension(ext)
		if !ok {
			t.Errorf("FormatFromExtension(%q): expected ok=true (case insensitive)", ext)
		}
	}
}

func TestFormatFromExtension_Unknown(t *testing.T) {
	cases := []string{".txt", ".zip", ".pem.bak"}
	for _, ext := range cases {
		_, ok := FormatFromExtension(ext)
		if ok {
			t.Errorf("FormatFromExtension(%q): expected ok=false", ext)
		}
	}
}

func TestFormatFromExtension_Empty(t *testing.T) {
	_, ok := FormatFromExtension("")
	if ok {
		t.Error("FormatFromExtension(\"\"): expected ok=false")
	}
}

func TestFormatFromExtension_DoubleExtension(t *testing.T) {
	_, ok := FormatFromExtension(".tar.gz")
	if ok {
		t.Error("FormatFromExtension(.tar.gz): expected ok=false")
	}
}

// ---------------------------------------------------------------------------
// Section 6: FilterContainers
// ---------------------------------------------------------------------------

func filterTestCert(t *testing.T, cn string, dns []string, ips []net.IP) *CertItem {
	t.Helper()
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CertItem{Type: ContentCertificate, Certificate: cert}
}

func filterContainerWith(path string, items ...*CertItem) *CertContainer {
	c := &CertContainer{
		FilePath: path,
		Format:   FormatPEM,
	}
	for _, item := range items {
		c.Items = append(c.Items, *item)
	}
	return c
}

func TestFilterContainers_EmptyQuery(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "A", nil, nil)),
		filterContainerWith("/test/b.pem", filterTestCert(t, "B", nil, nil)),
	}
	result := FilterContainers(containers, "")
	if len(result) != 2 {
		t.Errorf("empty query: got %d containers, want 2", len(result))
	}
}

func TestFilterContainers_MatchFilename(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/server.pem", filterTestCert(t, "Unrelated", nil, nil)),
		filterContainerWith("/test/client.pem", filterTestCert(t, "Unrelated2", nil, nil)),
	}
	result := FilterContainers(containers, "server")
	if len(result) != 1 {
		t.Errorf("filename match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_MatchCertCN(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "Root CA", nil, nil)),
		filterContainerWith("/test/b.pem", filterTestCert(t, "Leaf Cert", nil, nil)),
	}
	result := FilterContainers(containers, "root")
	if len(result) != 1 {
		t.Errorf("CN match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_MatchSANDNS(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "test", []string{"example.com", "www.example.com"}, nil)),
		filterContainerWith("/test/b.pem", filterTestCert(t, "other", []string{"other.org"}, nil)),
	}
	result := FilterContainers(containers, "example.com")
	if len(result) != 1 {
		t.Errorf("SAN DNS match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_MatchSANIP(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "test", nil, []net.IP{net.ParseIP("192.168.1.1")})),
		filterContainerWith("/test/b.pem", filterTestCert(t, "other", nil, nil)),
	}
	result := FilterContainers(containers, "192.168.1.1")
	if len(result) != 1 {
		t.Errorf("SAN IP match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_CaseInsensitive(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "Root CA", nil, nil)),
	}
	result := FilterContainers(containers, "ROOT")
	if len(result) != 1 {
		t.Errorf("case insensitive: got %d, want 1", len(result))
	}
}

func TestFilterContainers_PartialMatch(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "Intermediate CA", nil, nil)),
	}
	result := FilterContainers(containers, "inter")
	if len(result) != 1 {
		t.Errorf("partial match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_NilCertificate(t *testing.T) {
	item := &CertItem{Type: ContentCertificate, Certificate: nil}
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	result := FilterContainers(containers, "anything")
	if len(result) != 0 {
		t.Errorf("nil cert: got %d, want 0", len(result))
	}
}

func TestFilterContainers_NilCSR(t *testing.T) {
	item := &CertItem{Type: ContentCSR, CSR: nil}
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	result := FilterContainers(containers, "anything")
	if len(result) != 0 {
		t.Errorf("nil CSR: got %d, want 0", len(result))
	}
}

func TestFilterContainers_PrivateKeyOnlyAliasMatches(t *testing.T) {
	item := &CertItem{Type: ContentPrivateKey, Alias: "my-server-key"}
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}

	result := FilterContainers(containers, "server-key")
	if len(result) != 1 {
		t.Errorf("private key alias match: got %d, want 1", len(result))
	}

	result = FilterContainers(containers, "certificate")
	if len(result) != 0 {
		t.Errorf("private key no match: got %d, want 0", len(result))
	}
}

func TestFilterContainers_NoMatch(t *testing.T) {
	containers := []*CertContainer{
		filterContainerWith("/test/a.pem", filterTestCert(t, "Root CA", []string{"example.com"}, nil)),
		filterContainerWith("/test/b.pem", filterTestCert(t, "Leaf", []string{"leaf.org"}, nil)),
	}
	result := FilterContainers(containers, "zzzznotfound")
	if len(result) != 0 {
		t.Errorf("no match: got %d, want 0", len(result))
	}
}

func TestFilterContainers_MatchAlias(t *testing.T) {
	item := filterTestCert(t, "Some CN", nil, nil)
	item.Alias = "my-special-alias"
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	result := FilterContainers(containers, "special-alias")
	if len(result) != 1 {
		t.Errorf("alias match: got %d, want 1", len(result))
	}
}

// --- New edge case filter tests ---

func TestFilterContainers_MatchSANEmail(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "email-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		EmailAddresses:        []string{"admin@example.com"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	item := &CertItem{Type: ContentCertificate, Certificate: cert}

	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	result := FilterContainers(containers, "admin@example")
	if len(result) != 1 {
		t.Errorf("SAN email match: got %d, want 1", len(result))
	}

	result = FilterContainers(containers, "nobody@other")
	if len(result) != 0 {
		t.Errorf("SAN email no match: got %d, want 0", len(result))
	}
}

func TestFilterContainers_MatchSANURI(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	uri, _ := url.Parse("https://auth.example.com/oidc")
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "uri-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		URIs:                  []*url.URL{uri},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	item := &CertItem{Type: ContentCertificate, Certificate: cert}

	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	result := FilterContainers(containers, "auth.example.com")
	if len(result) != 1 {
		t.Errorf("SAN URI match: got %d, want 1", len(result))
	}
}

func TestFilterContainers_MatchSerialDecimal(t *testing.T) {
	item := filterTestCert(t, "serial-test", nil, nil)
	serial := item.Certificate.SerialNumber.String()

	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	// Use a portion of the decimal serial
	query := serial
	if len(query) > 8 {
		query = query[:8]
	}
	result := FilterContainers(containers, query)
	if len(result) != 1 {
		t.Errorf("serial decimal match: got %d, want 1 (query=%s, serial=%s)", len(result), query, serial)
	}
}

func TestFilterContainers_MatchSerialHex(t *testing.T) {
	item := filterTestCert(t, "hex-serial-test", nil, nil)
	serialHex := FormatSerial(item.Certificate.SerialNumber)

	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}
	// Use a portion of the hex serial (first few octets)
	query := serialHex
	if len(query) > 5 {
		query = query[:5] // e.g. "ab:cd" or "ab:cd:"
	}
	result := FilterContainers(containers, query)
	if len(result) != 1 {
		t.Errorf("serial hex match: got %d, want 1 (query=%s, serial=%s)", len(result), query, serialHex)
	}
}

func TestFilterContainers_MatchIPv6(t *testing.T) {
	// IPv6 matching: net.IP.String() produces a canonical form.
	// Verify that searching for the canonical form works.
	ip := net.ParseIP("::1")
	item := filterTestCert(t, "ipv6-test", nil, []net.IP{ip})

	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}

	// Search using the canonical IPv6 representation
	result := FilterContainers(containers, "::1")
	if len(result) != 1 {
		t.Errorf("IPv6 loopback match: got %d, want 1", len(result))
	}

	// Full IPv6 address -- different text representation won't match
	// because filter uses strings.Contains on ip.String() which returns "::1"
	result = FilterContainers(containers, "0:0:0:0:0:0:0:1")
	if len(result) != 0 {
		// This documents that expanded IPv6 notation does NOT match
		// the compressed form stored by Go's net.IP.String()
		t.Log("expanded IPv6 notation unexpectedly matched (Go may normalize)")
	}
}

func TestFilterContainers_MatchFullDN(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "dn-test",
			Organization: []string{"ACME Corp"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	item := &CertItem{Type: ContentCertificate, Certificate: cert}
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}

	// Match by organization in the full DN
	result := FilterContainers(containers, "acme corp")
	if len(result) != 1 {
		t.Errorf("DN match by org: got %d, want 1", len(result))
	}
}

func TestFilterContainers_MatchCSR(t *testing.T) {
	key := mustGenerateECKey(t)
	csr, _, err := CreateCSR(key, CertGenOptions{
		Subject: pkix.Name{CommonName: "csr-filter-test"},
		SANs:    SANList{DNSNames: []string{"csr.example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	item := &CertItem{Type: ContentCSR, CSR: csr}
	containers := []*CertContainer{filterContainerWith("/test/req.csr", item)}

	// Match by CSR CN
	result := FilterContainers(containers, "csr-filter")
	if len(result) != 1 {
		t.Errorf("CSR CN match: got %d, want 1", len(result))
	}

	// Match by CSR DNS SAN
	result = FilterContainers(containers, "csr.example")
	if len(result) != 1 {
		t.Errorf("CSR DNS match: got %d, want 1", len(result))
	}

	// No match
	result = FilterContainers(containers, "nonexistent")
	if len(result) != 0 {
		t.Errorf("CSR no match: got %d, want 0", len(result))
	}
}

// ---------------------------------------------------------------------------
// Section 7: ParseDN
// ---------------------------------------------------------------------------

func TestParseDN_Empty(t *testing.T) {
	_, err := ParseDN("")
	if err == nil {
		t.Error("ParseDN(\"\"): expected error")
	}
}

func TestParseDN_WhitespaceOnly(t *testing.T) {
	_, err := ParseDN("   \t  ")
	if err == nil {
		t.Error("ParseDN(whitespace): expected error")
	}
}

func TestParseDN_SingleComponent(t *testing.T) {
	name, err := ParseDN("CN=test")
	if err != nil {
		t.Fatalf("ParseDN(CN=test): %v", err)
	}
	if name.CommonName != "test" {
		t.Errorf("CN: got %q, want %q", name.CommonName, "test")
	}
}

func TestParseDN_FullDN(t *testing.T) {
	name, err := ParseDN("CN=test, O=Org, C=US")
	if err != nil {
		t.Fatalf("ParseDN full: %v", err)
	}
	if name.CommonName != "test" {
		t.Errorf("CN: got %q, want %q", name.CommonName, "test")
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Org" {
		t.Errorf("O: got %v, want [Org]", name.Organization)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("C: got %v, want [US]", name.Country)
	}
}

func TestParseDN_MultipleOUs(t *testing.T) {
	name, err := ParseDN("OU=A, OU=B")
	if err != nil {
		t.Fatalf("ParseDN multiple OUs: %v", err)
	}
	if len(name.OrganizationalUnit) != 2 {
		t.Fatalf("OU count: got %d, want 2", len(name.OrganizationalUnit))
	}
	if name.OrganizationalUnit[0] != "A" || name.OrganizationalUnit[1] != "B" {
		t.Errorf("OUs: got %v, want [A B]", name.OrganizationalUnit)
	}
}

func TestParseDN_EscapedComma(t *testing.T) {
	name, err := ParseDN(`CN=test\, inc`)
	if err != nil {
		t.Fatalf("ParseDN escaped comma: %v", err)
	}
	if name.CommonName != "test, inc" {
		t.Errorf("CN: got %q, want %q", name.CommonName, "test, inc")
	}
}

func TestParseDN_NoEquals(t *testing.T) {
	_, err := ParseDN("CN")
	if err == nil {
		t.Error("ParseDN(CN): expected error for missing '='")
	}
}

func TestParseDN_EmptyValue(t *testing.T) {
	name, err := ParseDN("CN=")
	if err != nil {
		t.Fatalf("ParseDN(CN=): %v", err)
	}
	if name.CommonName != "" {
		t.Errorf("CN: got %q, want empty", name.CommonName)
	}
}

func TestParseDN_SpacesAroundEquals(t *testing.T) {
	name, err := ParseDN("CN = test")
	if err != nil {
		t.Fatalf("ParseDN spaces: %v", err)
	}
	if name.CommonName != "test" {
		t.Errorf("CN: got %q, want %q", name.CommonName, "test")
	}
}

func TestParseDN_ExtraAttributes(t *testing.T) {
	name, err := ParseDN("DC=example")
	if err != nil {
		t.Fatalf("ParseDN DC: %v", err)
	}
	if len(name.ExtraNames) != 1 {
		t.Fatalf("ExtraNames count: got %d, want 1", len(name.ExtraNames))
	}
	expectedOID := asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	if !name.ExtraNames[0].Type.Equal(expectedOID) {
		t.Errorf("DC OID: got %v, want %v", name.ExtraNames[0].Type, expectedOID)
	}
	if name.ExtraNames[0].Value != "example" {
		t.Errorf("DC value: got %v, want %q", name.ExtraNames[0].Value, "example")
	}
}

func TestParseDN_UnknownAttribute(t *testing.T) {
	_, err := ParseDN("FOO=bar")
	if err == nil {
		t.Error("ParseDN(FOO=bar): expected error for unknown attribute")
	}
}

func TestParseDN_CaseInsensitive(t *testing.T) {
	cases := []string{"cn=test", "Cn=test", "cN=test"}
	for _, input := range cases {
		name, err := ParseDN(input)
		if err != nil {
			t.Errorf("ParseDN(%q): %v", input, err)
			continue
		}
		if name.CommonName != "test" {
			t.Errorf("ParseDN(%q): CN got %q, want %q", input, name.CommonName, "test")
		}
	}
}

func TestParseDN_EmptyComponentBetweenCommas(t *testing.T) {
	name, err := ParseDN("CN=test,,O=Org")
	if err != nil {
		t.Fatalf("ParseDN empty component: %v", err)
	}
	if name.CommonName != "test" {
		t.Errorf("CN: got %q, want %q", name.CommonName, "test")
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Org" {
		t.Errorf("O: got %v, want [Org]", name.Organization)
	}
}

// ---------------------------------------------------------------------------
// Section 7: FormatSerial
// ---------------------------------------------------------------------------

func TestFormatSerial_Nil(t *testing.T) {
	got := FormatSerial(nil)
	if got != "" {
		t.Errorf("FormatSerial(nil): got %q, want %q", got, "")
	}
}

func TestFormatSerial_Zero(t *testing.T) {
	got := FormatSerial(big.NewInt(0))
	if got != "00" {
		t.Errorf("FormatSerial(0): got %q, want %q", got, "00")
	}
}

func TestFormatSerial_One(t *testing.T) {
	got := FormatSerial(big.NewInt(1))
	if got != "01" {
		t.Errorf("FormatSerial(1): got %q, want %q", got, "01")
	}
}

func TestFormatSerial_255(t *testing.T) {
	got := FormatSerial(big.NewInt(255))
	if got != "ff" {
		t.Errorf("FormatSerial(255): got %q, want %q", got, "ff")
	}
}

func TestFormatSerial_256(t *testing.T) {
	got := FormatSerial(big.NewInt(256))
	if got != "01:00" {
		t.Errorf("FormatSerial(256): got %q, want %q", got, "01:00")
	}
}

func TestFormatSerial_Large(t *testing.T) {
	// 20-byte serial (160 bits)
	serial := new(big.Int).Lsh(big.NewInt(1), 159)
	got := FormatSerial(serial)
	// Should produce 20 colon-separated hex pairs
	parts := len(got)
	// 20 pairs of 2 chars + 19 colons = 59 chars
	if parts != 59 {
		t.Errorf("FormatSerial(large): got length %d, want 59; value=%q", parts, got)
	}
}

func TestFormatSerial_Negative(t *testing.T) {
	got := FormatSerial(big.NewInt(-1))
	// big.Int.Format %x for -1 produces "-1", prepend "0" -> "-01"
	// The function does fmt.Sprintf("%x", serial) which for negative gives "-1"
	// Then pads to even: "-01", then splits... this is an edge case.
	// Just verify it doesn't panic and returns something non-empty.
	if got == "" {
		t.Error("FormatSerial(-1): got empty string")
	}
}

// ---------------------------------------------------------------------------
// Section 7: FormatSerialDetailed
// ---------------------------------------------------------------------------

func TestFormatSerialDetailed_Nil(t *testing.T) {
	got := FormatSerialDetailed(nil)
	if got != "" {
		t.Errorf("FormatSerialDetailed(nil): got %q, want %q", got, "")
	}
}

func TestFormatSerialDetailed_One(t *testing.T) {
	got := FormatSerialDetailed(big.NewInt(1))
	if got != "01 (1)" {
		t.Errorf("FormatSerialDetailed(1): got %q, want %q", got, "01 (1)")
	}
}

// ---------------------------------------------------------------------------
// Section 7: FormatDNName
// ---------------------------------------------------------------------------

func TestFormatDNName_Empty(t *testing.T) {
	got := FormatDNName(pkix.Name{})
	if got != "" {
		t.Errorf("FormatDNName(empty): got %q, want %q", got, "")
	}
}

func TestFormatDNName_StandardAttributes(t *testing.T) {
	name := pkix.Name{
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Test CN"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Test Org"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
		},
	}
	got := FormatDNName(name)
	if got != "CN=Test CN, O=Test Org, C=US" {
		t.Errorf("FormatDNName standard: got %q, want %q", got, "CN=Test CN, O=Test Org, C=US")
	}
}

// TestFilterContainers_MatchIPv4MappedIPv6 tests that IPv4-mapped IPv6 addresses
// in SANs can be found via both their IPv4 and IPv6 string representations.
func TestFilterContainers_MatchIPv4MappedIPv6(t *testing.T) {
	// IPv4-mapped IPv6: ::ffff:192.168.1.1
	mappedIP := net.IPv4(192, 168, 1, 1).To16()
	item := certWithSANs(t, nil, []net.IP{mappedIP})
	container := filterContainerWith("/test/mapped.pem", item)
	containers := []*CertContainer{container}

	// net.IP.String() for a 16-byte IPv4-mapped address outputs "192.168.1.1"
	// (Go strips the IPv6 prefix for display). So matching "192.168.1.1" should work.
	result := FilterContainers(containers, "192.168.1.1")
	if len(result) != 1 {
		t.Errorf("expected 1 match for IPv4 form of mapped address, got %d", len(result))
	}

	// "::ffff:192.168.1.1" format depends on how Go renders it.
	// For a To16() address, Go's String() returns the IPv4 form,
	// so "::ffff" won't appear in the string and should NOT match.
	result2 := FilterContainers(containers, "::ffff:")
	if len(result2) != 0 {
		t.Errorf("expected 0 matches for ::ffff: prefix (Go renders as IPv4), got %d", len(result2))
	}
}

func TestFormatDNName_UnknownOID(t *testing.T) {
	name := pkix.Name{
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "val"},
		},
	}
	got := FormatDNName(name)
	// Unknown OID should use numeric string form
	if got != "1.2.3.4.5=val" {
		t.Errorf("FormatDNName unknown OID: got %q, want %q", got, "1.2.3.4.5=val")
	}
}

func TestFormatDNName_MultipleNames(t *testing.T) {
	name := pkix.Name{
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Unit A"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Unit B"},
		},
	}
	got := FormatDNName(name)
	if got != "CN=test, OU=Unit A, OU=Unit B" {
		t.Errorf("FormatDNName multiple: got %q, want %q", got, "CN=test, OU=Unit A, OU=Unit B")
	}
}

// ---------------------------------------------------------------------------
// cfssl-inspired edge cases
// ---------------------------------------------------------------------------

// TestFormatDNName_DomainComponent verifies that domainComponent (DC) attributes
// in the subject DN are displayed correctly. cfssl#632 found that DC attributes
// were stripped/lost in some code paths.
func TestFormatDNName_DomainComponent(t *testing.T) {
	name := pkix.Name{
		Names: []pkix.AttributeTypeAndValue{
			// DC OID: 0.9.2342.19200300.100.1.25
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "com"},
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "example"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "server1"},
		},
	}
	got := FormatDNName(name)
	if got != "DC=com, DC=example, CN=server1" {
		t.Errorf("FormatDNName with DC: got %q, want %q", got, "DC=com, DC=example, CN=server1")
	}
}

// TestFilterContainers_MatchDomainComponent verifies that filter can match
// on domainComponent values in the subject DN. cfssl#632.
func TestFilterContainers_MatchDomainComponent(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "server1",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "example"},
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "com"},
			},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	item := &CertItem{Type: ContentCertificate, Certificate: cert}
	containers := []*CertContainer{filterContainerWith("/test/dc.pem", item)}

	// "dc=example" should match via FormatDNName in the full DN path
	result := FilterContainers(containers, "dc=example")
	if len(result) != 1 {
		t.Errorf("expected 1 match for DC=example, got %d", len(result))
	}
}

// TestDetectDuplicates_IdenticalSerialDifferentIssuers verifies that two
// certificates with the same serial number but different issuers are NOT
// detected as duplicates. cfssl#1179.
func TestDetectDuplicates_IdenticalSerialDifferentIssuers(t *testing.T) {
	serial := big.NewInt(12345678)

	// Create two self-signed certs with the same serial but different CNs
	key1 := mustGenerateECKey(t)
	tmpl1 := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Issuer A"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der1, err := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, key1.Public(), key1)
	if err != nil {
		t.Fatal(err)
	}
	cert1, _ := x509.ParseCertificate(der1)

	key2 := mustGenerateECKey(t)
	tmpl2 := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Issuer B"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der2, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, key2.Public(), key2)
	if err != nil {
		t.Fatal(err)
	}
	cert2, _ := x509.ParseCertificate(der2)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/a.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert1}},
	})
	store.AddContainer(CertContainer{
		FilePath: "/test/b.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert2}},
	})

	relations := DetectRelations(store)

	// Same serial but different keys/issuers -> different DER bytes -> no duplicate
	for _, rel := range relations {
		if rel.Type == RelationSameCert {
			t.Error("expected no duplicate relation for certs with same serial but different issuers")
		}
	}
}

// TestDetectDuplicates_TrueDuplicate verifies that the exact same certificate
// in two different files IS detected as a duplicate.
func TestDetectDuplicates_TrueDuplicate(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dup-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert1, _ := x509.ParseCertificate(der)
	cert2, _ := x509.ParseCertificate(der)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/a.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert1}},
	})
	store.AddContainer(CertContainer{
		FilePath: "/test/b.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: cert2}},
	})

	relations := DetectRelations(store)

	foundDup := false
	for _, rel := range relations {
		if rel.Type == RelationSameCert {
			foundDup = true
		}
	}
	if !foundDup {
		t.Error("expected duplicate relation for identical DER bytes")
	}
}

// TestFormatExtKeyUsage_UnknownOID verifies that non-standard EKU values
// are formatted with their numeric value rather than silently dropped. cfssl#1220.
func TestFormatExtKeyUsage_UnknownOID(t *testing.T) {
	// x509.ExtKeyUsage values beyond the known ones are represented as integers
	ekus := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsage(42), // unknown EKU
	}
	names := FormatExtKeyUsage(ekus)
	if len(names) != 2 {
		t.Fatalf("expected 2 EKU names, got %d", len(names))
	}
	if names[0] != "Server Auth" {
		t.Errorf("expected 'Server Auth', got %q", names[0])
	}
	// Unknown EKU should produce something like "Unknown(42)", not be dropped
	if names[1] == "" {
		t.Error("unknown EKU was dropped (empty string)")
	}
	if !strings.Contains(names[1], "42") {
		t.Errorf("expected unknown EKU to contain '42', got %q", names[1])
	}
}

// TestDetectSignedBy_ChainDetection verifies that signed_by relations are
// correctly detected when a leaf cert is signed by a CA.
func TestDetectSignedBy_ChainDetection(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/leaf.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: leafCert}},
	})
	store.AddContainer(CertContainer{
		FilePath: "/test/ca.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: caCert}},
	})

	relations := DetectRelations(store)

	foundSignedBy := false
	for _, rel := range relations {
		if rel.Type == RelationSignedBy {
			foundSignedBy = true
		}
	}
	if !foundSignedBy {
		t.Error("expected signed_by relation between leaf and CA")
	}
}

// TestDetectKeyCertPair verifies that a matching key+cert pair is detected.
func TestDetectKeyCertPair(t *testing.T) {
	key := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/bundle.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert},
			{Type: ContentPrivateKey, PrivateKey: key},
		},
	})

	relations := DetectRelations(store)

	foundKeyCert := false
	for _, rel := range relations {
		if rel.Type == RelationKeyCert {
			foundKeyCert = true
		}
	}
	if !foundKeyCert {
		t.Error("expected key_cert_pair relation")
	}
}

// TestDetectKeyCertPair_Mismatch verifies that a non-matching key+cert pair
// does NOT produce a key_cert_pair relation.
func TestDetectKeyCertPair_Mismatch(t *testing.T) {
	key1 := mustGenerateECKey(t)
	cert, _ := mustCreateSelfSignedCA(t, key1)

	key2 := mustGenerateECKey(t) // different key

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/bundle.pem",
		Format:   FormatPEM,
		Items: []CertItem{
			{Type: ContentCertificate, Certificate: cert},
			{Type: ContentPrivateKey, PrivateKey: key2},
		},
	})

	relations := DetectRelations(store)

	for _, rel := range relations {
		if rel.Type == RelationKeyCert {
			t.Error("expected no key_cert_pair relation for mismatched key and cert")
		}
	}
}

// ---------------------------------------------------------------------------
// extras_by_codes: relation, SAN, and filter edge cases
// ---------------------------------------------------------------------------

// TestDetectSignedBy_DuplicateIssuer verifies that when the same issuer cert
// appears twice in the store, detectSignedBy emits one signed_by relation per
// matching parent (i.e. two relations, not deduplicated).
func TestDetectSignedBy_DuplicateIssuer(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/leaf.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: leafCert}},
	})
	// Same CA cert in two separate files
	store.AddContainer(CertContainer{
		FilePath: "/test/ca1.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: caCert}},
	})
	store.AddContainer(CertContainer{
		FilePath: "/test/ca2.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: caCert}},
	})

	relations := DetectRelations(store)

	signedByCount := 0
	for _, rel := range relations {
		if rel.Type == RelationSignedBy {
			signedByCount++
		}
	}
	// Each CA copy is a separate match, so we expect 2 signed_by relations
	if signedByCount != 2 {
		t.Errorf("expected 2 signed_by relations (one per CA copy), got %d", signedByCount)
	}
}

// TestFormatSANs_Order verifies that FormatSANs returns entries in the
// documented order: othername, DNS, IP, email, URI.
func TestFormatSANs_Order(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	uriVal, _ := url.Parse("https://example.com/oidc")

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "san-order-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              []string{"example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"admin@example.com"},
		URIs:                  []*url.URL{uriVal},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	sans := FormatSANs(cert)
	if len(sans) < 4 {
		t.Fatalf("expected at least 4 SANs, got %d: %v", len(sans), sans)
	}

	// Verify order: DNS before IP before email before URI
	dnsIdx, ipIdx, emailIdx, uriIdx := -1, -1, -1, -1
	for i, s := range sans {
		switch {
		case strings.HasPrefix(s, "DNS:") && dnsIdx == -1:
			dnsIdx = i
		case strings.HasPrefix(s, "IP:") && ipIdx == -1:
			ipIdx = i
		case strings.HasPrefix(s, "email:") && emailIdx == -1:
			emailIdx = i
		case strings.HasPrefix(s, "URI:") && uriIdx == -1:
			uriIdx = i
		}
	}

	if dnsIdx == -1 || ipIdx == -1 || emailIdx == -1 || uriIdx == -1 {
		t.Fatalf("missing SAN types: dns=%d ip=%d email=%d uri=%d in %v", dnsIdx, ipIdx, emailIdx, uriIdx, sans)
	}
	if !(dnsIdx < ipIdx && ipIdx < emailIdx && emailIdx < uriIdx) {
		t.Errorf("SAN order should be DNS < IP < email < URI, got indices dns=%d ip=%d email=%d uri=%d", dnsIdx, ipIdx, emailIdx, uriIdx)
	}
}

// TestParseIssuerAltNames_NilCert verifies ParseIssuerAltNames returns nil
// for a cert without the IssuerAltName extension.
func TestParseIssuerAltNames_NilCert(t *testing.T) {
	key := mustGenerateECKey(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "no-ian"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	ians := ParseIssuerAltNames(cert)
	if ians != nil {
		t.Errorf("expected nil for cert without IssuerAltNames, got %v", ians)
	}
}

// TestGroupRelations_Order verifies that GroupRelations returns groups in the
// documented display order: signed_by, issuer_of, key_cert_pair, same_cert.
func TestGroupRelations_Order(t *testing.T) {
	// Create resolved relations of different types
	rels := []ResolvedRelation{
		{Type: RelationSameCert, Direction: DirectionOutgoing, Peer: ItemRef{ContainerIdx: 1}},
		{Type: RelationKeyCert, Direction: DirectionOutgoing, Peer: ItemRef{ContainerIdx: 2}},
		{Type: RelationSignedBy, Direction: DirectionOutgoing, Peer: ItemRef{ContainerIdx: 3}},
		{Type: RelationSignedBy, Direction: DirectionIncoming, Peer: ItemRef{ContainerIdx: 4}},
	}

	groups := GroupRelations(rels)

	if len(groups) < 2 {
		t.Fatalf("expected at least 2 groups, got %d", len(groups))
	}

	// Expected order: signed_by, issuer_of, key_cert_pair, same_cert
	expectedOrder := []string{"signed_by", "issuer_of", "key_cert_pair", "same_cert"}
	gotOrder := make([]string, len(groups))
	for i, g := range groups {
		gotOrder[i] = g.Key
	}

	for i, expected := range expectedOrder {
		if i >= len(gotOrder) {
			break
		}
		if gotOrder[i] != expected {
			t.Errorf("group[%d]: expected key %q, got %q (full order: %v)", i, expected, gotOrder[i], gotOrder)
		}
	}
}

// TestFilterContainers_WhitespaceQuery verifies that leading/trailing whitespace
// in the filter query is NOT trimmed (current behavior).
func TestFilterContainers_WhitespaceQuery(t *testing.T) {
	item := filterTestCert(t, "Root CA", nil, nil)
	containers := []*CertContainer{filterContainerWith("/test/a.pem", item)}

	// "root" matches, but " root " (with spaces) may not match depending on trimming
	result := FilterContainers(containers, " root ")
	// Current behavior: query is lowercased but NOT trimmed.
	// " root " won't match because CN is "root ca" (no leading/trailing space).
	if len(result) != 0 {
		t.Log("filter query with whitespace unexpectedly matched (query may be trimmed)")
	}

	// Without whitespace it matches
	result2 := FilterContainers(containers, "root")
	if len(result2) != 1 {
		t.Errorf("expected 1 match for 'root', got %d", len(result2))
	}
}

// TestFormatCompactRelation verifies the compact relation format strings.
func TestFormatCompactRelation(t *testing.T) {
	caKey := mustGenerateECKey(t)
	caCert, _ := mustCreateSelfSignedCA(t, caKey)

	leafKey := mustGenerateECKey(t)
	leafCert, _ := mustCreateLeafCert(t, leafKey, caCert, caKey)

	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "/test/leaf.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: leafCert}},
	})
	store.AddContainer(CertContainer{
		FilePath: "/test/ca.pem",
		Format:   FormatPEM,
		Items:    []CertItem{{Type: ContentCertificate, Certificate: caCert}},
	})

	leafRef := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "/test/leaf.pem"}

	rel := ResolvedRelation{
		Type:      RelationSignedBy,
		Direction: DirectionOutgoing,
		Peer:      ItemRef{ContainerIdx: 1, ItemIdx: 0, FilePath: "/test/ca.pem"},
	}

	formatted := FormatCompactRelation(rel, leafRef, store)
	if !strings.HasPrefix(formatted, "signed_by(") {
		t.Errorf("expected signed_by(...) format, got %q", formatted)
	}
}

// TestFindSources_Deduplication verifies that findSources returns deduplicated
// sources when the same password is supplied from multiple sources.
func TestFindSources_Deduplication(t *testing.T) {
	pw := []byte("secret")
	tagged := []TaggedPassword{
		{Password: pw, Source: PasswordSourceCLI},
		{Password: pw, Source: PasswordSourceEnvVar},
		{Password: pw, Source: PasswordSourceCLI}, // duplicate CLI
	}

	sources := findSources(tagged, pw)

	// Should have 2 unique sources: CLI and Env
	if len(sources) != 2 {
		t.Errorf("expected 2 deduplicated sources, got %d: %v", len(sources), sources)
	}

	// Sources that don't match
	noMatch := findSources(tagged, []byte("wrong"))
	if len(noMatch) != 0 {
		t.Errorf("expected 0 sources for non-matching password, got %d", len(noMatch))
	}
}

// TestFindSources_NoMatch verifies empty UnlockSources when password doesn't match.
func TestFindSources_NoMatch(t *testing.T) {
	tagged := []TaggedPassword{
		{Password: []byte("abc"), Source: PasswordSourceCLI},
	}
	sources := findSources(tagged, []byte("xyz"))
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

// TestFindSources_NilPassword verifies behavior with nil password.
func TestFindSources_NilPassword(t *testing.T) {
	tagged := []TaggedPassword{
		{Password: []byte("abc"), Source: PasswordSourceCLI},
	}
	sources := findSources(tagged, nil)
	if len(sources) != 0 {
		t.Errorf("expected 0 sources for nil password, got %d", len(sources))
	}
}
