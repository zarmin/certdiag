//go:build fulltest

package certlib

import (
	"crypto/x509"
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// Section 8: SAN Parsing (ParseSANString)
// ---------------------------------------------------------------------------

func TestParseSANString_DNSPrefix(t *testing.T) {
	result, err := ParseSANString("DNS:example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.DNSNames) != 1 || result.DNSNames[0] != "example.com" {
		t.Fatalf("expected DNS entry example.com, got %v", result.DNSNames)
	}
}

func TestParseSANString_IPPrefix(t *testing.T) {
	result, err := ParseSANString("IP:1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.IPAddresses) != 1 || !result.IPAddresses[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected IP 1.2.3.4, got %v", result.IPAddresses)
	}
}

func TestParseSANString_EmailPrefix(t *testing.T) {
	result, err := ParseSANString("email:test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.EmailAddresses) != 1 || result.EmailAddresses[0] != "test@example.com" {
		t.Fatalf("expected email test@example.com, got %v", result.EmailAddresses)
	}
}

func TestParseSANString_URIPrefix(t *testing.T) {
	result, err := ParseSANString("URI:https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.URIs) != 1 || result.URIs[0].String() != "https://example.com" {
		t.Fatalf("expected URI https://example.com, got %v", result.URIs)
	}
}

func TestParseSANString_AutoDetectDNS(t *testing.T) {
	result, err := ParseSANString("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.DNSNames) != 1 || result.DNSNames[0] != "example.com" {
		t.Fatalf("expected DNS auto-detect example.com, got %v", result.DNSNames)
	}
}

func TestParseSANString_AutoDetectIP(t *testing.T) {
	result, err := ParseSANString("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.IPAddresses) != 1 || !result.IPAddresses[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected IP auto-detect 1.2.3.4, got %v", result.IPAddresses)
	}
}

func TestParseSANString_MultipleCommaSeparated(t *testing.T) {
	result, err := ParseSANString("DNS:a.com, IP:1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.DNSNames) != 1 || result.DNSNames[0] != "a.com" {
		t.Fatalf("expected DNS a.com, got %v", result.DNSNames)
	}
	if len(result.IPAddresses) != 1 || !result.IPAddresses[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected IP 1.2.3.4, got %v", result.IPAddresses)
	}
}

func TestParseSANString_InvalidIP(t *testing.T) {
	_, err := ParseSANString("IP:999.999.999.999")
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

func TestParseSANString_IPv6Loopback(t *testing.T) {
	result, err := ParseSANString("IP:::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.IPAddresses) != 1 || !result.IPAddresses[0].Equal(net.ParseIP("::1")) {
		t.Fatalf("expected IPv6 ::1, got %v", result.IPAddresses)
	}
}

func TestParseSANString_IPv6Full(t *testing.T) {
	result, err := ParseSANString("IP:2001:db8::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.IPAddresses) != 1 || !result.IPAddresses[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected IPv6 2001:db8::1, got %v", result.IPAddresses)
	}
}

func TestParseSANString_WildcardDNS(t *testing.T) {
	result, err := ParseSANString("DNS:*.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.DNSNames) != 1 || result.DNSNames[0] != "*.example.com" {
		t.Fatalf("expected wildcard DNS *.example.com, got %v", result.DNSNames)
	}
}

func TestParseSANString_Empty(t *testing.T) {
	result, err := ParseSANString("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsEmpty() {
		t.Fatalf("expected empty SANList, got %+v", result)
	}
}

func TestParseSANString_ExtraWhitespace(t *testing.T) {
	result, err := ParseSANString("DNS: example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.DNSNames) != 1 || result.DNSNames[0] != "example.com" {
		t.Fatalf("expected trimmed DNS example.com, got %q", result.DNSNames)
	}
}

// ---------------------------------------------------------------------------
// Section 11: Key Usage (ParseKeyUsage, FormatKeyUsage)
// ---------------------------------------------------------------------------

func TestParseKeyUsage_DigitalSignature(t *testing.T) {
	ku, err := ParseKeyUsage("digitalSignature")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ku != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected KeyUsageDigitalSignature, got %d", ku)
	}
}

func TestParseKeyUsage_CertSign(t *testing.T) {
	ku, err := ParseKeyUsage("certsign")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ku != x509.KeyUsageCertSign {
		t.Fatalf("expected KeyUsageCertSign, got %d", ku)
	}
}

func TestParseKeyUsage_CombinedComma(t *testing.T) {
	ku, err := ParseKeyUsage("digitalSignature, keyEncipherment")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if ku != expected {
		t.Fatalf("expected %d, got %d", expected, ku)
	}
}

func TestParseKeyUsage_UnderscoreNormalizationFails(t *testing.T) {
	_, err := ParseKeyUsage("key_cert_sign")
	if err == nil {
		t.Fatal("expected error for key_cert_sign (normalizes to keycertsign, not in map)")
	}
}

func TestParseKeyUsage_CaseInsensitive(t *testing.T) {
	ku, err := ParseKeyUsage("DIGITALSIGNATURE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ku != x509.KeyUsageDigitalSignature {
		t.Fatalf("expected KeyUsageDigitalSignature, got %d", ku)
	}
}

func TestParseKeyUsage_Empty(t *testing.T) {
	ku, err := ParseKeyUsage("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ku != 0 {
		t.Fatalf("expected 0 for empty input, got %d", ku)
	}
}

func TestParseKeyUsage_Unknown(t *testing.T) {
	_, err := ParseKeyUsage("foobar")
	if err == nil {
		t.Fatal("expected error for unknown key usage foobar")
	}
}

// ---------------------------------------------------------------------------
// FormatKeyUsage
// ---------------------------------------------------------------------------

func TestFormatKeyUsage_Zero(t *testing.T) {
	result := FormatKeyUsage(0)
	if len(result) != 0 {
		t.Fatalf("expected empty list for 0, got %v", result)
	}
}

func TestFormatKeyUsage_SingleDigitalSignature(t *testing.T) {
	result := FormatKeyUsage(x509.KeyUsageDigitalSignature)
	if len(result) != 1 || result[0] != "Digital Signature" {
		t.Fatalf("expected [Digital Signature], got %v", result)
	}
}

func TestFormatKeyUsage_Combined(t *testing.T) {
	ku := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	result := FormatKeyUsage(ku)
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %v", result)
	}
	found := map[string]bool{}
	for _, s := range result {
		found[s] = true
	}
	if !found["Digital Signature"] || !found["Cert Sign"] {
		t.Fatalf("expected Digital Signature and Cert Sign, got %v", result)
	}
}

func TestFormatKeyUsage_AllUsages(t *testing.T) {
	all := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	result := FormatKeyUsage(all)
	if len(result) != 9 {
		t.Fatalf("expected 9 entries for all usages, got %d: %v", len(result), result)
	}
}

// ---------------------------------------------------------------------------
// Section 11: Extended Key Usage (ParseExtKeyUsage, FormatExtKeyUsage)
// ---------------------------------------------------------------------------

func TestParseExtKeyUsage_ServerAuth(t *testing.T) {
	ekus, err := ParseExtKeyUsage("serverAuth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ekus) != 1 || ekus[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("expected [ServerAuth], got %v", ekus)
	}
}

func TestParseExtKeyUsage_Multiple(t *testing.T) {
	ekus, err := ParseExtKeyUsage("serverAuth, clientAuth")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ekus) != 2 {
		t.Fatalf("expected 2 entries, got %v", ekus)
	}
	if ekus[0] != x509.ExtKeyUsageServerAuth || ekus[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("expected ServerAuth and ClientAuth, got %v", ekus)
	}
}

func TestParseExtKeyUsage_Unknown(t *testing.T) {
	_, err := ParseExtKeyUsage("foobar")
	if err == nil {
		t.Fatal("expected error for unknown ext key usage foobar")
	}
}

func TestParseExtKeyUsage_Empty(t *testing.T) {
	ekus, err := ParseExtKeyUsage("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ekus != nil {
		t.Fatalf("expected nil for empty input, got %v", ekus)
	}
}

// ---------------------------------------------------------------------------
// FormatExtKeyUsage
// ---------------------------------------------------------------------------

func TestFormatExtKeyUsage_Nil(t *testing.T) {
	result := FormatExtKeyUsage(nil)
	if result != nil {
		t.Fatalf("expected nil for nil input, got %v", result)
	}
}

func TestFormatExtKeyUsage_ServerAuth(t *testing.T) {
	result := FormatExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if len(result) != 1 || result[0] != "Server Auth" {
		t.Fatalf("expected [Server Auth], got %v", result)
	}
}

func TestFormatExtKeyUsage_Multiple(t *testing.T) {
	result := FormatExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	})
	if len(result) != 2 || result[0] != "Server Auth" || result[1] != "Client Auth" {
		t.Fatalf("expected [Server Auth, Client Auth], got %v", result)
	}
}

func TestFormatExtKeyUsage_UnknownValue(t *testing.T) {
	result := FormatExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsage(9999)})
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %v", result)
	}
	if result[0] != "Unknown(9999)" {
		t.Fatalf("expected Unknown(9999), got %q", result[0])
	}
}
