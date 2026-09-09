package certlib

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// KeyUsageNames lists canonical camelCase names for --key-usage flag help.
var KeyUsageNames = []string{
	"digitalSignature", "contentCommitment", "keyEncipherment",
	"dataEncipherment", "keyAgreement", "certSign", "crlSign",
	"encipherOnly", "decipherOnly",
}

// ExtKeyUsageNames lists canonical camelCase names for --ext-key-usage flag help.
var ExtKeyUsageNames = []string{
	"any", "serverAuth", "clientAuth", "codeSigning",
	"emailProtection", "timeStamping", "ocspSigning",
}

var keyUsageMap = map[string]x509.KeyUsage{
	"digitalsignature":  x509.KeyUsageDigitalSignature,
	"contentcommitment": x509.KeyUsageContentCommitment,
	"keyencipherment":   x509.KeyUsageKeyEncipherment,
	"dataencipherment":  x509.KeyUsageDataEncipherment,
	"keyagreement":      x509.KeyUsageKeyAgreement,
	"certsign":          x509.KeyUsageCertSign,
	"crlsign":           x509.KeyUsageCRLSign,
	"encipheronly":      x509.KeyUsageEncipherOnly,
	"decipheronly":      x509.KeyUsageDecipherOnly,
}

var extKeyUsageMap = map[string]x509.ExtKeyUsage{
	"any":             x509.ExtKeyUsageAny,
	"serverauth":      x509.ExtKeyUsageServerAuth,
	"clientauth":      x509.ExtKeyUsageClientAuth,
	"codesigning":     x509.ExtKeyUsageCodeSigning,
	"emailprotection": x509.ExtKeyUsageEmailProtection,
	"timestamping":    x509.ExtKeyUsageTimeStamping,
	"ocspsigning":     x509.ExtKeyUsageOCSPSigning,
}

// FormatKeyUsage converts a KeyUsage bitmask to display strings.
func FormatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Cert Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

// FormatExtKeyUsage converts ExtKeyUsage values to display strings.
func FormatExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	var names []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			names = append(names, "Any")
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		default:
			names = append(names, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return names
}

func FormatKeyUsageInternal(ku x509.KeyUsage) string {
	if ku == 0 {
		return ""
	}
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "certSign"},
		{x509.KeyUsageCRLSign, "crlSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var parts []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			parts = append(parts, p.name)
		}
	}
	return strings.Join(parts, ",")
}

func FormatExtKeyUsageInternal(ekus []x509.ExtKeyUsage) string {
	if len(ekus) == 0 {
		return ""
	}
	reverse := make(map[x509.ExtKeyUsage]string, len(extKeyUsageMap))
	for name, val := range extKeyUsageMap {
		for _, canonical := range ExtKeyUsageNames {
			if strings.ToLower(canonical) == name {
				reverse[val] = canonical
				break
			}
		}
	}
	var parts []string
	for _, eku := range ekus {
		if name, ok := reverse[eku]; ok {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ",")
}

func ParseKeyUsage(s string) (x509.KeyUsage, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	var result x509.KeyUsage
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(part, "_", ""))
		key = strings.ReplaceAll(key, "-", "")
		key = strings.ReplaceAll(key, " ", "")
		val, ok := keyUsageMap[key]
		if !ok {
			return 0, fmt.Errorf("unknown key usage %q", part)
		}
		result |= val
	}
	return result, nil
}

func ParseKeyUsageList(list []string) (x509.KeyUsage, error) {
	var result x509.KeyUsage
	for _, s := range list {
		ku, err := ParseKeyUsage(s)
		if err != nil {
			return 0, err
		}
		result |= ku
	}
	return result, nil
}

func ParseExtKeyUsage(s string) ([]x509.ExtKeyUsage, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var result []x509.ExtKeyUsage
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(part, "_", ""))
		key = strings.ReplaceAll(key, "-", "")
		key = strings.ReplaceAll(key, " ", "")
		val, ok := extKeyUsageMap[key]
		if !ok {
			return nil, fmt.Errorf("unknown extended key usage %q", part)
		}
		result = append(result, val)
	}
	return result, nil
}

func ParseExtKeyUsageList(list []string) ([]x509.ExtKeyUsage, error) {
	var result []x509.ExtKeyUsage
	for _, s := range list {
		ekus, err := ParseExtKeyUsage(s)
		if err != nil {
			return nil, err
		}
		result = append(result, ekus...)
	}
	return result, nil
}
