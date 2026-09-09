package certlib

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidIssuerAltName  = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidUPN            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

type OthernameEntry struct {
	OID   asn1.ObjectIdentifier
	Value string
}

func ParseOthernameSANs(cert *x509.Certificate) ([]OthernameEntry, error) {
	var othernames []OthernameEntry

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			var seq asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &seq)
			if err != nil {
				return nil, err
			}

			rest := seq.Bytes
			for len(rest) > 0 {
				var gn asn1.RawValue
				rest, err = asn1.Unmarshal(rest, &gn)
				if err != nil {
					break
				}

				if gn.Class == asn1.ClassContextSpecific && gn.Tag == 0 {
					entry, err := parseOthername(gn.Bytes)
					if err == nil {
						othernames = append(othernames, entry)
					}
				}
			}
			break
		}
	}

	return othernames, nil
}

func parseOthername(data []byte) (OthernameEntry, error) {
	var entry OthernameEntry

	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(data, &oid)
	if err != nil {
		return entry, err
	}

	entry.OID = oid

	var val asn1.RawValue
	_, err = asn1.Unmarshal(rest, &val)
	if err != nil {
		return entry, err
	}

	var str string
	_, err = asn1.Unmarshal(val.Bytes, &str)
	if err == nil {
		entry.Value = str
	} else {
		entry.Value = fmt.Sprintf("%x", val.Bytes)
	}

	return entry, nil
}

func FormatOthername(entry OthernameEntry) string {
	switch {
	case entry.OID.Equal(oidUPN):
		return fmt.Sprintf("othername:UPN:%s", entry.Value)
	default:
		return fmt.Sprintf("othername:%s:%s", entry.OID.String(), entry.Value)
	}
}

func ParseIssuerAltNames(cert *x509.Certificate) []string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidIssuerAltName) {
			return parseGeneralNames(ext.Value)
		}
	}
	return nil
}

func parseGeneralNames(data []byte) []string {
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(data, &seq)
	if err != nil {
		return nil
	}

	var names []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			break
		}
		if gn.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag {
		case 1: // rfc822Name (email)
			names = append(names, "email:"+string(gn.Bytes))
		case 2: // dNSName
			names = append(names, "DNS:"+string(gn.Bytes))
		case 6: // uniformResourceIdentifier
			names = append(names, "URI:"+string(gn.Bytes))
		case 7: // iPAddress
			if len(gn.Bytes) == 4 || len(gn.Bytes) == 16 {
				ip := net.IP(gn.Bytes)
				names = append(names, "IP:"+ip.String())
			}
		}
	}
	return names
}

// FormatSANs returns display strings for all SAN entries in a certificate.
func FormatSANs(cert *x509.Certificate) []string {
	var sans []string
	othernames, err := ParseOthernameSANs(cert)
	if err == nil {
		for _, o := range othernames {
			sans = append(sans, FormatOthername(o))
		}
	}
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "email:"+email)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}
	return sans
}

func ParseSANString(san string) (SANList, error) {
	san = strings.TrimSpace(san)
	if san == "" {
		return SANList{}, nil
	}

	var result SANList
	parts := strings.Split(san, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		prefix, value, hasPrefix := "", part, false
		if idx := strings.Index(part, ":"); idx > 0 {
			candidate := strings.ToLower(part[:idx])
			switch candidate {
			case "dns", "ip", "email", "uri":
				prefix = candidate
				value = strings.TrimSpace(part[idx+1:])
				hasPrefix = true
			}
		}

		if !hasPrefix {
			if ip := net.ParseIP(value); ip != nil {
				result.IPAddresses = append(result.IPAddresses, ip)
			} else {
				result.DNSNames = append(result.DNSNames, value)
			}
			continue
		}

		switch prefix {
		case "dns":
			result.DNSNames = append(result.DNSNames, value)
		case "ip":
			ip := net.ParseIP(value)
			if ip == nil {
				return SANList{}, fmt.Errorf("invalid IP address: %q", value)
			}
			result.IPAddresses = append(result.IPAddresses, ip)
		case "email":
			result.EmailAddresses = append(result.EmailAddresses, value)
		case "uri":
			u, err := url.Parse(value)
			if err != nil {
				return SANList{}, fmt.Errorf("invalid URI: %q: %w", value, err)
			}
			if u.Scheme == "" {
				return SANList{}, fmt.Errorf("invalid URI (no scheme): %q", value)
			}
			result.URIs = append(result.URIs, u)
		}
	}

	return result, nil
}
