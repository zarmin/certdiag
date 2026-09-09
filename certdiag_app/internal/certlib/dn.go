package certlib

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

var oidShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.5":                    "SERIALNUMBER",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.17":                   "POSTALCODE",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"2.5.4.12":                   "title",
	"2.5.4.15":                   "businessCategory",
	"1.3.6.1.4.1.311.60.2.1.1":   "jurisdictionL",
	"1.3.6.1.4.1.311.60.2.1.2":   "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3":   "jurisdictionC",
}

func FormatSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	hex := fmt.Sprintf("%x", serial)
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

func FormatSerialDetailed(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return fmt.Sprintf("%s (%s)", FormatSerial(serial), serial.String())
}

var shortNameToOID = map[string]asn1.ObjectIdentifier{
	"CN":               {2, 5, 4, 3},
	"SERIALNUMBER":     {2, 5, 4, 5},
	"C":                {2, 5, 4, 6},
	"L":                {2, 5, 4, 7},
	"ST":               {2, 5, 4, 8},
	"STREET":           {2, 5, 4, 9},
	"O":                {2, 5, 4, 10},
	"OU":               {2, 5, 4, 11},
	"POSTALCODE":       {2, 5, 4, 17},
	"DC":               {0, 9, 2342, 19200300, 100, 1, 25},
	"UID":              {0, 9, 2342, 19200300, 100, 1, 1},
	"EMAILADDRESS":     {1, 2, 840, 113549, 1, 9, 1},
	"SN":               {2, 5, 4, 4},
	"GN":               {2, 5, 4, 42},
	"TITLE":            {2, 5, 4, 12},
	"BUSINESSCATEGORY": {2, 5, 4, 15},
}

func ParseDN(dn string) (pkix.Name, error) {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return pkix.Name{}, fmt.Errorf("empty DN string")
	}

	parts := splitDN(dn)
	var name pkix.Name

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			return pkix.Name{}, fmt.Errorf("invalid DN component (no '='): %q", part)
		}
		key := strings.TrimSpace(part[:idx])
		val := strings.TrimSpace(part[idx+1:])
		val = strings.ReplaceAll(val, "\\,", ",")

		upperKey := strings.ToUpper(key)

		switch upperKey {
		case "CN":
			name.CommonName = val
		case "O":
			name.Organization = append(name.Organization, val)
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, val)
		case "C":
			name.Country = append(name.Country, val)
		case "ST":
			name.Province = append(name.Province, val)
		case "L":
			name.Locality = append(name.Locality, val)
		case "SERIALNUMBER":
			name.SerialNumber = val
		case "STREET":
			name.StreetAddress = append(name.StreetAddress, val)
		case "POSTALCODE":
			name.PostalCode = append(name.PostalCode, val)
		default:
			oid, ok := shortNameToOID[upperKey]
			if !ok {
				return pkix.Name{}, fmt.Errorf("unknown DN attribute: %q", key)
			}
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  oid,
				Value: val,
			})
		}
	}

	return name, nil
}

func splitDN(dn string) []string {
	var parts []string
	var current strings.Builder
	for i := 0; i < len(dn); i++ {
		if dn[i] == '\\' && i+1 < len(dn) {
			current.WriteByte(dn[i])
			current.WriteByte(dn[i+1])
			i++
			continue
		}
		if dn[i] == ',' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(dn[i])
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func FormatDNName(name pkix.Name) string {
	if len(name.Names) == 0 {
		return ""
	}
	var parts []string
	for _, atv := range name.Names {
		key := atv.Type.String()
		if short, ok := oidShortNames[key]; ok {
			key = short
		}
		parts = append(parts, fmt.Sprintf("%s=%v", key, atv.Value))
	}
	return strings.Join(parts, ", ")
}
