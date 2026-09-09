package extensions

import "encoding/asn1"

// The legacy Netscape extensions. Long obsolete, still present on certificates
// from older CAs and from openssl configs that were never updated, and worth
// showing because a Netscape cert type that contradicts Key Usage is a real
// inconsistency.

var netscapeCertTypeBits = []string{
	"SSL client",
	"SSL server",
	"S/MIME",
	"Object signing",
	"reserved",
	"SSL CA",
	"S/MIME CA",
	"Object signing CA",
}

func parseNetscapeCertType(der []byte) []string {
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(der, &bits); err != nil {
		return nil
	}
	var out []string
	for i, name := range netscapeCertTypeBits {
		if bits.At(i) == 1 && name != "reserved" {
			out = append(out, name)
		}
	}
	return out
}

func parseNetscapeComment(der []byte) string {
	var comment string
	if _, err := asn1.Unmarshal(der, &comment); err == nil {
		return comment
	}
	// Some CAs encode it as an IA5String the default unmarshal refuses.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err == nil && len(raw.Bytes) > 0 {
		return string(raw.Bytes)
	}
	return ""
}
