package extensions

import (
	"encoding/asn1"
	"unicode/utf16"
)

// Microsoft certificate template extensions, MS-WCCE. Every certificate an
// Active Directory Certificate Services CA issues carries one, and without a
// parser it is invisible - which is unhelpful when the template is exactly what
// a Windows administrator needs to identify.

// MSTemplate is the structured template reference (MS-WCCE 2.2.2.7.7.2).
type MSTemplate struct {
	OID          string `json:"oid" yaml:"oid"`
	MajorVersion int    `json:"major_version" yaml:"major_version"`
	MinorVersion int    `json:"minor_version,omitempty" yaml:"minor_version,omitempty"`
}

// parseMSTemplateName reads the older name-only form, a BMPString.
func parseMSTemplateName(der []byte) string {
	var name string
	if _, err := asn1.Unmarshal(der, &name); err == nil && name != "" {
		return name
	}

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil || len(raw.Bytes) == 0 {
		return ""
	}
	// BMPString is UTF-16 big-endian.
	if len(raw.Bytes)%2 == 0 {
		units := make([]uint16, 0, len(raw.Bytes)/2)
		for i := 0; i+1 < len(raw.Bytes); i += 2 {
			units = append(units, uint16(raw.Bytes[i])<<8|uint16(raw.Bytes[i+1]))
		}
		if decoded := string(utf16.Decode(units)); decoded != "" {
			return decoded
		}
	}
	return string(raw.Bytes)
}

func parseMSTemplate(der []byte) *MSTemplate {
	var raw struct {
		TemplateID   asn1.ObjectIdentifier
		MajorVersion int `asn1:"optional"`
		MinorVersion int `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil
	}
	return &MSTemplate{
		OID:          raw.TemplateID.String(),
		MajorVersion: raw.MajorVersion,
		MinorVersion: raw.MinorVersion,
	}
}
