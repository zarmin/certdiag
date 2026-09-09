package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// Parsed is everything certdiag understands about a certificate's extensions
// beyond what Go's x509 package already exposes, plus the residue: every
// extension it does not decode, named where possible.
//
// The residue is the point of Tier 0: an extension certdiag cannot read should
// still be visible, because "there is something here I do not decode" is useful
// and silence is not.
type Parsed struct {
	SCTs              []SCT
	IsPrecertificate  bool
	MustStaple        bool
	TLSFeatures       []int
	QCStatements      []QCStatement
	NetscapeCertType  []string
	NetscapeComment   string
	MSTemplateName    string
	MSTemplate        *MSTemplate
	OCSPNoCheck       bool
	PolicyConstraints *PolicyConstraints
	InhibitAnyPolicy  *int

	// Other lists every extension not rendered elsewhere.
	Other []Residue
}

// Residue is an extension certdiag does not decode into a typed field.
type Residue struct {
	OID      string `json:"oid" yaml:"oid"`
	Name     string `json:"name,omitempty" yaml:"name,omitempty"`
	Critical bool   `json:"critical" yaml:"critical"`
	Length   int    `json:"length" yaml:"length"`
}

// typedElsewhere are the extensions rendered by their own fields, either by
// this package or by Go's x509 struct. They stay out of the residue so it lists
// only what is otherwise invisible.
var typedElsewhere = map[string]bool{
	OIDSubjectKeyID.String():          true,
	OIDKeyUsage.String():              true,
	OIDSubjectAltName.String():        true,
	OIDIssuerAltName.String():         true,
	OIDBasicConstraints.String():      true,
	OIDNameConstraints.String():       true,
	OIDCRLDistributionPoints.String(): true,
	OIDCertificatePolicies.String():   true,
	OIDAuthorityKeyID.String():        true,
	OIDExtKeyUsage.String():           true,
	OIDAuthorityInfoAccess.String():   true,
	OIDSCTList.String():               true,
	OIDPrecertPoison.String():         true,
	OIDTLSFeature.String():            true,
	OIDQCStatements.String():          true,
	OIDNetscapeCertType.String():      true,
	OIDNetscapeComment.String():       true,
	OIDMSTemplateName.String():        true,
	OIDMSTemplateInfo.String():        true,
	OIDOCSPNoCheck.String():           true,
	OIDPolicyConstraints.String():     true,
	OIDInhibitAnyPolicy.String():      true,
}

// Parse decodes what it can and records the rest. A malformed extension is
// never fatal: a certificate that fails to decode in one place must still be
// readable everywhere else, which is most of what a diagnostic tool is for.
func Parse(cert *x509.Certificate) Parsed {
	var p Parsed
	if cert == nil {
		return p
	}

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(OIDSCTList):
			p.SCTs = parseSCTList(ext.Value)

		case ext.Id.Equal(OIDPrecertPoison):
			p.IsPrecertificate = true

		case ext.Id.Equal(OIDTLSFeature):
			p.TLSFeatures = parseTLSFeature(ext.Value)
			for _, f := range p.TLSFeatures {
				if f == tlsFeatureStatusRequest {
					p.MustStaple = true
				}
			}

		case ext.Id.Equal(OIDQCStatements):
			p.QCStatements = parseQCStatements(ext.Value)

		case ext.Id.Equal(OIDNetscapeCertType):
			p.NetscapeCertType = parseNetscapeCertType(ext.Value)

		case ext.Id.Equal(OIDNetscapeComment):
			p.NetscapeComment = parseNetscapeComment(ext.Value)

		case ext.Id.Equal(OIDMSTemplateName):
			p.MSTemplateName = parseMSTemplateName(ext.Value)

		case ext.Id.Equal(OIDMSTemplateInfo):
			p.MSTemplate = parseMSTemplate(ext.Value)

		case ext.Id.Equal(OIDOCSPNoCheck):
			p.OCSPNoCheck = true

		case ext.Id.Equal(OIDPolicyConstraints):
			p.PolicyConstraints = parsePolicyConstraints(ext.Value)

		case ext.Id.Equal(OIDInhibitAnyPolicy):
			p.InhibitAnyPolicy = parseInhibitAnyPolicy(ext.Value)

		default:
			if typedElsewhere[ext.Id.String()] {
				continue
			}
			p.Other = append(p.Other, Residue{
				OID:      ext.Id.String(),
				Name:     Name(ext.Id),
				Critical: ext.Critical,
				Length:   len(ext.Value),
			})
		}
	}

	return p
}

// PolicyConstraints is the pair of skip counts from RFC 5280 4.2.1.11.
type PolicyConstraints struct {
	RequireExplicitPolicy *int
	InhibitPolicyMapping  *int
}

// String renders the constraint the way a reader thinks about it.
func (p PolicyConstraints) String() string {
	out := ""
	if p.RequireExplicitPolicy != nil {
		out += fmt.Sprintf("require explicit policy after %d", *p.RequireExplicitPolicy)
	}
	if p.InhibitPolicyMapping != nil {
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("inhibit policy mapping after %d", *p.InhibitPolicyMapping)
	}
	return out
}

func parsePolicyConstraints(der []byte) *PolicyConstraints {
	var raw struct {
		RequireExplicitPolicy int `asn1:"optional,tag:0"`
		InhibitPolicyMapping  int `asn1:"optional,tag:1"`
	}
	full := struct {
		RequireExplicitPolicy asn1.RawValue `asn1:"optional,tag:0"`
		InhibitPolicyMapping  asn1.RawValue `asn1:"optional,tag:1"`
	}{}
	if _, err := asn1.Unmarshal(der, &full); err != nil {
		return nil
	}
	_ = raw

	out := &PolicyConstraints{}
	if len(full.RequireExplicitPolicy.Bytes) > 0 {
		v := beInt(full.RequireExplicitPolicy.Bytes)
		out.RequireExplicitPolicy = &v
	}
	if len(full.InhibitPolicyMapping.Bytes) > 0 {
		v := beInt(full.InhibitPolicyMapping.Bytes)
		out.InhibitPolicyMapping = &v
	}
	if out.RequireExplicitPolicy == nil && out.InhibitPolicyMapping == nil {
		return nil
	}
	return out
}

func parseInhibitAnyPolicy(der []byte) *int {
	var skip int
	if _, err := asn1.Unmarshal(der, &skip); err != nil {
		return nil
	}
	return &skip
}

// beInt reads a big-endian integer from a context-tagged INTEGER body.
func beInt(b []byte) int {
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	return v
}
