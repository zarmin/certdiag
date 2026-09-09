// Package extensions parses and names the X.509 v3 extensions Go's x509
// package does not expose, and names the ones it does.
//
// It deliberately does not import certlib: certlib imports this, and the
// dependency has to run one way.
package extensions

import "encoding/asn1"

// Named OIDs. An extension certdiag cannot decode should still be shown with
// its name rather than as a bare number, which is the difference between "this
// certificate carries something I do not understand" and a dead end.
var (
	OIDSubjectKeyID           = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDIssuerAltName          = asn1.ObjectIdentifier{2, 5, 29, 18}
	OIDBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDNameConstraints        = asn1.ObjectIdentifier{2, 5, 29, 30}
	OIDCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	OIDPolicyMappings         = asn1.ObjectIdentifier{2, 5, 29, 33}
	OIDAuthorityKeyID         = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDPolicyConstraints      = asn1.ObjectIdentifier{2, 5, 29, 36}
	OIDExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDInhibitAnyPolicy       = asn1.ObjectIdentifier{2, 5, 29, 54}
	OIDSubjectDirAttributes   = asn1.ObjectIdentifier{2, 5, 29, 9}
	OIDFreshestCRL            = asn1.ObjectIdentifier{2, 5, 29, 46}
	OIDAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDQCStatements           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	OIDSubjectInfoAccess      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	OIDLogotype               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}
	OIDTLSFeature             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	OIDOCSPNoCheck            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	OIDSCTList                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	OIDPrecertPoison          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	OIDMSTemplateName         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
	OIDMSTemplateInfo         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}
	OIDMSApplicationPolicies  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 10}
	OIDNetscapeCertType       = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	OIDNetscapeComment        = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
	OIDCTPrecertSigningCert   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	OIDSignedCertTimestampTLS = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}
)

// extensionNames maps an extension OID to a human name.
var extensionNames = map[string]string{
	OIDSubjectKeyID.String():           "Subject Key Identifier",
	OIDKeyUsage.String():               "Key Usage",
	OIDSubjectAltName.String():         "Subject Alternative Name",
	OIDIssuerAltName.String():          "Issuer Alternative Name",
	OIDBasicConstraints.String():       "Basic Constraints",
	OIDNameConstraints.String():        "Name Constraints",
	OIDCRLDistributionPoints.String():  "CRL Distribution Points",
	OIDCertificatePolicies.String():    "Certificate Policies",
	OIDPolicyMappings.String():         "Policy Mappings",
	OIDAuthorityKeyID.String():         "Authority Key Identifier",
	OIDPolicyConstraints.String():      "Policy Constraints",
	OIDExtKeyUsage.String():            "Extended Key Usage",
	OIDInhibitAnyPolicy.String():       "Inhibit anyPolicy",
	OIDSubjectDirAttributes.String():   "Subject Directory Attributes",
	OIDFreshestCRL.String():            "Freshest CRL",
	OIDAuthorityInfoAccess.String():    "Authority Information Access",
	OIDQCStatements.String():           "Qualified Certificate Statements",
	OIDSubjectInfoAccess.String():      "Subject Information Access",
	OIDLogotype.String():               "Logotype",
	OIDTLSFeature.String():             "TLS Feature",
	OIDOCSPNoCheck.String():            "OCSP No Check",
	OIDSCTList.String():                "Signed Certificate Timestamps",
	OIDPrecertPoison.String():          "CT Precertificate Poison",
	OIDMSTemplateName.String():         "Microsoft Certificate Template Name",
	OIDMSTemplateInfo.String():         "Microsoft Certificate Template Information",
	OIDMSApplicationPolicies.String():  "Microsoft Application Policies",
	OIDNetscapeCertType.String():       "Netscape Certificate Type",
	OIDNetscapeComment.String():        "Netscape Comment",
	OIDCTPrecertSigningCert.String():   "CT Precertificate Signing Certificate",
	OIDSignedCertTimestampTLS.String(): "Signed Certificate Timestamps (OCSP/TLS)",
}

// policyNames maps certificate policy OIDs to what they assert. Telling DV from
// OV from EV at a glance is the practical value of the policies extension.
var policyNames = map[string]string{
	"2.23.140.1.1":     "Extended Validation (CA/B Forum)",
	"2.23.140.1.2.1":   "Domain Validated (CA/B Forum)",
	"2.23.140.1.2.2":   "Organization Validated (CA/B Forum)",
	"2.23.140.1.2.3":   "Individual Validated (CA/B Forum)",
	"2.23.140.1.3":     "Extended Validation Code Signing (CA/B Forum)",
	"2.23.140.1.4.1":   "Code Signing (CA/B Forum)",
	"2.23.140.1.5.1.1": "S/MIME Mailbox Validated Legacy (CA/B Forum)",
	"2.5.29.32.0":      "anyPolicy",
	// ETSI, which is what an eIDAS certificate asserts against.
	"0.4.0.2042.1.1":   "ETSI EVCP",
	"0.4.0.2042.1.2":   "ETSI DVCP",
	"0.4.0.2042.1.3":   "ETSI OVCP",
	"0.4.0.2042.1.4":   "ETSI EVCP (EV)",
	"0.4.0.2042.1.6":   "ETSI NCP",
	"0.4.0.2042.1.7":   "ETSI LCP",
	"0.4.0.194112.1.4": "ETSI QCP-w (qualified website authentication)",
	"0.4.0.194112.1.0": "ETSI QCP-n (qualified natural person)",
	"0.4.0.194112.1.1": "ETSI QCP-l (qualified legal person)",
	"0.4.0.194112.1.2": "ETSI QCP-n-qscd",
	"0.4.0.194112.1.3": "ETSI QCP-l-qscd",
}

// Name returns the human name of an extension OID, empty when unknown.
func Name(oid asn1.ObjectIdentifier) string { return extensionNames[oid.String()] }

// Known reports whether an extension OID is one certdiag recognises. It
// replaces the ad-hoc list the unknown-extension check used to carry.
func Known(oid asn1.ObjectIdentifier) bool {
	_, ok := extensionNames[oid.String()]
	return ok
}

// PolicyName returns what a certificate policy OID asserts, empty when unknown.
func PolicyName(oid asn1.ObjectIdentifier) string { return policyNames[oid.String()] }
