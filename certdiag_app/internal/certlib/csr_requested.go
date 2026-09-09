package certlib

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

// CSRRequest is what a CSR asked for in its extensionRequest attribute, as
// far as certdiag can name it. Go parses the attribute into
// CertificateRequest.Extensions but does not decode the values.
type CSRRequest struct {
	HasKeyUsage bool
	KeyUsage    x509.KeyUsage

	HasExtKeyUsage     bool
	ExtKeyUsage        []x509.ExtKeyUsage
	UnknownExtKeyUsage []string // dotted OIDs certdiag has no name for

	HasBasicConstraints bool
	IsCA                bool
}

// extKeyUsageOIDs names the extended key usages a CSR commonly requests.
var extKeyUsageOIDs = []struct {
	oid asn1.ObjectIdentifier
	eku x509.ExtKeyUsage
}{
	{asn1.ObjectIdentifier{2, 5, 29, 37, 0}, x509.ExtKeyUsageAny},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, x509.ExtKeyUsageServerAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, x509.ExtKeyUsageClientAuth},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, x509.ExtKeyUsageCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, x509.ExtKeyUsageEmailProtection},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}, x509.ExtKeyUsageIPSECEndSystem},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}, x509.ExtKeyUsageIPSECTunnel},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}, x509.ExtKeyUsageIPSECUser},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, x509.ExtKeyUsageTimeStamping},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, x509.ExtKeyUsageOCSPSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}, x509.ExtKeyUsageMicrosoftServerGatedCrypto},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}, x509.ExtKeyUsageNetscapeServerGatedCrypto},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}, x509.ExtKeyUsageMicrosoftCommercialCodeSigning},
	{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}, x509.ExtKeyUsageMicrosoftKernelCodeSigning},
}

// CSRRequestedExtensions decodes the key usage, extended key usage and basic
// constraints a CSR requested. Extensions that are absent or undecodable are
// reported as not requested.
func CSRRequestedExtensions(csr *x509.CertificateRequest) CSRRequest {
	var req CSRRequest
	if csr == nil {
		return req
	}
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(extensions.OIDKeyUsage):
			var bits asn1.BitString
			if _, err := asn1.Unmarshal(ext.Value, &bits); err != nil {
				continue
			}
			req.HasKeyUsage = true
			for i := 0; i < 9; i++ {
				if bits.At(i) != 0 {
					req.KeyUsage |= x509.KeyUsage(1) << uint(i)
				}
			}
		case ext.Id.Equal(extensions.OIDExtKeyUsage):
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
				continue
			}
			req.HasExtKeyUsage = true
			for _, oid := range oids {
				known := false
				for _, e := range extKeyUsageOIDs {
					if e.oid.Equal(oid) {
						req.ExtKeyUsage = append(req.ExtKeyUsage, e.eku)
						known = true
						break
					}
				}
				if !known {
					req.UnknownExtKeyUsage = append(req.UnknownExtKeyUsage, oid.String())
				}
			}
		case ext.Id.Equal(extensions.OIDBasicConstraints):
			var bc struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err != nil {
				continue
			}
			req.HasBasicConstraints = true
			req.IsCA = bc.IsCA
		}
	}
	return req
}
