package certlib

import (
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

// Checks over the extensions M30b taught certdiag to read. Each one exists
// because the condition is invisible without a parser and consequential with
// one.

func init() {
	registerCheck(CheckDefinition{
		ID: "precert_as_cert", Category: "structure", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Certificate is a CT precertificate, not a usable certificate",
		check:       checkPrecertAsCert,
	})
	registerCheck(CheckDefinition{
		ID: "path_length_violation", Category: "chain", Severity: SeverityCritical,
		AppliesTo:   kindsCA,
		Description: "A CA is deeper below an ancestor than its path length allows",
		check:       checkPathLengthViolation,
	})
	registerCheck(CheckDefinition{
		ID: "netscape_type_conflict", Category: "structure", Severity: SeverityInfo,
		AppliesTo:   kindsCert,
		Description: "Netscape certificate type contradicts Key Usage",
		check:       checkNetscapeTypeConflict,
	})
}

// checkPrecertAsCert: a precertificate exists only to be logged. Serving or
// storing one as a certificate is a mistake no client will accept, and the
// poison extension makes it certain rather than a guess.
func checkPrecertAsCert(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	if !extensions.Parse(item.Certificate).IsPrecertificate {
		return nil
	}
	return []CheckIssue{makeIssue(SeverityWarning, "structure", "precert_as_cert", c, item, ref,
		"Certificate carries the CT poison extension: it is a precertificate and no client will accept it",
		map[string]any{"oid": extensions.OIDPrecertPoison.String()})}
}

// checkPathLengthViolation: x509.Verify rejects a chain that is too deep, with
// an error that does not say which constraint was exceeded. This says it.
func checkPathLengthViolation(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, index RelationIndex, store *CertStore) []CheckIssue {
	cert := item.Certificate
	if cert == nil || !cert.IsCA || store == nil {
		return nil
	}

	depth := 0
	current := ref
	for i := 0; i < 16; i++ {
		parent, ok := issuerRef(current, index)
		if !ok {
			break
		}
		parentItem := store.SafeItem(parent)
		if parentItem == nil || parentItem.Certificate == nil {
			break
		}
		depth++
		p := parentItem.Certificate
		if p.MaxPathLenZero || p.MaxPathLen > 0 {
			// A path length of n allows n CAs below this one; this CA is the
			// depth-th CA below p, so depth > n is the violation.
			if depth > p.MaxPathLen {
				return []CheckIssue{makeIssue(SeverityCritical, "chain", "path_length_violation", c, item, ref,
					fmt.Sprintf("CA sits %d level(s) below %q, whose path length allows %d",
						depth, FormatDNName(p.Subject), p.MaxPathLen),
					map[string]any{
						"ancestor":     FormatDNName(p.Subject),
						"max_path_len": p.MaxPathLen,
						"depth":        depth,
					})}
			}
		}
		current = parent
	}
	return nil
}

// issuerRef returns the ref of the certificate that signed this one.
func issuerRef(ref ItemRef, index RelationIndex) (ItemRef, bool) {
	for _, rel := range index[ref] {
		if rel.Type == RelationSignedBy && rel.Direction == DirectionOutgoing {
			return rel.Peer, true
		}
	}
	return ItemRef{}, false
}

// checkNetscapeTypeConflict: the legacy extension and Key Usage disagreeing is
// a sign of a certificate assembled from a stale template.
func checkNetscapeTypeConflict(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	cert := item.Certificate
	if cert == nil {
		return nil
	}
	types := extensions.Parse(cert).NetscapeCertType
	if len(types) == 0 {
		return nil
	}

	claimsCA := false
	for _, t := range types {
		if strings.HasSuffix(t, "CA") {
			claimsCA = true
		}
	}
	if claimsCA == cert.IsCA {
		return nil
	}

	return []CheckIssue{makeIssue(SeverityInfo, "structure", "netscape_type_conflict", c, item, ref,
		fmt.Sprintf("Netscape certificate type says %q but Basic Constraints says CA=%v",
			strings.Join(types, ", "), cert.IsCA),
		map[string]any{"netscape_type": types, "is_ca": cert.IsCA})}
}

func init() {
	registerCheck(CheckDefinition{
		ID: "name_constraints_violation", Category: "chain", Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "Certificate carries a name its issuer's constraints forbid",
		check:       checkNameConstraintsViolation,
	})
	registerCheck(CheckDefinition{
		ID: "name_constraints_on_root", Category: "structure", Severity: SeverityInfo,
		AppliesTo:   kindsCA,
		Description: "Name constraints on a self-signed root are not applied by every verifier",
		check:       checkNameConstraintsOnRoot,
	})
}

// checkNameConstraintsViolation names the certificate that broke a constraint.
// x509.Verify already rejects such a chain, with an error that does not say
// which name was at fault; this is the same refusal the signer would have made.
// RFC 5280 applies every ancestor's constraints, so the walk goes to the root.
func checkNameConstraintsViolation(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, index RelationIndex, store *CertStore) []CheckIssue {
	cert := item.Certificate
	if cert == nil || store == nil {
		return nil
	}

	sans := SANList{
		DNSNames:       cert.DNSNames,
		IPAddresses:    cert.IPAddresses,
		EmailAddresses: cert.EmailAddresses,
		URIs:           cert.URIs,
	}
	current := ref
	for i := 0; i < 16; i++ {
		parent, ok := issuerRef(current, index)
		if !ok {
			return nil
		}
		parentItem := store.SafeItem(parent)
		if parentItem == nil || parentItem.Certificate == nil {
			return nil
		}
		if err := CheckNameConstraints(parentItem.Certificate, cert.Subject.CommonName, sans); err != nil {
			return []CheckIssue{makeIssue(SeverityCritical, "chain", "name_constraints_violation", c, item, ref,
				fmt.Sprintf("Issued outside the name constraints of %q: %v", FormatDNName(parentItem.Certificate.Subject), err),
				map[string]any{
					"issuer": FormatDNName(parentItem.Certificate.Subject),
					"depth":  i + 1,
					"reason": err.Error(),
				})}
		}
		current = parent
	}
	return nil
}

// checkNameConstraintsOnRoot: RFC 5280 leaves trust anchor extensions to local
// policy, and verifiers differ on whether they apply them. Go does; others do
// not. Constraints belong on an issuing sub-CA if they are meant to hold.
func checkNameConstraintsOnRoot(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	cert := item.Certificate
	if cert == nil || !cert.IsCA || !IsSelfSigned(cert) {
		return nil
	}
	if len(cert.PermittedDNSDomains) == 0 && len(cert.ExcludedDNSDomains) == 0 &&
		len(cert.PermittedIPRanges) == 0 && len(cert.ExcludedIPRanges) == 0 &&
		len(cert.PermittedEmailAddresses) == 0 && len(cert.ExcludedEmailAddresses) == 0 &&
		len(cert.PermittedURIDomains) == 0 && len(cert.ExcludedURIDomains) == 0 {
		return nil
	}

	return []CheckIssue{makeIssue(SeverityInfo, "structure", "name_constraints_on_root", c, item, ref,
		"Name constraints sit on a self-signed root; RFC 5280 leaves anchor extensions to local policy, so put them on an issuing sub-CA if they must hold everywhere",
		map[string]any{"self_signed": true})}
}
