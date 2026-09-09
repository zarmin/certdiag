package certlib

import (
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func registerTrustChecks() {
	registerCheck(CheckDefinition{
		ID: "untrusted_chain", Category: "trust", Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Certificate does not chain to a trust anchor on this machine",
		check:       checkUntrustedChain,
	})
	registerCheck(CheckDefinition{
		ID: "distrusted_root", Category: "trust", Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "Certificate is explicitly distrusted by the OS trust store",
		check:       checkDistrustedRoot,
	})
}

func checkUntrustedChain(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if opts.TrustIndex == nil || item.Certificate == nil {
		return nil
	}
	if opts.TrustIndex.Verdict(item.Certificate) != truststore.VerdictUntrusted {
		return nil
	}

	issuer := item.Certificate.Issuer.CommonName
	if issuer == "" {
		issuer = FormatDNName(item.Certificate.Issuer)
	}
	return []CheckIssue{makeIssue(SeverityWarning, "trust", "untrusted_chain", c, item, ref,
		fmt.Sprintf("No path to a trust anchor: issuer %q is not trusted by this machine", issuer),
		map[string]any{"issuer": FormatDNName(item.Certificate.Issuer)})}
}

func checkDistrustedRoot(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if opts.TrustIndex == nil || item.Certificate == nil {
		return nil
	}
	if opts.TrustIndex.Verdict(item.Certificate) != truststore.VerdictDenied {
		return nil
	}

	subject := item.Certificate.Subject.CommonName
	if subject == "" {
		subject = FormatDNName(item.Certificate.Subject)
	}
	return []CheckIssue{makeIssue(SeverityCritical, "trust", "distrusted_root", c, item, ref,
		fmt.Sprintf("Explicitly distrusted by the OS trust store: %q", subject),
		map[string]any{"subject": FormatDNName(item.Certificate.Subject)})}
}
