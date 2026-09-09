package certlib

import (
	"fmt"
	"strings"
	"time"
)

const (
	categoryRevocation = "revocation"

	checkRevocationRevokedID      = "revocation_revoked"
	checkRevocationUndeterminedID = "revocation_undetermined"
	checkRevocationUnverifiedID   = "revocation_unverified"
)

func registerRevocationChecks() {
	registerCheck(CheckDefinition{
		ID: checkRevocationRevokedID, Category: categoryRevocation, Severity: SeverityCritical,
		AppliesTo:   kindsCert,
		Description: "Certificate is revoked (OCSP or CRL)",
		check:       checkRevocationRevoked,
	})
	registerCheck(CheckDefinition{
		ID: checkRevocationUndeterminedID, Category: categoryRevocation, Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Revocation status could not be determined",
		check:       checkRevocationUndetermined,
	})
	registerCheck(CheckDefinition{
		ID: checkRevocationUnverifiedID, Category: categoryRevocation, Severity: SeverityWarning,
		AppliesTo:   kindsCert,
		Description: "Revocation answer could not be cryptographically verified",
		check:       checkRevocationUnverified,
	})
}

func checkRevocationRevoked(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	res := revocationFor(opts, item, ref)
	if res == nil || res.Status != RevocationRevoked {
		return nil
	}
	msg := fmt.Sprintf("Certificate is REVOKED (via %s)", res.Method)
	if res.Reason != "" {
		msg += fmt.Sprintf(", reason: %s", res.Reason)
	}
	if !res.RevokedAt.IsZero() {
		msg += fmt.Sprintf(", at %s", res.RevokedAt.Format("2006-01-02"))
	}
	return []CheckIssue{makeIssue(SeverityCritical, categoryRevocation, checkRevocationRevokedID, c, item, ref, msg, revocationDetails(res))}
}

func checkRevocationUndetermined(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	res := revocationFor(opts, item, ref)
	if res == nil || res.Status != RevocationUndetermined {
		return nil
	}
	sev := SeverityWarning
	if opts.RevocationRequire {
		sev = SeverityCritical
	}
	msg := "Revocation status could not be determined"
	if s := attemptSummary(res); s != "" {
		msg += " (" + s + ")"
	}
	return []CheckIssue{makeIssue(sev, categoryRevocation, checkRevocationUndeterminedID, c, item, ref, msg, revocationDetails(res))}
}

func checkRevocationUnverified(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	res := revocationFor(opts, item, ref)
	if res == nil {
		return nil
	}
	if (res.Status == RevocationGood || res.Status == RevocationRevoked) && !res.Verified {
		msg := fmt.Sprintf("Revocation answer (%s via %s) could not be verified against the issuer", res.Status, res.Method)
		return []CheckIssue{makeIssue(SeverityWarning, categoryRevocation, checkRevocationUnverifiedID, c, item, ref, msg, revocationDetails(res))}
	}
	return nil
}

func revocationFor(opts CheckOptions, item *CertItem, ref ItemRef) *RevocationResult {
	if !opts.RevocationEnabled || item.Certificate == nil {
		return nil
	}
	return opts.RevocationResults[ref]
}

func revocationDetails(res *RevocationResult) map[string]any {
	d := map[string]any{
		"status": string(res.Status),
		"method": string(res.Method),
	}
	if res.Reason != "" {
		d["reason"] = res.Reason
	}
	if !res.RevokedAt.IsZero() {
		d["revoked_at"] = res.RevokedAt.Format(time.RFC3339)
	}
	if s := attemptSummary(res); s != "" {
		d["attempts"] = s
	}
	return d
}

func attemptSummary(res *RevocationResult) string {
	var parts []string
	for _, a := range res.Attempts {
		if a.Err == "" {
			continue
		}
		src := a.Source
		if src == "" {
			src = string(a.Method)
		}
		parts = append(parts, fmt.Sprintf("%s: %s", src, a.Err))
	}
	return strings.Join(parts, "; ")
}
