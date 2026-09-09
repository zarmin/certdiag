package certlib

import "fmt"

const (
	checkRemoteRevocationRevokedID      = "remote_revocation_revoked"
	checkRemoteRevocationUndeterminedID = "remote_revocation_undetermined"
	checkRemoteRevocationUnverifiedID   = "remote_revocation_unverified"
	checkRemoteStapleInvalidID          = "remote_staple_invalid"
)

func init() {
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          checkRemoteRevocationRevokedID,
		Category:    categoryRemote,
		Severity:    SeverityCritical,
		Description: "Leaf certificate is revoked (OCSP or CRL)",
		check:       checkRemoteRevocationRevoked,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          checkRemoteRevocationUndeterminedID,
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Revocation status could not be determined",
		check:       checkRemoteRevocationUndetermined,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          checkRemoteRevocationUnverifiedID,
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Revocation answer could not be cryptographically verified",
		check:       checkRemoteRevocationUnverified,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          checkRemoteStapleInvalidID,
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server provided an OCSP staple that failed to parse or verify",
		check:       checkRemoteStapleInvalid,
	})
}

func checkRemoteRevocationRevoked(ctx RemoteCheckContext, _ CheckOptions) []CheckIssue {
	res := ctx.Revocation
	if res == nil || res.Status != RevocationRevoked {
		return nil
	}
	msg := fmt.Sprintf("Certificate is REVOKED (via %s)", res.Method)
	if res.Reason != "" {
		msg += fmt.Sprintf(", reason: %s", res.Reason)
	}
	return []CheckIssue{makeRemoteIssue(SeverityCritical, checkRemoteRevocationRevokedID, ctx.Target.Address(), msg, revocationDetails(res))}
}

func checkRemoteRevocationUndetermined(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	res := ctx.Revocation
	if !opts.RevocationEnabled || res == nil || res.Status != RevocationUndetermined {
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
	return []CheckIssue{makeRemoteIssue(sev, checkRemoteRevocationUndeterminedID, ctx.Target.Address(), msg, revocationDetails(res))}
}

func checkRemoteRevocationUnverified(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	res := ctx.Revocation
	if !opts.RevocationEnabled || res == nil {
		return nil
	}
	if (res.Status == RevocationGood || res.Status == RevocationRevoked) && !res.Verified {
		msg := fmt.Sprintf("Revocation answer (%s via %s) could not be verified against the issuer", res.Status, res.Method)
		return []CheckIssue{makeRemoteIssue(SeverityWarning, checkRemoteRevocationUnverifiedID, ctx.Target.Address(), msg, revocationDetails(res))}
	}
	return nil
}

func checkRemoteStapleInvalid(ctx RemoteCheckContext, _ CheckOptions) []CheckIssue {
	res := ctx.Revocation
	if !ctx.TLSInfo.OCSPStapled || res == nil {
		return nil
	}
	if stapleFailed(res) {
		return []CheckIssue{makeRemoteIssue(SeverityWarning, checkRemoteStapleInvalidID, ctx.Target.Address(),
			"Server provided an OCSP staple that failed to parse or verify", nil)}
	}
	return nil
}

func stapleFailed(res *RevocationResult) bool {
	for _, a := range res.Attempts {
		if a.Method == RevocationMethodStapledOCSP && a.Err != "" {
			return true
		}
	}
	// A staple that parsed to a determinate status is not "invalid" even when it
	// could not be verified (e.g. no issuer available) - that case is reported by
	// the separate unverified check. Only an undetermined staple failed outright.
	return res.Method == RevocationMethodStapledOCSP && res.Status == RevocationUndetermined
}
