package certlib

import (
	"crypto/x509"
	"testing"
)

func revocationStore(t *testing.T, leaf *x509.Certificate) (*CertStore, ItemRef) {
	t.Helper()
	store := NewCertStore()
	store.AddContainer(CertContainer{
		FilePath: "leaf.pem",
		Items:    []CertItem{{Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
	})
	ref := ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "leaf.pem"}
	return store, ref
}

func runRevocationChecks(t *testing.T, store *CertStore, ref ItemRef, enabled, require bool, res *RevocationResult) *CheckResult {
	t.Helper()
	opts := CheckOptions{
		RevocationEnabled: enabled,
		RevocationRequire: require,
		RevocationResults: map[ItemRef]*RevocationResult{ref: res},
		Categories:        []string{categoryRevocation},
	}
	return RunChecks(store, RelationIndex{}, opts)
}

func hasCheck(res *CheckResult, id string) *CheckIssue {
	for i := range res.Issues {
		if res.Issues[i].CheckID == id {
			return &res.Issues[i]
		}
	}
	return nil
}

func TestRevocationChecks(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 500, nil, nil)
	store, ref := revocationStore(t, leaf)

	t.Run("revoked is critical", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, false, &RevocationResult{Status: RevocationRevoked, Method: RevocationMethodOCSP, Verified: true, Reason: reasonKeyCompromise})
		issue := hasCheck(res, checkRevocationRevokedID)
		if issue == nil || issue.Severity != SeverityCritical {
			t.Fatalf("expected critical revoked issue, got %+v", res.Issues)
		}
	})

	t.Run("undetermined is warning", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, false, &RevocationResult{Status: RevocationUndetermined})
		issue := hasCheck(res, checkRevocationUndeterminedID)
		if issue == nil || issue.Severity != SeverityWarning {
			t.Fatalf("expected warning undetermined, got %+v", res.Issues)
		}
	})

	t.Run("undetermined with require is critical", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, true, &RevocationResult{Status: RevocationUndetermined})
		issue := hasCheck(res, checkRevocationUndeterminedID)
		if issue == nil || issue.Severity != SeverityCritical {
			t.Fatalf("expected critical under require, got %+v", res.Issues)
		}
	})

	t.Run("determinate unverified warns", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, false, &RevocationResult{Status: RevocationGood, Method: RevocationMethodCRL, Verified: false})
		if hasCheck(res, checkRevocationUnverifiedID) == nil {
			t.Fatalf("expected unverified warning, got %+v", res.Issues)
		}
	})

	t.Run("good verified produces no issue", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, false, &RevocationResult{Status: RevocationGood, Method: RevocationMethodOCSP, Verified: true})
		if len(res.Issues) != 0 {
			t.Fatalf("expected no issues, got %+v", res.Issues)
		}
	})

	t.Run("disabled produces no issues", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, false, false, &RevocationResult{Status: RevocationRevoked})
		if len(res.Issues) != 0 {
			t.Fatalf("revocation disabled must yield no issues, got %+v", res.Issues)
		}
	})

	t.Run("nil result produces no issues", func(t *testing.T) {
		res := runRevocationChecks(t, store, ref, true, false, nil)
		if len(res.Issues) != 0 {
			t.Fatalf("expected no issues for nil result, got %+v", res.Issues)
		}
	})

	t.Run("disabled-checks suppresses revoked", func(t *testing.T) {
		opts := CheckOptions{
			RevocationEnabled: true,
			RevocationResults: map[ItemRef]*RevocationResult{ref: {Status: RevocationRevoked, Method: RevocationMethodOCSP, Verified: true}},
			Categories:        []string{categoryRevocation},
			DisabledChecks:    []string{checkRevocationRevokedID},
		}
		res := RunChecks(store, RelationIndex{}, opts)
		if hasCheck(res, checkRevocationRevokedID) != nil {
			t.Fatal("disabled check still fired")
		}
	})
}

func TestRemoteRevocationChecks(t *testing.T) {
	pki := newTestPKI(t)
	leaf := makeLeaf(t, pki, 501, nil, nil)

	t.Run("revoked critical", func(t *testing.T) {
		ctx := RemoteCheckContext{
			Target:       RemoteTarget{Host: "x", Port: 443},
			Certificates: []*x509.Certificate{leaf},
			Revocation:   &RevocationResult{Status: RevocationRevoked, Method: RevocationMethodOCSP, Reason: reasonKeyCompromise},
		}
		res := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: true})
		if hasCheck(res, checkRemoteRevocationRevokedID) == nil {
			t.Fatalf("expected remote revoked, got %+v", res.Issues)
		}
	})

	t.Run("undetermined only when enabled", func(t *testing.T) {
		ctx := RemoteCheckContext{
			Target:     RemoteTarget{Host: "x", Port: 443},
			Revocation: &RevocationResult{Status: RevocationUndetermined},
		}
		off := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: false})
		if hasCheck(off, checkRemoteRevocationUndeterminedID) != nil {
			t.Fatal("undetermined should not fire when revocation not requested")
		}
		on := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: true})
		if hasCheck(on, checkRemoteRevocationUndeterminedID) == nil {
			t.Fatal("undetermined should fire when requested")
		}
	})

	t.Run("unverified good fires a warning", func(t *testing.T) {
		// A determinate answer (good) from a source we could not verify (e.g. a
		// delegated OCSP responder lacking the OCSPSigning EKU) must not pass
		// silently on remote check.
		ctx := RemoteCheckContext{
			Target:       RemoteTarget{Host: "x", Port: 443},
			Certificates: []*x509.Certificate{leaf},
			Revocation:   &RevocationResult{Status: RevocationGood, Method: RevocationMethodOCSP, Verified: false},
		}
		off := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: false})
		if hasCheck(off, checkRemoteRevocationUnverifiedID) != nil {
			t.Fatal("unverified should not fire when revocation not requested")
		}
		on := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: true})
		if hasCheck(on, checkRemoteRevocationUnverifiedID) == nil {
			t.Fatalf("expected remote unverified warning, got %+v", on.Issues)
		}
	})

	t.Run("verified good does not warn", func(t *testing.T) {
		ctx := RemoteCheckContext{
			Target:       RemoteTarget{Host: "x", Port: 443},
			Certificates: []*x509.Certificate{leaf},
			Revocation:   &RevocationResult{Status: RevocationGood, Method: RevocationMethodOCSP, Verified: true},
		}
		res := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: true})
		if hasCheck(res, checkRemoteRevocationUnverifiedID) != nil {
			t.Fatal("a verified good answer must not warn")
		}
	})

	t.Run("valid unverified staple is not flagged invalid", func(t *testing.T) {
		// Parsed to a determinate status but not verified (no issuer) - handled by
		// the unverified check, not reported as a parse/verify failure.
		ctx := RemoteCheckContext{
			Target:  RemoteTarget{Host: "x", Port: 443},
			TLSInfo: TLSConnectionInfo{OCSPStapled: true},
			Revocation: &RevocationResult{
				Status:   RevocationGood,
				Method:   RevocationMethodStapledOCSP,
				Verified: false,
			},
		}
		res := RunRemoteChecks(ctx, CheckOptions{RevocationEnabled: true})
		if hasCheck(res, checkRemoteStapleInvalidID) != nil {
			t.Fatalf("a determinate unverified staple must not be flagged invalid: %+v", res.Issues)
		}
	})

	t.Run("staple invalid", func(t *testing.T) {
		ctx := RemoteCheckContext{
			Target:  RemoteTarget{Host: "x", Port: 443},
			TLSInfo: TLSConnectionInfo{OCSPStapled: true},
			Revocation: &RevocationResult{
				Status:   RevocationUndetermined,
				Method:   RevocationMethodStapledOCSP,
				Attempts: []RevocationAttempt{{Method: RevocationMethodStapledOCSP, Source: "staple", Err: "bad signature"}},
			},
		}
		res := RunRemoteChecks(ctx, CheckOptions{})
		if hasCheck(res, checkRemoteStapleInvalidID) == nil {
			t.Fatalf("expected staple invalid, got %+v", res.Issues)
		}
	})
}
