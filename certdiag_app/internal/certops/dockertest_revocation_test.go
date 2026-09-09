//go:build dockertest

package certops

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

const (
	portRevocableGood    = 14562
	portRevocableRevoked = 14563
)

// checkRevocation runs `remote check` against a revocation vhost with the given
// method and returns the single target result.
func checkRevocation(t *testing.T, port int, method certlib.RevocationMethod) TargetCheckResult {
	t.Helper()
	requireDockerAvailable(t)
	requireServiceAvailable(t, port)

	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{dockerTarget(port)},
		Timeout: dockerTestTimeout,
		Revocation: RevocationConfig{
			Enabled: true,
			Method:  method,
		},
	})
	if err != nil {
		t.Fatalf("CheckRemote error: %v", err)
	}
	return result.TargetResults[0]
}

func findIssue(tr TargetCheckResult, checkID string) *certlib.CheckIssue {
	for i := range tr.Issues {
		if tr.Issues[i].CheckID == checkID {
			return &tr.Issues[i]
		}
	}
	return nil
}

func TestDockerRevocation_OCSPRevoked(t *testing.T) {
	tr := checkRevocation(t, portRevocableRevoked, certlib.RevocationMethodOCSP)
	issue := findIssue(tr, "remote_revocation_revoked")
	if issue == nil {
		t.Fatalf("expected remote_revocation_revoked issue, got issues: %+v", issueIDs(tr))
	}
	if issue.Severity != certlib.SeverityCritical {
		t.Errorf("expected critical, got %s", issue.Severity)
	}
	if m, _ := issue.Details["method"].(string); m != string(certlib.RevocationMethodOCSP) {
		t.Errorf("expected method ocsp, got %q", m)
	}
}

func TestDockerRevocation_OCSPGood(t *testing.T) {
	tr := checkRevocation(t, portRevocableGood, certlib.RevocationMethodOCSP)
	if findIssue(tr, "remote_revocation_revoked") != nil {
		t.Fatal("good cert must not be flagged revoked")
	}
	if findIssue(tr, "remote_revocation_undetermined") != nil {
		t.Fatalf("good OCSP status should be determinable, got: %+v", issueIDs(tr))
	}
}

func TestDockerRevocation_CRLRevoked(t *testing.T) {
	tr := checkRevocation(t, portRevocableRevoked, certlib.RevocationMethodCRL)
	issue := findIssue(tr, "remote_revocation_revoked")
	if issue == nil {
		t.Fatalf("expected revoked via CRL, got issues: %+v", issueIDs(tr))
	}
	if m, _ := issue.Details["method"].(string); m != string(certlib.RevocationMethodCRL) {
		t.Errorf("expected method crl, got %q", m)
	}
}

func TestDockerRevocation_AutoPrefersOCSP(t *testing.T) {
	tr := checkRevocation(t, portRevocableRevoked, certlib.RevocationMethodAuto)
	issue := findIssue(tr, "remote_revocation_revoked")
	if issue == nil {
		t.Fatalf("expected revoked via auto, got issues: %+v", issueIDs(tr))
	}
	// No staple is served, so auto should resolve via live OCSP before CRL.
	if m, _ := issue.Details["method"].(string); m != string(certlib.RevocationMethodOCSP) {
		t.Errorf("auto should prefer OCSP, got method %q", m)
	}
}

func issueIDs(tr TargetCheckResult) []string {
	var ids []string
	for _, is := range tr.Issues {
		ids = append(ids, is.CheckID)
	}
	return ids
}
