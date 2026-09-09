//go:build dockertest

package certops

import (
	"strings"
	"testing"
	"time"
)

// --- Fetch tests ---

func TestDockerFetch_ExpiredCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portExpired)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{dockerTarget(portExpired)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least one cert")
	}

	leaf := tr.Certs[0].Cert.Certificate
	if leaf.NotAfter.After(time.Now()) {
		t.Errorf("expected expired cert, but NotAfter is %v (in the future)", leaf.NotAfter)
	}
}

func TestDockerFetch_SelfSignedCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portSelfSigned)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{dockerTarget(portSelfSigned)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least one cert")
	}

	leaf := tr.Certs[0].Cert.Certificate
	if leaf.Subject.String() != leaf.Issuer.String() {
		t.Errorf("expected self-signed cert (Subject==Issuer), got Subject=%q Issuer=%q",
			leaf.Subject, leaf.Issuer)
	}
}

func TestDockerFetch_WrongHostCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portWrongHost)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{dockerTarget(portWrongHost)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}
	if len(tr.Certs) == 0 {
		t.Fatal("expected at least one cert")
	}

	leaf := tr.Certs[0].Cert.Certificate
	if err := leaf.VerifyHostname("localhost"); err == nil {
		t.Error("expected VerifyHostname('localhost') to fail for wronghost cert")
	}
	if leaf.Subject.CommonName != "wrong.example.com" {
		t.Errorf("expected CN=wrong.example.com, got %q", leaf.Subject.CommonName)
	}
}

func TestDockerFetch_IncompleteChain(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portIncomplete)

	result, err := FetchRemoteCert(FetchRemoteCertOptions{
		Targets: []string{dockerTarget(portIncomplete)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("FetchRemoteCert error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}

	// Only leaf should be returned, no intermediate
	if len(tr.Certs) != 1 {
		t.Errorf("expected 1 cert (leaf only), got %d", len(tr.Certs))
	}
}

// --- Check tests ---

func TestDockerCheck_ExpiredCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portExpired)

	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{dockerTarget(portExpired)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("CheckRemote error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}

	found := false
	for _, issue := range tr.Issues {
		msg := strings.ToLower(issue.Message)
		if strings.Contains(msg, "expir") || strings.Contains(strings.ToLower(issue.CheckID), "expir") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected an issue related to 'expired' cert")
		for _, issue := range tr.Issues {
			t.Logf("  issue: [%s] %s: %s", issue.Severity, issue.CheckID, issue.Message)
		}
	}
}

func TestDockerCheck_SelfSignedCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portSelfSigned)

	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{dockerTarget(portSelfSigned)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("CheckRemote error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}

	found := false
	for _, issue := range tr.Issues {
		if issue.CheckID == "remote_self_signed" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected remote_self_signed issue")
		for _, issue := range tr.Issues {
			t.Logf("  issue: [%s] %s: %s", issue.Severity, issue.CheckID, issue.Message)
		}
	}
}

func TestDockerCheck_WrongHostCert(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portWrongHost)

	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{dockerTarget(portWrongHost)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("CheckRemote error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}

	found := false
	for _, issue := range tr.Issues {
		if issue.CheckID == "remote_hostname_mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected remote_hostname_mismatch issue")
		for _, issue := range tr.Issues {
			t.Logf("  issue: [%s] %s: %s", issue.Severity, issue.CheckID, issue.Message)
		}
	}
}

func TestDockerCheck_IncompleteChain(t *testing.T) {
	requireDockerAvailable(t)
	requireServiceAvailable(t, portIncomplete)

	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{dockerTarget(portIncomplete)},
		Timeout: dockerTestTimeout,
	})
	if err != nil {
		t.Fatalf("CheckRemote error: %v", err)
	}

	tr := result.TargetResults[0]
	if tr.Error != "" {
		t.Fatalf("unexpected error: %s", tr.Error)
	}

	found := false
	for _, issue := range tr.Issues {
		if issue.CheckID == "remote_chain_incomplete" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected remote_chain_incomplete issue")
		for _, issue := range tr.Issues {
			t.Logf("  issue: [%s] %s: %s", issue.Severity, issue.CheckID, issue.Message)
		}
	}
}
