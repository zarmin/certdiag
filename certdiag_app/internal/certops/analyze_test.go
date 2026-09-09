package certops

import (
	"crypto/x509"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestAnalyze_SharedWithScan guards R9: a store assembled elsewhere (pcap, the
// TUI walk) gets the same relations, chains and checks the file scan gets,
// including the disabled-checks policy.
func TestAnalyze_SharedWithScan(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Analyze Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.analyze", false, root, rootKey, nil)

	build := func() *certlib.CertStore {
		store := certlib.NewCertStore()
		store.AddContainer(certlib.CertContainer{
			FilePath: "/tmp/chain.pem", Format: certlib.FormatPEM,
			Items: []certlib.CertItem{
				{Type: certlib.ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw},
				{Type: certlib.ContentCertificate, Certificate: root, RawBytes: root.Raw},
			},
		})
		return store
	}

	res := Analyze(build(), ScanOptions{AssembleChains: true, Check: true})
	if res.RelIndex == nil {
		t.Fatal("relations were not detected")
	}
	if len(res.Chains) == 0 {
		t.Error("chains were not assembled")
	}
	if res.CheckResult == nil {
		t.Fatal("checks did not run")
	}
	fired := map[string]bool{}
	for _, is := range res.CheckResult.Issues {
		fired[is.CheckID] = true
	}
	if !fired["self_signed_leaf"] && !fired["missing_sans"] && len(fired) == 0 {
		t.Fatalf("expected at least one finding on the fixture, got none")
	}
	var disable []string
	for id := range fired {
		disable = append(disable, id)
	}

	again := Analyze(build(), ScanOptions{Check: true, CheckOptions: certlib.CheckOptions{DisabledChecks: disable}})
	for _, is := range again.CheckResult.Issues {
		if fired[is.CheckID] {
			t.Errorf("disabled check %s still fired through Analyze", is.CheckID)
		}
	}
	_ = x509.ExtKeyUsageAny
}
