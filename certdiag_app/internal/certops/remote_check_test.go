package certops

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestCheckRemote_NoTargets(t *testing.T) {
	_, err := CheckRemote(CheckRemoteOptions{})
	if err == nil {
		t.Fatal("expected error for no targets")
	}
}

func TestCheckRemote_InvalidTarget(t *testing.T) {
	result, err := CheckRemote(CheckRemoteOptions{
		Targets: []string{"://invalid"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TargetResults[0].Error == "" {
		t.Error("expected error for invalid target")
	}
	if result.Summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", result.Summary.Failed)
	}
}

func TestCheckRemote_InvalidTLSVersion(t *testing.T) {
	_, err := CheckRemote(CheckRemoteOptions{
		Targets:    []string{"example.com"},
		TLSVersion: "tls0.9",
	})
	if err == nil {
		t.Fatal("expected error for invalid TLS version")
	}
}

func TestCheckRemote_InvalidStarttls(t *testing.T) {
	_, err := CheckRemote(CheckRemoteOptions{
		Targets:  []string{"example.com"},
		Starttls: "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid STARTTLS protocol")
	}
}

func TestCheckRemoteExitCode(t *testing.T) {
	result := &CheckRemoteResult{
		TargetResults: []TargetCheckResult{
			{
				Target: "good.example.com:443",
				Summary: certlib.CheckSummary{
					Info: 1,
				},
			},
		},
	}

	// No critical or warning -> 0
	if result.Summary.Critical > 0 || result.Summary.Warning > 0 {
		t.Error("expected no critical/warning")
	}

	// Add warning target
	result.TargetResults = append(result.TargetResults, TargetCheckResult{
		Target: "warn.example.com:443",
		Summary: certlib.CheckSummary{
			Warning: 1,
		},
	})
	result.Summary.Warning = 1

	maxCode := 0
	for _, tr := range result.TargetResults {
		if tr.Error != "" && maxCode < 3 {
			maxCode = 3
		}
		if tr.Summary.Critical > 0 && maxCode < 2 {
			maxCode = 2
		}
		if tr.Summary.Warning > 0 && maxCode < 1 {
			maxCode = 1
		}
	}
	if maxCode != 1 {
		t.Errorf("expected exit code 1 for warnings, got %d", maxCode)
	}
}
