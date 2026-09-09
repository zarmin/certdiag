package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func makeTestCheckResult() *certops.CheckRemoteResult {
	return &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{
				Target: "example.com:443",
				Connection: &certops.RemoteConnectionInfo{
					TLSVersion:  "TLS 1.3",
					CipherSuite: "TLS_AES_256_GCM_SHA384",
				},
				Issues: []certlib.CheckIssue{
					{
						Severity: certlib.SeverityWarning,
						Category: "remote",
						CheckID:  "remote_no_ocsp_staple",
						Message:  "No OCSP stapling",
					},
				},
				Summary: certlib.CheckSummary{
					Warning: 1,
				},
			},
			{
				Target: "error.example.com:443",
				Error:  "connection refused",
			},
		},
		Summary: certops.CheckRemoteSummary{
			Total:     2,
			Succeeded: 1,
			Failed:    1,
			Warning:   1,
		},
	}
}

func TestFormatRemoteCheckHuman(t *testing.T) {
	result := makeTestCheckResult()
	out := FormatRemoteCheckHuman(result)

	if !strings.Contains(out, "example.com:443") {
		t.Error("expected target in output")
	}
	if !strings.Contains(out, "No OCSP stapling") {
		t.Error("expected issue message")
	}
	if !strings.Contains(out, "remote_no_ocsp_staple") {
		t.Error("expected check ID")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error in output")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("expected summary")
	}
}

func TestFormatRemoteCheckHuman_NoIssues(t *testing.T) {
	result := &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{
				Target: "good.example.com:443",
				Connection: &certops.RemoteConnectionInfo{
					TLSVersion: "TLS 1.3",
				},
			},
		},
		Summary: certops.CheckRemoteSummary{
			Total:     1,
			Succeeded: 1,
		},
	}
	out := FormatRemoteCheckHuman(result)
	if !strings.Contains(out, "No issues found") {
		t.Error("expected 'No issues found'")
	}
}

func TestFormatRemoteCheckJSON(t *testing.T) {
	result := makeTestCheckResult()
	out := FormatRemoteCheckJSON(result)

	var parsed remoteCheckJSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(parsed.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(parsed.Targets))
	}
	if parsed.Targets[0].Target != "example.com:443" {
		t.Errorf("unexpected target: %s", parsed.Targets[0].Target)
	}
	if len(parsed.Targets[0].Issues) != 1 {
		t.Errorf("expected 1 issue, got %d", len(parsed.Targets[0].Issues))
	}
	if parsed.Targets[1].Error != "connection refused" {
		t.Errorf("expected error, got %q", parsed.Targets[1].Error)
	}
	if parsed.Summary.Total != 2 {
		t.Errorf("expected total=2, got %d", parsed.Summary.Total)
	}
}

func TestFormatRemoteCheckYAML(t *testing.T) {
	result := makeTestCheckResult()
	out := FormatRemoteCheckYAML(result)

	if !strings.Contains(out, "example.com:443") {
		t.Error("expected target in YAML")
	}
	if !strings.Contains(out, "remote_no_ocsp_staple") {
		t.Error("expected check ID in YAML")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error in YAML")
	}
}

func TestFormatRemoteCheckHuman_OKCount(t *testing.T) {
	warnIssue := []certlib.CheckIssue{{Severity: certlib.SeverityWarning, CheckID: "x", Message: "y"}}
	result := &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{Target: "clean1:443"},
			{Target: "clean2:443"},
			{Target: "issues:443", Issues: warnIssue},
			{Target: "err1:443", Error: "connection refused"},
			{Target: "err2:443", Error: "connection refused"},
			{Target: "err3:443", Error: "connection refused"},
		},
		Summary: certops.CheckRemoteSummary{
			Total:     6,
			Succeeded: 3,
			Failed:    3,
			Warning:   1,
		},
	}

	if got := countTargetsOK(result); got != 2 {
		t.Errorf("expected 2 ok, got %d", got)
	}
	if got := countTargetsWithIssues(result); got != 4 {
		t.Errorf("expected 4 with issues, got %d", got)
	}

	// old formula (Succeeded - countTargetsWithIssues) would have been 3-4 = -1
	if countTargetsOK(result) < 0 {
		t.Error("ok count must never be negative")
	}
	if countTargetsOK(result)+countTargetsWithIssues(result) != result.Summary.Total {
		t.Error("ok + with-issues must reconcile to total")
	}

	out := FormatRemoteCheckHuman(result)
	if !strings.Contains(out, "6 total, 2 ok, 4 with issues") {
		t.Errorf("unexpected summary line: %q", out)
	}
}

func makeUnmarshalableCheckResult() *certops.CheckRemoteResult {
	return &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{
				Target: "example.com:443",
				Issues: []certlib.CheckIssue{
					{
						Severity: certlib.SeverityWarning,
						CheckID:  "x",
						Message:  "y",
						Details:  map[string]any{"bad": make(chan int)},
					},
				},
			},
		},
		Summary: certops.CheckRemoteSummary{Total: 1},
	}
}

func TestFormatRemoteCheckJSON_MarshalError(t *testing.T) {
	out := FormatRemoteCheckJSON(makeUnmarshalableCheckResult())
	if out == "" {
		t.Fatal("marshal failure must not produce empty output")
	}
	if !strings.Contains(out, "error") {
		t.Errorf("expected error surfaced in output, got %q", out)
	}
}

func TestFormatRemoteCheckJSON_EmptyIssues(t *testing.T) {
	result := &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{Target: "good.example.com:443"},
		},
		Summary: certops.CheckRemoteSummary{Total: 1, Succeeded: 1},
	}
	out := FormatRemoteCheckJSON(result)

	var parsed remoteCheckJSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	// Issues should be empty array, not null
	if parsed.Targets[0].Issues == nil {
		t.Error("issues should be empty array, not nil")
	}
}
