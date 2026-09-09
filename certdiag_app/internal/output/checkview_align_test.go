package output

import (
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func forceColors(t *testing.T) {
	t.Helper()
	oldEnabled := ColorsEnabled
	oldNoColor := color.NoColor
	ColorsEnabled = true
	color.NoColor = false
	t.Cleanup(func() {
		ColorsEnabled = oldEnabled
		color.NoColor = oldNoColor
	})
}

func mixedSeverityCheckResult() *certlib.CheckResult {
	return &certlib.CheckResult{
		Issues: []certlib.CheckIssue{
			{Severity: certlib.SeverityCritical, Filename: "a.pem", Message: "expired"},
			{Severity: certlib.SeverityWarning, Filename: "b.pem", Message: "expires soon"},
			{Severity: certlib.SeverityInfo, Filename: "c.pem", Message: "weak key"},
		},
		FilesScanned: 3,
		Summary:      certlib.CheckSummary{Critical: 1, Warning: 1, Info: 1, FilesWithIssues: 3},
	}
}

func TestFormatCheckHuman_SeverityColumnAligned(t *testing.T) {
	forceColors(t)

	out := FormatCheckHuman(mixedSeverityCheckResult(), 0)

	if !strings.Contains(out, "\x1b[") {
		t.Fatal("expected ANSI escapes with colors forced on")
	}

	filenameCol := -1
	for _, raw := range strings.Split(out, "\n") {
		line := stripANSI(raw)
		if !strings.Contains(line, ".pem") {
			continue
		}
		if len(line) < severityColWidth+1 {
			t.Fatalf("line shorter than severity column: %q", line)
		}
		if line[severityColWidth] != ' ' {
			t.Errorf("severity field not padded to %d visible chars: %q", severityColWidth, line)
		}
		col := strings.Index(line, ".pem")
		if filenameCol == -1 {
			filenameCol = col
		} else if col != filenameCol {
			t.Errorf("filename column drifted: got %d want %d in %q", col, filenameCol, line)
		}
	}
	if filenameCol == -1 {
		t.Fatal("no issue lines rendered")
	}
}

func TestFormatCheckHuman_SeverityColumnAligned_NoColor(t *testing.T) {
	disableColors(t)

	out := FormatCheckHuman(mixedSeverityCheckResult(), 0)

	if strings.Contains(out, "\x1b[") {
		t.Fatal("unexpected ANSI escapes in no-color mode")
	}

	filenameCol := -1
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ".pem") {
			continue
		}
		col := strings.Index(line, ".pem")
		if filenameCol == -1 {
			filenameCol = col
		} else if col != filenameCol {
			t.Errorf("filename column drifted: got %d want %d in %q", col, filenameCol, line)
		}
	}
	if filenameCol == -1 {
		t.Fatal("no issue lines rendered")
	}
}

func TestColorizeSeverityPadded_VisibleWidth(t *testing.T) {
	forceColors(t)

	for _, sev := range []certlib.CheckSeverity{
		certlib.SeverityCritical,
		certlib.SeverityWarning,
		certlib.SeverityInfo,
	} {
		got := colorizeSeverityPadded(sev, severityColWidth)
		if !strings.Contains(got, "\x1b[") {
			t.Errorf("severity %q not colorized: %q", sev, got)
		}
		if visible := stripANSI(got); len(visible) != severityColWidth {
			t.Errorf("severity %q visible width = %d, want %d (%q)", sev, len(visible), severityColWidth, visible)
		}
	}
}

func TestFormatRemoteCheckHuman_SeverityColumnAligned(t *testing.T) {
	forceColors(t)

	result := &certops.CheckRemoteResult{
		TargetResults: []certops.TargetCheckResult{
			{
				Target: "example.com:443",
				Issues: []certlib.CheckIssue{
					{Severity: certlib.SeverityCritical, CheckID: "c1", Message: "expired"},
					{Severity: certlib.SeverityWarning, CheckID: "c2", Message: "expires soon"},
					{Severity: certlib.SeverityInfo, CheckID: "c3", Message: "weak key"},
				},
			},
		},
		Summary: certops.CheckRemoteSummary{Total: 1, Succeeded: 1},
	}

	out := FormatRemoteCheckHuman(result)

	if !strings.Contains(out, "\x1b[") {
		t.Fatal("expected ANSI escapes with colors forced on")
	}

	msgCol := -1
	for _, raw := range strings.Split(out, "\n") {
		line := stripANSI(raw)
		if !strings.Contains(line, "[c") {
			continue
		}
		col := -1
		for _, marker := range []string{"expired", "expires soon", "weak key"} {
			if i := strings.Index(line, marker); i >= 0 {
				col = i
				break
			}
		}
		if msgCol == -1 {
			msgCol = col
		} else if col != msgCol {
			t.Errorf("message column drifted: got %d want %d in %q", col, msgCol, line)
		}
	}
	if msgCol == -1 {
		t.Fatal("no issue lines rendered")
	}
}
