package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

func TestFormatCheckHuman(t *testing.T) {
	disableColors(t)

	t.Run("no issues", func(t *testing.T) {
		result := &certlib.CheckResult{
			FilesScanned: 5,
			Summary:      certlib.CheckSummary{},
		}
		got := FormatCheckHuman(result, 0)
		if !strings.Contains(got, "Summary:") {
			t.Error("should contain Summary")
		}
		if !strings.Contains(got, "Files scanned: 5") {
			t.Error("should contain files scanned count")
		}
	})

	t.Run("one issue", func(t *testing.T) {
		result := &certlib.CheckResult{
			Issues: []certlib.CheckIssue{{
				Severity: certlib.SeverityWarning,
				Filename: "test.pem",
				Message:  "cert expires soon",
			}},
			FilesScanned: 1,
			Summary:      certlib.CheckSummary{Warning: 1, FilesWithIssues: 1},
		}
		got := FormatCheckHuman(result, 0)
		if !strings.Contains(got, "WARNING") {
			t.Error("should contain severity")
		}
		if !strings.Contains(got, "test.pem") {
			t.Error("should contain filename")
		}
		if !strings.Contains(got, "cert expires soon") {
			t.Error("should contain message")
		}
	})

	t.Run("revocation records rendered", func(t *testing.T) {
		result := &certlib.CheckResult{
			FilesScanned: 1,
			Revocations: []certlib.RevocationRecord{{
				DN: "CN=leaf.example.com",
				Result: &certlib.RevocationResult{
					Status:   certlib.RevocationGood,
					Method:   certlib.RevocationMethodCRL,
					Verified: true,
					Attempts: []certlib.RevocationAttempt{{Method: certlib.RevocationMethodCRL, Err: "CRL is expired (nextUpdate in the past)"}},
				},
			}},
		}
		got := FormatCheckHuman(result, 0)
		if !strings.Contains(got, "Revocation:") {
			t.Error("should contain a Revocation section")
		}
		if !strings.Contains(got, "CN=leaf.example.com") || !strings.Contains(got, "good") {
			t.Errorf("should list the cert and status:\n%s", got)
		}
		if !strings.Contains(got, "CRL is expired") {
			t.Errorf("should surface the freshness note in human output:\n%s", got)
		}
	})

	t.Run("hidden info", func(t *testing.T) {
		result := &certlib.CheckResult{
			FilesScanned: 3,
			Summary:      certlib.CheckSummary{Info: 5},
		}
		got := FormatCheckHuman(result, 5)
		if !strings.Contains(got, "(5 info hidden)") {
			t.Errorf("should contain hidden info count, got %q", got)
		}
	})
}

func TestFormatCheckJSON(t *testing.T) {
	t.Run("with issues", func(t *testing.T) {
		result := &certlib.CheckResult{
			Issues: []certlib.CheckIssue{{
				Severity: certlib.SeverityCritical,
				Category: "expiry",
				CheckID:  "expired",
				Filename: "cert.pem",
				FilePath: "/tmp/cert.pem",
				Message:  "certificate expired",
			}},
			FilesScanned: 1,
			Summary:      certlib.CheckSummary{Critical: 1, FilesWithIssues: 1},
		}
		got := FormatCheckJSON(result)
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		issues, ok := parsed["issues"].([]interface{})
		if !ok || len(issues) != 1 {
			t.Errorf("expected 1 issue in JSON")
		}
	})

	t.Run("empty issues", func(t *testing.T) {
		result := &certlib.CheckResult{FilesScanned: 0}
		got := FormatCheckJSON(result)
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		issues, ok := parsed["issues"].([]interface{})
		if !ok || len(issues) != 0 {
			t.Errorf("expected empty issues array")
		}
	})
}

func TestFormatCheckYAML(t *testing.T) {
	result := &certlib.CheckResult{
		Issues: []certlib.CheckIssue{{
			Severity: certlib.SeverityInfo,
			Category: "key",
			Message:  "weak key",
		}},
		FilesScanned: 1,
		Summary:      certlib.CheckSummary{Info: 1},
	}
	got := FormatCheckYAML(result)
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
}

func TestFormatCheckListHuman(t *testing.T) {
	got := FormatCheckListHuman(nil)
	if !strings.Contains(got, "ID") {
		t.Error("should contain header ID")
	}
	if !strings.Contains(got, "CATEGORY") {
		t.Error("should contain header CATEGORY")
	}
	if !strings.Contains(got, "checks available") {
		t.Error("should contain summary line")
	}
}

func TestFormatCheckListJSON(t *testing.T) {
	got := FormatCheckListJSON(nil)
	var parsed []interface{}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) == 0 {
		t.Error("expected at least one check entry")
	}
	first, ok := parsed[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected object entry")
	}
	for _, key := range []string{"id", "category", "severity", "enabled"} {
		if _, ok := first[key]; !ok {
			t.Errorf("entry missing key %q", key)
		}
	}
}

func TestFormatCheckListYAML(t *testing.T) {
	got := FormatCheckListYAML(nil)
	var parsed interface{}
	if err := yaml.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}
}

func TestBuildCheckListEntries(t *testing.T) {
	t.Run("all enabled", func(t *testing.T) {
		entries := buildCheckListEntries(nil)
		for _, e := range entries {
			if !e.Enabled {
				t.Errorf("entry %q should be enabled", e.ID)
			}
		}
	})

	t.Run("one disabled", func(t *testing.T) {
		all := certlib.AllChecks()
		if len(all) == 0 {
			t.Skip("no checks defined")
		}
		disabledID := all[0].ID
		entries := buildCheckListEntries([]string{disabledID})
		found := false
		for _, e := range entries {
			if e.ID == disabledID {
				found = true
				if e.Enabled {
					t.Errorf("entry %q should be disabled", e.ID)
				}
			}
		}
		if !found {
			t.Errorf("disabled entry %q not found", disabledID)
		}
	})
}
