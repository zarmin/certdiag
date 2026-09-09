package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

var (
	CriticalColor *color.Color
	InfoColor     *color.Color
)

func init() {
	CriticalColor = color.New(color.FgRed, color.Bold)
	InfoColor = color.New(color.Faint)
}

const severityColWidth = 10

func colorizeSeverityLabel(sev certlib.CheckSeverity, label string) string {
	if !ColorsEnabled {
		return label
	}
	switch sev {
	case certlib.SeverityCritical:
		return CriticalColor.Sprint(label)
	case certlib.SeverityWarning:
		return WarningColor.Sprint(label)
	case certlib.SeverityInfo:
		return InfoColor.Sprint(label)
	}
	return label
}

func ColorizeSeverity(sev certlib.CheckSeverity) string {
	return colorizeSeverityLabel(sev, strings.ToUpper(string(sev)))
}

func colorizeSeverityPadded(sev certlib.CheckSeverity, width int) string {
	label := fmt.Sprintf("%-*s", width, strings.ToUpper(string(sev)))
	return colorizeSeverityLabel(sev, label)
}

func FormatCheckHuman(result *certlib.CheckResult, hiddenInfo int) string {
	var b strings.Builder

	for _, issue := range result.Issues {
		sev := colorizeSeverityPadded(issue.Severity, severityColWidth)
		fmt.Fprintf(&b, "%s %-22s %s\n", sev, issue.Filename, issue.Message)
	}

	if len(result.Issues) > 0 {
		b.WriteString("\n")
	}

	// Revocation records list the status of every checked cert, including "good"
	// ones that produce no issue, and surface freshness notes (e.g. an expired
	// CRL) that otherwise appear only in JSON/YAML.
	if len(result.Revocations) > 0 {
		b.WriteString("Revocation:\n")
		for _, r := range result.Revocations {
			res := r.Result
			if res == nil {
				continue
			}
			line := fmt.Sprintf("  %-11s %s (via %s", string(res.Status), r.DN, res.Method)
			if res.Verified {
				line += ", verified"
			}
			if res.Reason != "" {
				line += ", reason: " + res.Reason
			}
			fmt.Fprintf(&b, "%s)\n", line)
			for _, a := range res.Attempts {
				if a.Err != "" {
					fmt.Fprintf(&b, "    note: %s\n", a.Err)
				}
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("Summary: ")
	parts := []string{
		fmt.Sprintf("%d critical", result.Summary.Critical),
		fmt.Sprintf("%d warnings", result.Summary.Warning),
	}
	if hiddenInfo > 0 {
		parts = append(parts, fmt.Sprintf("(%d info hidden)", hiddenInfo))
	} else {
		parts = append(parts, fmt.Sprintf("%d info", result.Summary.Info))
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n")

	fmt.Fprintf(&b, "Files scanned: %d | Files with issues: %d\n",
		result.FilesScanned, result.Summary.FilesWithIssues)

	return b.String()
}

type checkJSONOutput struct {
	Summary     checkJSONSummary      `json:"summary" yaml:"summary"`
	Issues      []checkJSONIssue      `json:"issues" yaml:"issues"`
	Revocations []checkJSONRevocation `json:"revocations,omitempty" yaml:"revocations,omitempty"`
}

type checkJSONRevocation struct {
	File       string `json:"file" yaml:"file"`
	FilePath   string `json:"file_path" yaml:"file_path"`
	ItemIndex  int    `json:"item_index" yaml:"item_index"`
	DN         string `json:"dn" yaml:"dn"`
	Status     string `json:"status" yaml:"status"`
	Method     string `json:"method,omitempty" yaml:"method,omitempty"`
	Verified   bool   `json:"verified" yaml:"verified"`
	Reason     string `json:"reason,omitempty" yaml:"reason,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	ThisUpdate string `json:"this_update,omitempty" yaml:"this_update,omitempty"`
	NextUpdate string `json:"next_update,omitempty" yaml:"next_update,omitempty"`
}

type checkJSONSummary struct {
	FilesScanned    int `json:"files_scanned" yaml:"files_scanned"`
	FilesWithIssues int `json:"files_with_issues" yaml:"files_with_issues"`
	Critical        int `json:"critical" yaml:"critical"`
	Warning         int `json:"warning" yaml:"warning"`
	Info            int `json:"info" yaml:"info"`
}

type checkJSONIssue struct {
	Severity  string         `json:"severity" yaml:"severity"`
	Category  string         `json:"category" yaml:"category"`
	CheckID   string         `json:"check_id" yaml:"check_id"`
	File      string         `json:"file" yaml:"file"`
	FilePath  string         `json:"file_path" yaml:"file_path"`
	ItemIndex int            `json:"item_index" yaml:"item_index"`
	DN        string         `json:"dn" yaml:"dn"`
	Message   string         `json:"message" yaml:"message"`
	Details   map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
}

func buildCheckJSONOutput(result *certlib.CheckResult) checkJSONOutput {
	out := checkJSONOutput{
		Summary: checkJSONSummary{
			FilesScanned:    result.FilesScanned,
			FilesWithIssues: result.Summary.FilesWithIssues,
			Critical:        result.Summary.Critical,
			Warning:         result.Summary.Warning,
			Info:            result.Summary.Info,
		},
		Issues: make([]checkJSONIssue, 0, len(result.Issues)),
	}

	for _, issue := range result.Issues {
		out.Issues = append(out.Issues, checkJSONIssue{
			Severity:  string(issue.Severity),
			Category:  issue.Category,
			CheckID:   issue.CheckID,
			File:      issue.Filename,
			FilePath:  issue.FilePath,
			ItemIndex: issue.ItemIndex,
			DN:        issue.DN,
			Message:   issue.Message,
			Details:   issue.Details,
		})
	}

	for _, r := range result.Revocations {
		rev := checkJSONRevocation{
			File:      r.Filename,
			FilePath:  r.FilePath,
			ItemIndex: r.ItemIndex,
			DN:        r.DN,
			Status:    string(r.Result.Status),
			Method:    string(r.Result.Method),
			Verified:  r.Result.Verified,
			Reason:    r.Result.Reason,
		}
		if !r.Result.RevokedAt.IsZero() {
			rev.RevokedAt = r.Result.RevokedAt.Format(time.RFC3339)
		}
		if !r.Result.ThisUpdate.IsZero() {
			rev.ThisUpdate = r.Result.ThisUpdate.Format(time.RFC3339)
		}
		if !r.Result.NextUpdate.IsZero() {
			rev.NextUpdate = r.Result.NextUpdate.Format(time.RFC3339)
		}
		out.Revocations = append(out.Revocations, rev)
	}

	return out
}

func FormatCheckJSON(result *certlib.CheckResult) string {
	out := buildCheckJSONOutput(result)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(data) + "\n"
}

func FormatCheckYAML(result *certlib.CheckResult) string {
	out := buildCheckJSONOutput(result)
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}

type checkListJSONEntry struct {
	ID          string `json:"id" yaml:"id"`
	Category    string `json:"category" yaml:"category"`
	Severity    string `json:"severity" yaml:"severity"`
	Description string `json:"description" yaml:"description"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

func FormatCheckListHuman(disabledChecks []string) string {
	disabled := make(map[string]bool, len(disabledChecks))
	for _, id := range disabledChecks {
		disabled[id] = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-25s %-15s %-10s %s\n", "ID", "CATEGORY", "SEVERITY", "DESCRIPTION")

	for _, def := range certlib.AllChecks() {
		sev := strings.ToUpper(string(def.Severity))
		fmt.Fprintf(&b, "%-25s %-15s %-10s %s\n", def.ID, def.Category, sev, def.Description)
	}

	total, enabled, disabledCount := certlib.EnabledCheckCount(disabledChecks)
	fmt.Fprintf(&b, "\n%d checks available (%d enabled, %d disabled by config)\n", total, enabled, disabledCount)

	return b.String()
}

func FormatCheckListJSON(disabledChecks []string) string {
	entries := buildCheckListEntries(disabledChecks)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(data) + "\n"
}

func FormatCheckListYAML(disabledChecks []string) string {
	entries := buildCheckListEntries(disabledChecks)
	data, err := yaml.Marshal(entries)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}

func buildCheckListEntries(disabledChecks []string) []checkListJSONEntry {
	disabled := make(map[string]bool, len(disabledChecks))
	for _, id := range disabledChecks {
		disabled[id] = true
	}

	var entries []checkListJSONEntry
	for _, def := range certlib.AllChecks() {
		entries = append(entries, checkListJSONEntry{
			ID:          def.ID,
			Category:    def.Category,
			Severity:    string(def.Severity),
			Description: def.Description,
			Enabled:     !disabled[def.ID],
		})
	}
	return entries
}
