package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func FormatRemoteCheckHuman(result *certops.CheckRemoteResult) string {
	var b strings.Builder

	for _, tr := range result.TargetResults {
		fmt.Fprintf(&b, "%s\n", tr.Target)

		if tr.Error != "" {
			fmt.Fprintf(&b, "  %s  %s\n", ColorizeSeverity(certlib.SeverityCritical), tr.Error)
			b.WriteString("\n")
			continue
		}

		if len(tr.Issues) == 0 {
			fmt.Fprintf(&b, "  OK       No issues found\n")
		}
		for _, issue := range tr.Issues {
			sev := colorizeSeverityPadded(issue.Severity, severityColWidth)
			fmt.Fprintf(&b, "  %s %s  [%s]\n", sev, issue.Message, issue.CheckID)
		}
		formatStoreVerdicts(&b, tr.StoreVerdicts)
		b.WriteString("\n")
	}

	// Summary
	fmt.Fprintf(&b, "Summary: %d critical, %d warnings, %d info\n",
		result.Summary.Critical, result.Summary.Warning, result.Summary.Info)
	fmt.Fprintf(&b, "Targets: %d total, %d ok, %d with issues\n",
		result.Summary.Total, countTargetsOK(result), countTargetsWithIssues(result))

	return b.String()
}

// targetHasProblems: INFO lines are observations, not problems; a target
// counts as "with issues" only on a warning, a critical finding or an error.
func targetHasProblems(tr certops.TargetCheckResult) bool {
	if tr.Error != "" {
		return true
	}
	for _, is := range tr.Issues {
		if is.Severity.Rank() >= certlib.SeverityWarning.Rank() {
			return true
		}
	}
	return false
}

func countTargetsOK(result *certops.CheckRemoteResult) int {
	count := 0
	for _, tr := range result.TargetResults {
		if !targetHasProblems(tr) {
			count++
		}
	}
	return count
}

func countTargetsWithIssues(result *certops.CheckRemoteResult) int {
	count := 0
	for _, tr := range result.TargetResults {
		if targetHasProblems(tr) {
			count++
		}
	}
	return count
}

type remoteCheckJSONOutput struct {
	Targets []remoteCheckJSONTarget `json:"targets" yaml:"targets"`
	Summary remoteCheckJSONSummary  `json:"summary" yaml:"summary"`
}

type remoteCheckJSONTarget struct {
	Target      string                       `json:"target" yaml:"target"`
	Connection  *remoteCheckJSONConnection   `json:"connection,omitempty" yaml:"connection,omitempty"`
	Issues      []remoteCheckJSONIssue       `json:"issues" yaml:"issues"`
	TrustStores []certops.RemoteStoreVerdict `json:"trust_stores,omitempty" yaml:"trust_stores,omitempty"`
	Summary     remoteCheckJSONTargetSummary `json:"summary" yaml:"summary"`
	Error       string                       `json:"error,omitempty" yaml:"error,omitempty"`
}

type remoteCheckJSONConnection struct {
	TLSVersion  string `json:"tls_version" yaml:"tls_version"`
	CipherSuite string `json:"cipher_suite" yaml:"cipher_suite"`
	ALPN        string `json:"alpn,omitempty" yaml:"alpn,omitempty"`
}

type remoteCheckJSONIssue struct {
	Severity string         `json:"severity" yaml:"severity"`
	Category string         `json:"category" yaml:"category"`
	CheckID  string         `json:"check_id" yaml:"check_id"`
	Message  string         `json:"message" yaml:"message"`
	Details  map[string]any `json:"details,omitempty" yaml:"details,omitempty"`
}

type remoteCheckJSONTargetSummary struct {
	Critical int `json:"critical" yaml:"critical"`
	Warning  int `json:"warning" yaml:"warning"`
	Info     int `json:"info" yaml:"info"`
}

type remoteCheckJSONSummary struct {
	Total     int `json:"total" yaml:"total"`
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	Failed    int `json:"failed" yaml:"failed"`
	Critical  int `json:"critical" yaml:"critical"`
	Warning   int `json:"warning" yaml:"warning"`
	Info      int `json:"info" yaml:"info"`
}

func buildRemoteCheckStructured(result *certops.CheckRemoteResult) remoteCheckJSONOutput {
	out := remoteCheckJSONOutput{
		Summary: remoteCheckJSONSummary{
			Total:     result.Summary.Total,
			Succeeded: result.Summary.Succeeded,
			Failed:    result.Summary.Failed,
			Critical:  result.Summary.Critical,
			Warning:   result.Summary.Warning,
			Info:      result.Summary.Info,
		},
	}

	for _, tr := range result.TargetResults {
		target := remoteCheckJSONTarget{
			Target:      tr.Target,
			Error:       tr.Error,
			TrustStores: tr.StoreVerdicts,
			Summary: remoteCheckJSONTargetSummary{
				Critical: tr.Summary.Critical,
				Warning:  tr.Summary.Warning,
				Info:     tr.Summary.Info,
			},
		}

		if tr.Connection != nil {
			target.Connection = &remoteCheckJSONConnection{
				TLSVersion:  tr.Connection.TLSVersion,
				CipherSuite: tr.Connection.CipherSuite,
				ALPN:        tr.Connection.ALPN,
			}
		}

		for _, issue := range tr.Issues {
			target.Issues = append(target.Issues, remoteCheckJSONIssue{
				Severity: string(issue.Severity),
				Category: issue.Category,
				CheckID:  issue.CheckID,
				Message:  issue.Message,
				Details:  issue.Details,
			})
		}

		if target.Issues == nil {
			target.Issues = []remoteCheckJSONIssue{}
		}

		out.Targets = append(out.Targets, target)
	}

	return out
}

func FormatRemoteCheckJSON(result *certops.CheckRemoteResult) string {
	out := buildRemoteCheckStructured(result)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(data) + "\n"
}

func FormatRemoteCheckYAML(result *certops.CheckRemoteResult) string {
	out := buildRemoteCheckStructured(result)
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}
