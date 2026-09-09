package output

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

var (
	DiffHeaderColor  *color.Color
	DiffChangedColor *color.Color
	DiffAddedColor   *color.Color
	DiffRemovedColor *color.Color
	DiffSameColor    *color.Color
)

func init() {
	DiffHeaderColor = color.New(color.FgBlue, color.Bold)
	DiffChangedColor = color.New(color.FgYellow)
	DiffAddedColor = color.New(color.FgGreen)
	DiffRemovedColor = color.New(color.FgRed)
	DiffSameColor = color.New(color.Faint)
}

type DiffOutputOptions struct {
	OnlyChanges bool

	// FingerprintFormat controls how fingerprint rows are rendered in human
	// output. The zero value means plain hex. JSON/YAML stay canonical.
	FingerprintFormat certlib.FingerprintFormat
}

// fingerprintFieldNames is the set of diff field names that hold a certificate
// digest. Subject/Authority Key ID share the "fingerprint" category but are not
// digests of the certificate, so matching on the name rather than the category
// leaves them as bare hex.
var fingerprintFieldNames = func() map[string]bool {
	m := make(map[string]bool, len(certlib.FingerprintAlgos))
	for _, a := range certlib.FingerprintAlgos {
		m[a.Label()] = true
	}
	return m
}()

// reformatFingerprintFields returns a copy of result with fingerprint values
// re-rendered in the display format.
func reformatFingerprintFields(result certlib.DiffResult, format certlib.FingerprintFormat) certlib.DiffResult {
	if format == "" || format == certlib.FingerprintHex {
		return result
	}
	fields := make([]certlib.DiffField, len(result.Fields))
	copy(fields, result.Fields)
	for i := range fields {
		if !fingerprintFieldNames[fields[i].Name] {
			continue
		}
		fields[i].Left = certlib.ReformatFingerprint(fields[i].Left, format)
		fields[i].Right = certlib.ReformatFingerprint(fields[i].Right, format)
	}
	result.Fields = fields
	return result
}

func FormatDiffHuman(result certlib.DiffResult, opts DiffOutputOptions) string {
	result = reformatFingerprintFields(result, opts.FingerprintFormat)
	var sb strings.Builder

	leftLabel := formatDiffSourceLabel(result.Left)
	rightLabel := formatDiffSourceLabel(result.Right)

	if ColorsEnabled {
		sb.WriteString(DiffHeaderColor.Sprintf("--- %s", leftLabel))
	} else {
		sb.WriteString(fmt.Sprintf("--- %s", leftLabel))
	}
	sb.WriteString("\n")
	if ColorsEnabled {
		sb.WriteString(DiffHeaderColor.Sprintf("+++ %s", rightLabel))
	} else {
		sb.WriteString(fmt.Sprintf("+++ %s", rightLabel))
	}
	sb.WriteString("\n")

	if result.Identical() {
		sb.WriteString("\nAll fields are identical.\n")
		return sb.String()
	}

	sb.WriteString("\n")

	maxNameLen := 0
	for _, f := range result.Fields {
		if opts.OnlyChanges && f.Status == certlib.DiffSame {
			continue
		}
		if len(f.Name) > maxNameLen {
			maxNameLen = len(f.Name)
		}
	}

	for _, f := range result.Fields {
		if opts.OnlyChanges && f.Status == certlib.DiffSame {
			continue
		}
		sb.WriteString(formatDiffField(f, maxNameLen, opts.OnlyChanges))
	}

	sb.WriteString(formatDiffSummary(result.Summary, opts.OnlyChanges))
	return sb.String()
}

func formatDiffSourceLabel(src certlib.DiffSource) string {
	label := filepath.Base(src.FilePath)
	if src.ItemIndex > 0 || src.Alias != "" {
		indexPart := fmt.Sprintf("#%d", src.ItemIndex+1)
		if src.Alias != "" {
			label = fmt.Sprintf("%s [%s %q]", label, indexPart, src.Alias)
		} else {
			label = fmt.Sprintf("%s [%s]", label, indexPart)
		}
	}
	return label
}

func formatDiffField(f certlib.DiffField, nameWidth int, onlyChanges bool) string {
	var sb strings.Builder
	padding := strings.Repeat(" ", nameWidth-len(f.Name))
	prefix := fmt.Sprintf("  %s:%s  ", f.Name, padding)

	if len(f.Children) > 0 && f.Status == certlib.DiffChanged {
		sb.WriteString(fmt.Sprintf("  %s:\n", f.Name))
		for _, child := range f.Children {
			switch child.Status {
			case certlib.DiffSame:
				if onlyChanges {
					continue
				}
				line := fmt.Sprintf("      %s", child.Name)
				if ColorsEnabled {
					sb.WriteString(fmt.Sprintf("%s  %s\n", line, DiffSameColor.Sprint("(same)")))
				} else {
					sb.WriteString(fmt.Sprintf("%s  (same)\n", line))
				}
			case certlib.DiffAdded:
				line := fmt.Sprintf("    + %s", child.Name)
				if ColorsEnabled {
					sb.WriteString(fmt.Sprintf("%s  %s\n", DiffAddedColor.Sprint(line), DiffAddedColor.Sprint("(added)")))
				} else {
					sb.WriteString(fmt.Sprintf("%s  (added)\n", line))
				}
			case certlib.DiffRemoved:
				line := fmt.Sprintf("    - %s", child.Name)
				if ColorsEnabled {
					sb.WriteString(fmt.Sprintf("%s  %s\n", DiffRemovedColor.Sprint(line), DiffRemovedColor.Sprint("(removed)")))
				} else {
					sb.WriteString(fmt.Sprintf("%s  (removed)\n", line))
				}
			}
		}
		return sb.String()
	}

	switch f.Status {
	case certlib.DiffSame:
		if ColorsEnabled {
			sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, f.Left, DiffSameColor.Sprint("(same)")))
		} else {
			sb.WriteString(fmt.Sprintf("%s%s  (same)\n", prefix, f.Left))
		}
	case certlib.DiffChanged:
		if ColorsEnabled {
			sb.WriteString(fmt.Sprintf("%s%s  %s  %s\n", prefix, f.Left,
				DiffChangedColor.Sprint("->"), DiffChangedColor.Sprint(f.Right)))
		} else {
			sb.WriteString(fmt.Sprintf("%s%s  ->  %s\n", prefix, f.Left, f.Right))
		}
	case certlib.DiffAdded:
		if ColorsEnabled {
			sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, DiffAddedColor.Sprint(f.Right), DiffAddedColor.Sprint("(added)")))
		} else {
			sb.WriteString(fmt.Sprintf("%s%s  (added)\n", prefix, f.Right))
		}
	case certlib.DiffRemoved:
		if ColorsEnabled {
			sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, DiffRemovedColor.Sprint(f.Left), DiffRemovedColor.Sprint("(removed)")))
		} else {
			sb.WriteString(fmt.Sprintf("%s%s  (removed)\n", prefix, f.Left))
		}
	}

	return sb.String()
}

func formatDiffSummary(s certlib.DiffSummary, onlyChanges bool) string {
	parts := []string{}
	if s.Changed > 0 {
		p := fmt.Sprintf("%d changed", s.Changed)
		if ColorsEnabled {
			p = DiffChangedColor.Sprint(p)
		}
		parts = append(parts, p)
	}
	if s.Added > 0 {
		p := fmt.Sprintf("%d added", s.Added)
		if ColorsEnabled {
			p = DiffAddedColor.Sprint(p)
		}
		parts = append(parts, p)
	}
	if s.Removed > 0 {
		p := fmt.Sprintf("%d removed", s.Removed)
		if ColorsEnabled {
			p = DiffRemovedColor.Sprint(p)
		}
		parts = append(parts, p)
	}
	if s.Same > 0 && !onlyChanges {
		parts = append(parts, fmt.Sprintf("%d same", s.Same))
	}
	return fmt.Sprintf("\nSummary: %s\n", strings.Join(parts, ", "))
}

type diffOutputJSON struct {
	Left      diffSourceJSON  `json:"left" yaml:"left"`
	Right     diffSourceJSON  `json:"right" yaml:"right"`
	Fields    []diffFieldJSON `json:"fields" yaml:"fields"`
	Summary   diffSummaryJSON `json:"summary" yaml:"summary"`
	Identical bool            `json:"identical" yaml:"identical"`
}

type diffSourceJSON struct {
	FilePath  string `json:"file_path" yaml:"file_path"`
	ItemIndex int    `json:"item_index" yaml:"item_index"`
	Alias     string `json:"alias,omitempty" yaml:"alias,omitempty"`
	Format    string `json:"format,omitempty" yaml:"format,omitempty"`
}

type diffFieldJSON struct {
	Name     string             `json:"name" yaml:"name"`
	Category string             `json:"category" yaml:"category"`
	Left     string             `json:"left" yaml:"left"`
	Right    string             `json:"right" yaml:"right"`
	Status   certlib.DiffStatus `json:"status" yaml:"status"`
	Children []diffChildJSON    `json:"children,omitempty" yaml:"children,omitempty"`
}

type diffChildJSON struct {
	Name   string             `json:"name" yaml:"name"`
	Status certlib.DiffStatus `json:"status" yaml:"status"`
}

type diffSummaryJSON struct {
	Same    int `json:"same" yaml:"same"`
	Changed int `json:"changed" yaml:"changed"`
	Added   int `json:"added" yaml:"added"`
	Removed int `json:"removed" yaml:"removed"`
}

func buildDiffOutputJSON(result certlib.DiffResult, opts DiffOutputOptions) diffOutputJSON {
	out := diffOutputJSON{
		Left: diffSourceJSON{
			FilePath:  result.Left.FilePath,
			ItemIndex: result.Left.ItemIndex,
			Alias:     result.Left.Alias,
			Format:    result.Left.Format,
		},
		Right: diffSourceJSON{
			FilePath:  result.Right.FilePath,
			ItemIndex: result.Right.ItemIndex,
			Alias:     result.Right.Alias,
			Format:    result.Right.Format,
		},
		Summary: diffSummaryJSON{
			Same:    result.Summary.Same,
			Changed: result.Summary.Changed,
			Added:   result.Summary.Added,
			Removed: result.Summary.Removed,
		},
		Identical: result.Identical(),
	}

	for _, f := range result.Fields {
		if opts.OnlyChanges && f.Status == certlib.DiffSame {
			continue
		}
		jf := diffFieldJSON{
			Name:     f.Name,
			Category: f.Category,
			Left:     f.Left,
			Right:    f.Right,
			Status:   f.Status,
		}
		for _, c := range f.Children {
			jf.Children = append(jf.Children, diffChildJSON{
				Name:   c.Name,
				Status: c.Status,
			})
		}
		out.Fields = append(out.Fields, jf)
	}

	return out
}

func FormatDiffJSON(result certlib.DiffResult, opts DiffOutputOptions) string {
	out := buildDiffOutputJSON(result, opts)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(data) + "\n"
}

func FormatDiffYAML(result certlib.DiffResult, opts DiffOutputOptions) string {
	out := buildDiffOutputJSON(result, opts)
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}
