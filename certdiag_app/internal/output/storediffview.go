package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func FormatStoreDiffHuman(result *certops.StoreDiffResult, fpFormat certlib.FingerprintFormat) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s (%s, %d certs)\n", BoldAttr.Sprint("Store A:"),
		result.SideA.Spec, sideLabel(result.SideA), result.SideA.CertCount)
	fmt.Fprintf(&b, "%s %s (%s, %d certs)\n", BoldAttr.Sprint("Store B:"),
		result.SideB.Spec, sideLabel(result.SideB), result.SideB.CertCount)
	b.WriteString("\n")

	if result.Identical {
		fmt.Fprintf(&b, "%s: %d common certificates\n",
			SuccessColor.Sprint("Stores are identical"), result.Common)
		return b.String()
	}

	fmt.Fprintf(&b, "Common: %d   Only in A: %d   Only in B: %d   Rotated: %d\n",
		result.Common, len(result.OnlyInA), len(result.OnlyInB), len(result.Rotated))

	writeDiffSection(&b, "Only in A", result.SideA.Spec, result.OnlyInA, fpFormat)
	writeDiffSection(&b, "Only in B", result.SideB.Spec, result.OnlyInB, fpFormat)

	if len(result.Rotated) > 0 {
		fmt.Fprintf(&b, "\n%s\n", BoldAttr.Sprint("Rotated (same subject, different certificate):"))
		for _, r := range result.Rotated {
			fmt.Fprintf(&b, "  %s\n", r.Subject)
			fmt.Fprintf(&b, "    A: %s\n", strings.Join(shortFPs(r.FingerprintsA, fpFormat), ", "))
			fmt.Fprintf(&b, "    B: %s\n", strings.Join(shortFPs(r.FingerprintsB, fpFormat), ", "))
		}
	}

	return b.String()
}

// writeDiffSection titles a bucket with both the A/B shorthand used in the
// summary line and the spec the user typed, so neither has to be decoded from
// the header.
func writeDiffSection(b *strings.Builder, title, spec string, entries []certops.StoreDiffEntry, fpFormat certlib.FingerprintFormat) {
	if len(entries) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s\n", BoldAttr.Sprint(fmt.Sprintf("%s (%s):", title, spec)))
	for _, e := range entries {
		fmt.Fprintf(b, "  %s\n", e.Subject)
		fmt.Fprintf(b, "    expires %s, sha256 %s\n",
			ColorizeExpiry(e.NotAfter), DimAttr.Sprint(shortFP(e.Fingerprint, fpFormat)))
	}
}

func sideLabel(side certops.StoreDiffSide) string {
	if side.Path != "" && side.Path != side.Name {
		return fmt.Sprintf("%s, %s", side.Name, side.Path)
	}
	return side.Name
}

// shortFPBytes is how much of the digest the human view shows, in bytes. The
// prefix is truncated before formatting so hex-colon and base64 stay valid
// renderings of the same leading bytes rather than a cut-up string.
const shortFPBytes = 8

func shortFP(canonicalHex string, fpFormat certlib.FingerprintFormat) string {
	if len(canonicalHex) <= shortFPBytes*2 {
		return certlib.ReformatFingerprint(canonicalHex, fpFormat)
	}
	return certlib.ReformatFingerprint(canonicalHex[:shortFPBytes*2], fpFormat) + "..."
}

func shortFPs(fps []string, fpFormat certlib.FingerprintFormat) []string {
	out := make([]string, len(fps))
	for i, fp := range fps {
		out[i] = shortFP(fp, fpFormat)
	}
	return out
}

type storeDiffJSON struct {
	SideA     storeDiffSideJSON     `json:"side_a" yaml:"side_a"`
	SideB     storeDiffSideJSON     `json:"side_b" yaml:"side_b"`
	Common    int                   `json:"common" yaml:"common"`
	OnlyInA   []storeDiffEntryJSON  `json:"only_in_a" yaml:"only_in_a"`
	OnlyInB   []storeDiffEntryJSON  `json:"only_in_b" yaml:"only_in_b"`
	Rotated   []storeDiffRotateJSON `json:"rotated" yaml:"rotated"`
	Identical bool                  `json:"identical" yaml:"identical"`
	Warnings  []string              `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

type storeDiffSideJSON struct {
	Spec      string `json:"spec" yaml:"spec"`
	Name      string `json:"name" yaml:"name"`
	Path      string `json:"path,omitempty" yaml:"path,omitempty"`
	CertCount int    `json:"cert_count" yaml:"cert_count"`
}

type storeDiffEntryJSON struct {
	Subject     string `json:"subject" yaml:"subject"`
	Fingerprint string `json:"sha256" yaml:"sha256"`
	NotAfter    string `json:"not_after" yaml:"not_after"`
}

type storeDiffRotateJSON struct {
	Subject       string   `json:"subject" yaml:"subject"`
	FingerprintsA []string `json:"sha256_a" yaml:"sha256_a"`
	FingerprintsB []string `json:"sha256_b" yaml:"sha256_b"`
}

func buildStoreDiffJSON(result *certops.StoreDiffResult) storeDiffJSON {
	out := storeDiffJSON{
		SideA:     storeDiffSideJSON{Spec: result.SideA.Spec, Name: result.SideA.Name, Path: result.SideA.Path, CertCount: result.SideA.CertCount},
		SideB:     storeDiffSideJSON{Spec: result.SideB.Spec, Name: result.SideB.Name, Path: result.SideB.Path, CertCount: result.SideB.CertCount},
		Common:    result.Common,
		OnlyInA:   make([]storeDiffEntryJSON, 0, len(result.OnlyInA)),
		OnlyInB:   make([]storeDiffEntryJSON, 0, len(result.OnlyInB)),
		Rotated:   make([]storeDiffRotateJSON, 0, len(result.Rotated)),
		Identical: result.Identical,
		Warnings:  result.Warnings,
	}
	for _, e := range result.OnlyInA {
		out.OnlyInA = append(out.OnlyInA, entryJSON(e))
	}
	for _, e := range result.OnlyInB {
		out.OnlyInB = append(out.OnlyInB, entryJSON(e))
	}
	for _, r := range result.Rotated {
		out.Rotated = append(out.Rotated, storeDiffRotateJSON{Subject: r.Subject, FingerprintsA: r.FingerprintsA, FingerprintsB: r.FingerprintsB})
	}
	return out
}

func entryJSON(e certops.StoreDiffEntry) storeDiffEntryJSON {
	return storeDiffEntryJSON{
		Subject:     e.Subject,
		Fingerprint: e.Fingerprint,
		NotAfter:    e.NotAfter.Format(time.RFC3339),
	}
}

func FormatStoreDiffJSON(result *certops.StoreDiffResult) string {
	data, err := json.MarshalIndent(buildStoreDiffJSON(result), "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(data) + "\n"
}

func FormatStoreDiffYAML(result *certops.StoreDiffResult) string {
	data, err := yaml.Marshal(buildStoreDiffJSON(result))
	if err != nil {
		return fmt.Sprintf("error: %q\n", err.Error())
	}
	return string(data)
}
