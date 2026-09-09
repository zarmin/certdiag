package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

func (m RootModel) viewTrustVerify() string {
	info, infoBarHeight := RenderHintBar(m.width, m.trustVerifyHints())

	var sb strings.Builder
	sb.WriteString(styleModalTitle.Render(" Verify Against Trust Store"))
	sb.WriteString("\n")
	sb.WriteString(styleSeparator.Render(" " + strings.Repeat("─", max(m.width-2, 4))))
	sb.WriteString("\n")

	if m.trustVerify == nil {
		sb.WriteString(styleDimRow.Render("  No result"))
		sb.WriteString("\n")
		return sb.String() + info
	}

	vr := m.trustVerify
	lines := 3

	if m.trustVerifyPath != "" {
		sb.WriteString(fmt.Sprintf("  Certificate:  %s\n", filepath.Base(m.trustVerifyPath)))
		lines++
	}
	sb.WriteString(fmt.Sprintf("  Store:        %s\n", vr.Store.Name))
	lines++
	// A store whose scope is narrower than its name suggests (an NSS profile
	// holds only what was added to it) must say so here, or an untrusted
	// verdict reads as a fact about the browser.
	for _, w := range vr.Store.Warnings {
		sb.WriteString(styleDimRow.Render(fmt.Sprintf("                %s", w)))
		sb.WriteString("\n")
		lines++
	}
	sb.WriteString("\n")
	lines++

	if vr.Trusted {
		sb.WriteString("  Result:       " + lipgloss.NewStyle().Foreground(colorGreen).Render("TRUSTED") + "\n")
	} else {
		sb.WriteString("  Result:       " + styleError.Render("NOT TRUSTED") + "\n")
	}
	lines++

	if len(vr.Chain) > 0 {
		sb.WriteString("\n  Chain (issuance order):\n")
		lines += 2
		// Root first: the project renders chains as "who signed whom".
		for i := len(vr.Chain) - 1; i >= 0; i-- {
			cert := vr.Chain[i]
			indent := strings.Repeat("  ", len(vr.Chain)-1-i)
			label := "Intermediate"
			if i == len(vr.Chain)-1 {
				label = "Root"
			}
			if i == 0 {
				label = "Leaf"
			}
			prefix := ""
			if i < len(vr.Chain)-1 {
				prefix = "-> "
			}
			sb.WriteString(fmt.Sprintf("    %s%s[%s]  %s\n", indent, prefix, label, output.FormatSubject(cert)))
			lines++
		}
	}

	if vr.Trusted && vr.TrustAnchor != nil {
		sb.WriteString(fmt.Sprintf("\n  Trust anchor: %s\n", output.FormatSubject(vr.TrustAnchor)))
		lines += 2
	}

	if !vr.Trusted && vr.Reason != "" {
		sb.WriteString(fmt.Sprintf("\n  Reason:       %s\n", vr.Reason))
		lines += 2
	}

	if len(vr.Suggestions) > 0 {
		sb.WriteString("\n  Suggestions:\n")
		lines += 2
		for _, s := range vr.Suggestions {
			sb.WriteString(fmt.Sprintf("    - %s\n", s))
			lines++
		}
	}

	for lines < m.height-infoBarHeight {
		sb.WriteString("\n")
		lines++
	}

	return sb.String() + info
}

func (m RootModel) trustVerifyHints() []Hint {
	hints := []Hint{{"?", "Help"}, {"Esc/q", "Back"}}
	if m.trustVerifyRemote && m.remoteHasResult {
		hints = append([]Hint{{"Enter", "Open remote result"}}, hints...)
	}
	return hints
}
