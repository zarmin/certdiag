package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func FormatVerifyHuman(vr truststore.VerifyResult) string {
	var sb strings.Builder

	if vr.Trusted {
		sb.WriteString(fmt.Sprintf("Verification: %s\n", SuccessColor.Sprint("TRUSTED")))
	} else {
		sb.WriteString(fmt.Sprintf("Verification: %s\n", ExpiredColor.Sprint("NOT TRUSTED")))
	}

	sb.WriteString("\n")

	if len(vr.Chain) > 0 {
		sb.WriteString("  Chain:\n")
		for i := len(vr.Chain) - 1; i >= 0; i-- {
			cert := vr.Chain[i]
			indent := strings.Repeat("  ", len(vr.Chain)-1-i)
			label := "Intermediate"
			if i == 0 {
				label = "Leaf"
			}
			if i == len(vr.Chain)-1 {
				label = "Root"
			}
			if len(vr.Chain) == 1 {
				label = "Leaf"
			}

			prefix := ""
			if i < len(vr.Chain)-1 {
				prefix = "-> "
			}

			sb.WriteString(fmt.Sprintf("    %s%s[%s]  %s\n",
				indent, prefix, label, FormatSubject(cert)))
		}
		sb.WriteString("\n")
	}

	if vr.Trusted {
		if vr.TrustAnchor != nil {
			sb.WriteString(fmt.Sprintf("  Trust anchor:  %s\n", FormatSubject(vr.TrustAnchor)))
		}
		sb.WriteString(fmt.Sprintf("  Trust store:   %s", vr.Store.Name))
		if vr.Store.CertCount > 0 {
			sb.WriteString(fmt.Sprintf(" (%d CAs)", vr.Store.CertCount))
		}
		sb.WriteString("\n")
		if vr.Store.Path != "" {
			sb.WriteString(fmt.Sprintf("  Store path:    %s\n", vr.Store.Path))
		}
	} else {
		sb.WriteString(fmt.Sprintf("  Reason:        %s\n", vr.Reason))
		sb.WriteString(fmt.Sprintf("  Trust store:   %s\n", vr.Store.Name))

		if len(vr.Suggestions) > 0 {
			sb.WriteString("\n  Suggestions:\n")
			for _, s := range vr.Suggestions {
				sb.WriteString(fmt.Sprintf("    - %s\n", s))
			}
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

type verifyJSON struct {
	Trusted     bool         `json:"trusted"`
	Hostname    string       `json:"hostname,omitempty"`
	Chain       []chainEntry `json:"chain,omitempty"`
	TrustAnchor string       `json:"trust_anchor,omitempty"`
	Reason      string       `json:"reason,omitempty"`
	Suggestions []string     `json:"suggestions,omitempty"`
	Store       storeRef     `json:"store"`
}

type chainEntry struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"not_after"`
	Role     string `json:"role"`
}

type storeRef struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	CertCount int    `json:"cert_count,omitempty"`
}

func FormatVerifyJSON(vr truststore.VerifyResult) (string, error) {
	out := verifyJSON{
		Trusted:  vr.Trusted,
		Hostname: vr.Hostname,
		Store: storeRef{
			Type:      string(vr.Store.Type),
			Name:      vr.Store.Name,
			Path:      vr.Store.Path,
			CertCount: vr.Store.CertCount,
		},
	}

	if !vr.Trusted {
		out.Reason = vr.Reason
		out.Suggestions = vr.Suggestions
	}

	if vr.TrustAnchor != nil {
		out.TrustAnchor = FormatSubject(vr.TrustAnchor)
	}

	for i, cert := range vr.Chain {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		}
		if i == len(vr.Chain)-1 {
			role = "root"
		}
		if len(vr.Chain) == 1 {
			role = "leaf"
		}

		out.Chain = append(out.Chain, chainEntry{
			Subject:  FormatSubject(cert),
			Issuer:   FormatIssuer(cert),
			NotAfter: cert.NotAfter.Format(time.RFC3339),
			Role:     role,
		})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func FormatVerifyYAML(vr truststore.VerifyResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("trusted: %v\n", vr.Trusted))
	if vr.Hostname != "" {
		sb.WriteString(fmt.Sprintf("hostname: %q\n", vr.Hostname))
	}

	if !vr.Trusted {
		sb.WriteString(fmt.Sprintf("reason: %q\n", vr.Reason))
	}

	if vr.TrustAnchor != nil {
		sb.WriteString(fmt.Sprintf("trust_anchor: %q\n", FormatSubject(vr.TrustAnchor)))
	}

	sb.WriteString(fmt.Sprintf("store:\n"))
	sb.WriteString(fmt.Sprintf("  type: %q\n", vr.Store.Type))
	sb.WriteString(fmt.Sprintf("  name: %q\n", vr.Store.Name))
	if vr.Store.Path != "" {
		sb.WriteString(fmt.Sprintf("  path: %q\n", vr.Store.Path))
	}

	if len(vr.Chain) > 0 {
		sb.WriteString("chain:\n")
		for _, cert := range vr.Chain {
			sb.WriteString(fmt.Sprintf("  - subject: %q\n", FormatSubject(cert)))
			sb.WriteString(fmt.Sprintf("    issuer: %q\n", FormatIssuer(cert)))
			sb.WriteString(fmt.Sprintf("    not_after: %q\n", cert.NotAfter.Format(time.RFC3339)))
		}
	}

	if len(vr.Suggestions) > 0 {
		sb.WriteString("suggestions:\n")
		for _, s := range vr.Suggestions {
			sb.WriteString(fmt.Sprintf("  - %q\n", s))
		}
	}

	return sb.String()
}
