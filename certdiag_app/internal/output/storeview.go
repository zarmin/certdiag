package output

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"gopkg.in/yaml.v3"
)

type CertCategory string

const (
	CategoryRootCA         CertCategory = "Root CA"
	CategoryIntermediateCA CertCategory = "Intermediate CA"
	CategoryServer         CertCategory = "Server"
	CategoryClient         CertCategory = "Client"
	CategoryCodeSigning    CertCategory = "Code Signing"
	CategoryLeaf           CertCategory = "Leaf"
)

var categoryOrder = []CertCategory{
	CategoryRootCA,
	CategoryIntermediateCA,
	CategoryServer,
	CategoryClient,
	CategoryCodeSigning,
	CategoryLeaf,
}

func ClassifyCert(cert *x509.Certificate) CertCategory {
	if cert.IsCA {
		if certlib.IsSelfSigned(cert) {
			return CategoryRootCA
		}
		return CategoryIntermediateCA
	}

	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return CategoryServer
		}
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return CategoryClient
		}
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			return CategoryCodeSigning
		}
	}

	return CategoryLeaf
}

func FormatStoreList(stores []truststore.StoreContents, details bool, query string) string {
	return FormatStoreListFormat(stores, details, query, certlib.FingerprintHex)
}

// FormatStoreListFormat renders a store listing with an explicit fingerprint
// display format.
func FormatStoreListFormat(stores []truststore.StoreContents, details bool, query string, fpFormat certlib.FingerprintFormat) string {
	var sb strings.Builder

	for si, store := range stores {
		if si > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("%s  [%s]  %d certs\n",
			BoldAttr.Sprint(store.Info.Name),
			store.Info.Path,
			len(store.Certificates)))

		for _, w := range store.Info.Warnings {
			sb.WriteString(fmt.Sprintf("  %s %s\n", ColorizeWarning("[!]"), w))
		}

		grouped := groupByCategory(store.Certificates)
		for _, cat := range categoryOrder {
			certs := grouped[cat]
			if len(certs) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("\n  %s (%d):\n", BoldAttr.Sprint(string(cat)), len(certs)))
			for _, cert := range certs {
				sb.WriteString(formatStoreCert(cert, &store, details, fpFormat))
			}
		}
	}

	return sb.String()
}

func groupByCategory(certs []*x509.Certificate) map[CertCategory][]*x509.Certificate {
	groups := make(map[CertCategory][]*x509.Certificate)
	for _, cert := range certs {
		cat := ClassifyCert(cert)
		groups[cat] = append(groups[cat], cert)
	}
	return groups
}

func formatStoreCert(cert *x509.Certificate, store *truststore.StoreContents, details bool, fpFormat certlib.FingerprintFormat) string {
	var sb strings.Builder

	subject := FormatSubject(cert)
	issuer := FormatIssuer(cert)
	algo := FormatKeyAlgo(cert.PublicKey)
	expiry := cert.NotAfter
	trust := store.GetTrust(cert)

	coloredSubject := colorizeByExpiry(subject, expiry)
	trustBadge := formatTrustBadge(trust)

	if trustBadge != "" {
		sb.WriteString(fmt.Sprintf("  %s  %s\n", coloredSubject, trustBadge))
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", coloredSubject))
	}

	if !certlib.IsSelfSigned(cert) {
		sb.WriteString(fmt.Sprintf("    Issuer:  %s\n", issuer))
	}
	sb.WriteString(fmt.Sprintf("    Algo:    %s\n", algo))
	sb.WriteString(fmt.Sprintf("    Expires: %s\n", ColorizeExpiry(expiry)))

	if len(trust.Policies) > 0 {
		sb.WriteString(fmt.Sprintf("    Trust:   %s\n", formatTrustPolicies(trust.Policies)))
	}

	if details {
		sb.WriteString(fmt.Sprintf("    Serial:  %s\n", cert.SerialNumber.Text(16)))
		sb.WriteString(fmt.Sprintf("    Valid:   %s - %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02")))
		if len(cert.Subject.Organization) > 0 {
			sb.WriteString(fmt.Sprintf("    Org:     %s\n", strings.Join(cert.Subject.Organization, ", ")))
		}
		for _, algo := range certlib.FingerprintAlgos {
			sb.WriteString(fmt.Sprintf("    %-8s %s\n", algo.Label()+":",
				certlib.CertFingerprint(cert, algo, fpFormat)))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

func formatTrustBadge(trust truststore.CertTrust) string {
	switch trust.Overall {
	case truststore.TrustTrusted:
		purposes := trustedPurposes(trust.Policies)
		if len(purposes) > 0 && len(purposes) < len(trust.Policies) {
			badge := fmt.Sprintf("[Trusted: %s]", strings.Join(purposes, ", "))
			if ColorsEnabled {
				return SuccessColor.Sprint(badge)
			}
			return badge
		}
		badge := "[Trusted]"
		if ColorsEnabled {
			return SuccessColor.Sprint(badge)
		}
		return badge
	case truststore.TrustDenied:
		badge := "[Denied]"
		if ColorsEnabled {
			return ExpiredColor.Sprint(badge)
		}
		return badge
	default:
		return ""
	}
}

func trustedPurposes(policies []truststore.TrustPolicy) []string {
	var purposes []string
	for _, p := range policies {
		if p.Status == truststore.TrustTrusted {
			purposes = append(purposes, p.Purpose)
		}
	}
	return purposes
}

func formatTrustPolicies(policies []truststore.TrustPolicy) string {
	var parts []string
	for _, p := range policies {
		parts = append(parts, fmt.Sprintf("%s: %s", p.Purpose, strings.ToLower(string(p.Status))))
	}
	return strings.Join(parts, ", ")
}

func colorizeByExpiry(text string, expiry time.Time) string {
	if !ColorsEnabled {
		return text
	}
	now := time.Now()
	if expiry.Before(now) {
		return ExpiredColor.Sprint(text)
	}
	if expiry.Before(now.Add(time.Duration(certlib.DefaultExpiryWarnDays) * 24 * time.Hour)) {
		return WarningColor.Sprint(text)
	}
	return ExpiringOK.Sprint(text)
}

func FormatStoreTable(stores []truststore.StoreContents) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%-18s %-36s %-26s %-12s %-12s\n",
		"Category", "Subject", "Issuer", "Algorithm", "Expires"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")

	for _, store := range stores {
		for _, cert := range store.Certificates {
			cat := string(ClassifyCert(cert))
			subject := truncate(FormatSubject(cert), 34)
			issuer := truncate(FormatIssuer(cert), 24)
			algo := FormatKeyAlgo(cert.PublicKey)
			expiry := cert.NotAfter.Format("2006-01-02")

			sb.WriteString(fmt.Sprintf("%-18s %-36s %-26s %-12s %-12s\n",
				cat, subject, issuer, algo, expiry))
		}
	}

	return sb.String()
}

// storeJSONEntry is the shared certificate shape (the same fields, names and
// fingerprints as the scan and remote outputs, so store rows can be joined
// with them) plus what only a trust store knows.
type storeJSONEntry struct {
	*StructuredCertificate `yaml:",inline"`
	Category               string            `json:"category" yaml:"category"`
	TrustStatus            string            `json:"trust_status" yaml:"trust_status"`
	TrustPolicies          []jsonTrustPolicy `json:"trust_policies,omitempty" yaml:"trust_policies,omitempty"`
	Store                  string            `json:"store" yaml:"store"`
	StorePath              string            `json:"store_path" yaml:"store_path"`
}

type jsonTrustPolicy struct {
	Purpose string `json:"purpose" yaml:"purpose"`
	Status  string `json:"status" yaml:"status"`
}

func storeEntries(stores []truststore.StoreContents) []storeJSONEntry {
	entries := []storeJSONEntry{}
	for _, store := range stores {
		for _, cert := range store.Certificates {
			trust := store.GetTrust(cert)
			var policies []jsonTrustPolicy
			for _, p := range trust.Policies {
				policies = append(policies, jsonTrustPolicy{Purpose: p.Purpose, Status: string(p.Status)})
			}
			item := certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw}
			entries = append(entries, storeJSONEntry{
				StructuredCertificate: BuildStructuredCert(&item),
				Category:              string(ClassifyCert(cert)),
				TrustStatus:           string(trust.Overall),
				TrustPolicies:         policies,
				Store:                 store.Info.Name,
				StorePath:             store.Info.Path,
			})
		}
	}
	return entries
}

func FormatStoreJSON(stores []truststore.StoreContents) (string, error) {
	data, err := json.MarshalIndent(storeEntries(stores), "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func FormatStoreYAML(stores []truststore.StoreContents) string {
	data, err := yaml.Marshal(storeEntries(stores))
	if err != nil {
		return ""
	}
	return string(data)
}

func FormatDiscoverList(stores []truststore.StoreInfo) string {
	var sb strings.Builder
	sb.WriteString("Trust Stores Found:\n\n")

	if len(stores) == 0 {
		sb.WriteString("  (none detected)\n")
		return sb.String()
	}

	for _, s := range stores {
		line := fmt.Sprintf("  %-25s %-60s %d certs", s.Name, s.Path, s.CertCount)
		for _, w := range s.Warnings {
			line += fmt.Sprintf("  %s %s", ColorizeWarning("[!]"), w)
		}
		sb.WriteString(line + "\n")
	}

	return sb.String()
}

func FormatDiscoverJSON(stores []truststore.StoreInfo) (string, error) {
	type entry struct {
		Type      string   `json:"type"`
		Name      string   `json:"name"`
		Path      string   `json:"path"`
		CertCount int      `json:"cert_count"`
		Warnings  []string `json:"warnings,omitempty"`
	}
	var entries []entry
	for _, s := range stores {
		entries = append(entries, entry{
			Type:      string(s.Type),
			Name:      s.Name,
			Path:      s.Path,
			CertCount: s.CertCount,
			Warnings:  s.Warnings,
		})
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func FormatDiscoverYAML(stores []truststore.StoreInfo) string {
	var sb strings.Builder
	for _, s := range stores {
		sb.WriteString(fmt.Sprintf("- type: %q\n", s.Type))
		sb.WriteString(fmt.Sprintf("  name: %q\n", s.Name))
		sb.WriteString(fmt.Sprintf("  path: %q\n", s.Path))
		sb.WriteString(fmt.Sprintf("  cert_count: %d\n", s.CertCount))
		if len(s.Warnings) > 0 {
			sb.WriteString("  warnings:\n")
			for _, w := range s.Warnings {
				sb.WriteString(fmt.Sprintf("    - %q\n", w))
			}
		}
	}
	return sb.String()
}

func truncate(s string, max int) string {
	const ellipsis = "..."
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= len(ellipsis) {
		if max <= 0 {
			return ""
		}
		return string(runes[:max])
	}
	return string(runes[:max-len(ellipsis)]) + ellipsis
}
