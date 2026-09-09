//go:build darwin

package truststore

import (
	"crypto/x509"
	"os/exec"
	"strings"
)

func LoadTrustSettings(certs []*x509.Certificate) map[string]CertTrust {
	trustMap := make(map[string]CertTrust)

	subjectToFP := buildSubjectIndex(certs)

	for _, domain := range []string{"", "-s", "-d"} {
		settings := parseTrustDomain(domain)
		for subject, trust := range settings {
			fps := subjectToFP[subject]
			for _, fp := range fps {
				if _, exists := trustMap[fp]; !exists {
					trustMap[fp] = trust
				}
			}
		}
	}

	return trustMap
}

func buildSubjectIndex(certs []*x509.Certificate) map[string][]string {
	idx := make(map[string][]string)
	for _, cert := range certs {
		cn := cert.Subject.CommonName
		if cn == "" {
			cn = cert.Subject.String()
		}
		fp := CertFingerprint(cert)
		idx[cn] = append(idx[cn], fp)
	}
	return idx
}

func parseTrustDomain(domainFlag string) map[string]CertTrust {
	args := []string{"dump-trust-settings"}
	if domainFlag != "" {
		args = append(args, domainFlag)
	}

	out, err := exec.Command("security", args...).Output()
	if err != nil {
		return nil
	}

	return parseTrustOutput(string(out))
}

func parseTrustOutput(output string) map[string]CertTrust {
	result := make(map[string]CertTrust)
	lines := strings.Split(output, "\n")

	var currentSubject string
	var currentPolicies []TrustPolicy
	var settingCount int
	var currentPolicy string
	var currentResult string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "Cert ") && strings.Contains(trimmed, ": ") {
			if currentSubject != "" {
				// Flush the pending policy/result pair of the previous cert before
				// building its trust; otherwise the last (or only) policy of every
				// non-final cert is dropped (e.g. a single Deny reported as Unset).
				if currentPolicy != "" && currentResult != "" {
					currentPolicies = append(currentPolicies, TrustPolicy{
						Purpose: currentPolicy,
						Status:  mapResultType(currentResult),
					})
				}
				result[currentSubject] = buildCertTrust(currentPolicies, settingCount)
			}
			idx := strings.Index(trimmed, ": ")
			currentSubject = trimmed[idx+2:]
			currentPolicies = nil
			currentPolicy = ""
			currentResult = ""
			settingCount = -1
			continue
		}

		if strings.HasPrefix(trimmed, "Number of trust settings : ") {
			val := strings.TrimPrefix(trimmed, "Number of trust settings : ")
			n := 0
			for _, c := range val {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				}
			}
			settingCount = n
			continue
		}

		if strings.HasPrefix(trimmed, "Policy OID") && strings.Contains(trimmed, ": ") {
			if currentPolicy != "" && currentResult != "" {
				currentPolicies = append(currentPolicies, TrustPolicy{
					Purpose: currentPolicy,
					Status:  mapResultType(currentResult),
				})
			}
			idx := strings.Index(trimmed, ": ")
			currentPolicy = normalizePolicyName(strings.TrimSpace(trimmed[idx+2:]))
			currentResult = ""
			continue
		}

		if strings.HasPrefix(trimmed, "Result Type") && strings.Contains(trimmed, ": ") {
			idx := strings.Index(trimmed, ": ")
			currentResult = strings.TrimSpace(trimmed[idx+2:])
			continue
		}
	}

	if currentSubject != "" {
		if currentPolicy != "" && currentResult != "" {
			currentPolicies = append(currentPolicies, TrustPolicy{
				Purpose: currentPolicy,
				Status:  mapResultType(currentResult),
			})
		}
		result[currentSubject] = buildCertTrust(currentPolicies, settingCount)
	}

	return result
}

var appleOIDNames = map[string]string{
	"2A 86 48 86 F7 63 64 01 02": "Apple X509 Basic",
	"2A 86 48 86 F7 63 64 01 03": "SSL",
	"2A 86 48 86 F7 63 64 01 08": "SMIME",
	"2A 86 48 86 F7 63 64 01 0B": "EAP",
	"2A 86 48 86 F7 63 64 01 0C": "Code Signing",
	"2A 86 48 86 F7 63 64 01 0E": "IPSec",
	"2A 86 48 86 F7 63 64 01 10": "iChat",
	"2A 86 48 86 F7 63 64 01 12": "Time Stamping",
	"2A 86 48 86 F7 63 64 01 14": "Time Stamping",
	"2A 86 48 86 F7 63 64 01 16": "Provisioning Profile",
}

func normalizePolicyName(raw string) string {
	if strings.HasPrefix(raw, "Unknown OID") {
		start := strings.Index(raw, "{ ")
		end := strings.Index(raw, " }")
		if start != -1 && end != -1 {
			hexBytes := strings.TrimSpace(raw[start+2 : end])
			if name, ok := appleOIDNames[hexBytes]; ok {
				return name
			}
		}
	}
	return raw
}

func mapResultType(result string) TrustStatus {
	switch result {
	case "kSecTrustSettingsResultTrustRoot", "kSecTrustSettingsResultTrustAsRoot":
		return TrustTrusted
	case "kSecTrustSettingsResultDeny":
		return TrustDenied
	default:
		return TrustUnset
	}
}

func buildCertTrust(policies []TrustPolicy, settingCount int) CertTrust {
	if settingCount == 0 {
		return CertTrust{Overall: TrustTrusted}
	}

	if len(policies) == 0 {
		return CertTrust{Overall: TrustUnset}
	}

	dedupPolicies := deduplicatePolicies(policies)

	hasTrusted := false
	hasDenied := false
	for _, p := range dedupPolicies {
		if p.Status == TrustTrusted {
			hasTrusted = true
		}
		if p.Status == TrustDenied {
			hasDenied = true
		}
	}

	overall := TrustUnset
	if hasDenied && !hasTrusted {
		overall = TrustDenied
	} else if hasTrusted && !hasDenied {
		overall = TrustTrusted
	} else if hasTrusted && hasDenied {
		overall = TrustTrusted
	}

	return CertTrust{
		Overall:  overall,
		Policies: dedupPolicies,
	}
}

func deduplicatePolicies(policies []TrustPolicy) []TrustPolicy {
	best := make(map[string]TrustStatus)
	order := []string{}

	for _, p := range policies {
		existing, ok := best[p.Purpose]
		if !ok {
			order = append(order, p.Purpose)
			best[p.Purpose] = p.Status
		} else if p.Status == TrustDenied {
			best[p.Purpose] = TrustDenied
		} else if existing == TrustUnset && p.Status == TrustTrusted {
			best[p.Purpose] = TrustTrusted
		}
	}

	var result []TrustPolicy
	for _, purpose := range order {
		result = append(result, TrustPolicy{
			Purpose: purpose,
			Status:  best[purpose],
		})
	}
	return result
}
