package output

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func FormatProbeHuman(result *certops.ProbeRemoteResult) string {
	var b strings.Builder

	if result.Error != "" {
		fmt.Fprintf(&b, "%s -- Error: %s\n", result.Target, result.Error)
		return b.String()
	}

	probe := result.Probe
	if probe.ResolvedAddr != "" {
		fmt.Fprintf(&b, "%s (%s) -- TLS Probe Results\n", result.Target, probe.ResolvedAddr)
	} else {
		fmt.Fprintf(&b, "%s -- TLS Probe Results\n", result.Target)
	}
	b.WriteString(strings.Repeat("=", 40))
	b.WriteString("\n\n")

	// TLS Versions
	b.WriteString("TLS Versions:\n")
	for _, v := range probe.Versions {
		status := "not supported"
		if v.Supported {
			status = fmt.Sprintf("supported    (negotiated: %s)", v.CipherSuite)
		}
		fmt.Fprintf(&b, "  %-12s %s\n", v.VersionName, status)
	}
	b.WriteString("\n")

	// Cipher Suites grouped by TLS version
	ciphersByVersion := make(map[string][]certlib.ProbeCipherResult)
	for _, cs := range probe.CipherSuites {
		ciphersByVersion[cs.TLSVersion] = append(ciphersByVersion[cs.TLSVersion], cs)
	}

	for _, vr := range probe.Versions {
		if !vr.Supported {
			continue
		}
		ciphers, ok := ciphersByVersion[vr.VersionName]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "Cipher Suites (%s):\n", vr.VersionName)
		for _, cs := range ciphers {
			if !cs.Supported {
				continue
			}
			classification := certlib.ClassifyCipher(cs.CipherSuiteName)
			label := colorCipherClass(classification)
			fmt.Fprintf(&b, "  %-50s supported    %s\n", cs.CipherSuiteName, label)
		}
		b.WriteString("\n")
	}

	// Features
	b.WriteString("Features:\n")
	if len(probe.ALPNProtocols) > 0 {
		fmt.Fprintf(&b, "  ALPN:                    %s\n", strings.Join(probe.ALPNProtocols, ", "))
	} else {
		b.WriteString("  ALPN:                    none\n")
	}

	ocsp := "no"
	if probe.OCSPStapled {
		ocsp = "yes"
	}
	fmt.Fprintf(&b, "  OCSP Stapling:           %s\n", ocsp)

	fmt.Fprintf(&b, "  Secure Renegotiation:    %s\n", renegotiationText(probe))
	fmt.Fprintf(&b, "  TLS Compression:         %s\n", compressionText(probe))

	fmt.Fprintf(&b, "  Cipher Preference:       %s\n", probe.CipherPreference)
	b.WriteString("\n")

	fmt.Fprintf(&b, "Probe completed in %.1fs\n", probe.Duration.Seconds())

	return b.String()
}

func colorCipherClass(class certlib.CipherClassification) string {
	label := fmt.Sprintf("[%s]", class)
	if !ColorsEnabled {
		return label
	}
	switch class {
	case certlib.CipherInsecure:
		return CriticalColor.Sprint(label)
	case certlib.CipherWeak:
		return WarningColor.Sprint(label)
	case certlib.CipherRecommended:
		return fmt.Sprintf("[%s]", class) // green handled by caller if needed
	default:
		return label
	}
}

type probeJSONOutput struct {
	Target           string             `json:"target" yaml:"target"`
	ResolvedAddr     string             `json:"resolved_addr,omitempty" yaml:"resolved_addr,omitempty"`
	Versions         []probeJSONVersion `json:"versions" yaml:"versions"`
	CipherSuites     []probeJSONCipher  `json:"cipher_suites" yaml:"cipher_suites"`
	Features         probeJSONFeatures  `json:"features" yaml:"features"`
	CipherPreference string             `json:"cipher_preference" yaml:"cipher_preference"`
	DurationMs       int64              `json:"duration_ms" yaml:"duration_ms"`
	Error            string             `json:"error,omitempty" yaml:"error,omitempty"`
}

type probeJSONVersion struct {
	Version     string `json:"version" yaml:"version"`
	Supported   bool   `json:"supported" yaml:"supported"`
	CipherSuite string `json:"cipher_suite,omitempty" yaml:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty" yaml:"error,omitempty"`
}

type probeJSONCipher struct {
	Name           string `json:"name" yaml:"name"`
	TLSVersion     string `json:"tls_version" yaml:"tls_version"`
	Supported      bool   `json:"supported" yaml:"supported"`
	Classification string `json:"classification" yaml:"classification"`
}

type probeJSONFeatures struct {
	ALPN        []string `json:"alpn" yaml:"alpn"`
	OCSPStapled bool     `json:"ocsp_stapled" yaml:"ocsp_stapled"`
	// null when the feature connection did not complete (nothing measured);
	// secure_renegotiation is also null on TLS 1.3, which has no renegotiation
	SecureRenegotiation *bool  `json:"secure_renegotiation" yaml:"secure_renegotiation"`
	Compression         *bool  `json:"compression" yaml:"compression"`
	FeaturesTLSVersion  string `json:"features_tls_version,omitempty" yaml:"features_tls_version,omitempty"`
}

func renegotiationText(probe *certlib.ProbeResult) string {
	switch {
	case probe.SecureRenegotiation != nil && *probe.SecureRenegotiation:
		return "yes"
	case probe.SecureRenegotiation != nil:
		return "no (server did not send renegotiation_info)"
	case probe.FeaturesTLSVersion == tls.VersionTLS13:
		return "not applicable (TLS 1.3 has no renegotiation)"
	}
	return "not probed"
}

func compressionText(probe *certlib.ProbeResult) string {
	switch {
	case probe.Compression != nil && *probe.Compression:
		return "yes (CRIME vulnerability!)"
	case probe.Compression != nil:
		return "no"
	}
	return "not probed"
}

func buildProbeStructured(result *certops.ProbeRemoteResult) probeJSONOutput {
	out := probeJSONOutput{
		Target: result.Target,
		Error:  result.Error,
	}

	if result.Probe == nil {
		return out
	}

	probe := result.Probe
	out.ResolvedAddr = probe.ResolvedAddr
	out.DurationMs = probe.Duration.Milliseconds()
	out.CipherPreference = probe.CipherPreference

	for _, v := range probe.Versions {
		out.Versions = append(out.Versions, probeJSONVersion{
			Version:     v.VersionName,
			Supported:   v.Supported,
			CipherSuite: v.CipherSuite,
			Error:       v.Error,
		})
	}

	for _, cs := range probe.CipherSuites {
		out.CipherSuites = append(out.CipherSuites, probeJSONCipher{
			Name:           cs.CipherSuiteName,
			TLSVersion:     cs.TLSVersion,
			Supported:      cs.Supported,
			Classification: string(certlib.ClassifyCipher(cs.CipherSuiteName)),
		})
	}

	out.Features = probeJSONFeatures{
		ALPN:                probe.ALPNProtocols,
		OCSPStapled:         probe.OCSPStapled,
		SecureRenegotiation: probe.SecureRenegotiation,
		Compression:         probe.Compression,
	}
	if probe.FeaturesTLSVersion != 0 {
		out.Features.FeaturesTLSVersion = certlib.TLSVersionName(probe.FeaturesTLSVersion)
	}

	if out.Features.ALPN == nil {
		out.Features.ALPN = []string{}
	}
	if out.Versions == nil {
		out.Versions = []probeJSONVersion{}
	}
	if out.CipherSuites == nil {
		out.CipherSuites = []probeJSONCipher{}
	}

	return out
}

func FormatProbeJSON(result *certops.ProbeRemoteResult) string {
	out := buildProbeStructured(result)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(data) + "\n"
}

func FormatProbeYAML(result *certops.ProbeRemoteResult) string {
	out := buildProbeStructured(result)
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}
