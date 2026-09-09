package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func FormatRemoteHuman(result *certops.FetchRemoteCertResult, details ...bool) string {
	level := 0
	if len(details) > 0 && details[0] {
		level = 1
	}
	return FormatRemoteHumanFormat(result, level, certlib.FingerprintHex)
}

// FormatRemoteHumanFormat renders remote results at a detail level with an
// explicit fingerprint display format.
func FormatRemoteHumanFormat(result *certops.FetchRemoteCertResult, detailLevel int, fpFormat certlib.FingerprintFormat) string {
	return FormatRemoteHumanOptions(result, OutputOptions{
		DetailLevel:       detailLevel,
		FingerprintFormat: fpFormat,
	})
}

// FormatRemoteHumanOptions renders remote results through the same options the
// file scan uses, so relations, chains and trust reach a served chain too. The
// container indices in opts.RelationIndex must come from
// certops.RemoteCertStore on the same result.
func FormatRemoteHumanOptions(result *certops.FetchRemoteCertResult, opts OutputOptions) string {
	var b strings.Builder

	for i := range result.TargetResults {
		if i > 0 {
			b.WriteString("\n")
		}
		formatTargetHuman(&b, &result.TargetResults[i], i, opts)
	}

	if result.Summary.Total > 1 {
		b.WriteString("\n")
		fmt.Fprintf(&b, "Summary: %d of %d targets succeeded", result.Summary.Succeeded, result.Summary.Total)
		if result.Summary.Failed > 0 {
			fmt.Fprintf(&b, ", %d failed", result.Summary.Failed)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func formatTargetHuman(b *strings.Builder, tr *certops.TargetFetchResult, containerIdx int, opts OutputOptions) {
	if tr.Error != "" {
		header := fmt.Sprintf("%s [remote/error]", tr.Target)
		if ColorsEnabled {
			header = ErrorColor.Sprint(header)
		}
		fmt.Fprintf(b, "%s\n", header)
		fmt.Fprintf(b, "  Error: %s\n", tr.Error)
		return
	}

	tlsVer := ""
	if tr.Connection != nil {
		tlsVer = strings.ToLower(strings.ReplaceAll(tr.Connection.TLSVersion, " ", ""))
	}
	header := fmt.Sprintf("%s [remote/%s]", tr.Target, tlsVer)
	if ColorsEnabled {
		header = BoldAttr.Sprint(header)
	}
	fmt.Fprintf(b, "%s\n", header)

	if tr.Connection != nil {
		formatConnectionHuman(b, tr.Connection)
	}

	if len(tr.Certs) > 0 {
		fmt.Fprintf(b, "\n  Chain (%d certificates, server order):\n", len(tr.Certs))
		container := certops.RemoteContainer(tr)
		b.WriteString(formatContainerItems(&container, containerIdx, opts))
	}

	formatStoreVerdicts(b, opts.StoreVerdicts[tr.Target])

	if tr.MultiIP != nil && len(tr.MultiIP.ResolvedIPs) > 1 {
		b.WriteString("\n  Multi-IP:\n")
		fmt.Fprintf(b, "    Resolved IPs:  %s\n", strings.Join(tr.MultiIP.ResolvedIPs, ", "))
		if tr.MultiIP.AllIdentical {
			fmt.Fprintf(b, "    Chains:        identical across all IPs\n")
		} else {
			msg := "DIFFERENT chains across IPs"
			if ColorsEnabled {
				msg = WarningColor.Sprint(msg)
			}
			fmt.Fprintf(b, "    Chains:        %s\n", msg)
		}
	}

	if tr.ExpiryWarn != nil && len(tr.ExpiryWarn.ExpiringCerts) > 0 {
		b.WriteString("\n  Expiry warnings:\n")
		for _, ec := range tr.ExpiryWarn.ExpiringCerts {
			status := "expiring"
			if ec.Expired {
				status = "EXPIRED"
			}
			dateStr := ColorizeExpiry(ec.NotAfter)
			fmt.Fprintf(b, "    %s: %s (expires %s)\n", status, ec.Subject, dateStr)
		}
	}
}

// formatStoreVerdicts renders one verdict per trust store. The point of the
// table is the disagreement: a chain browsers accept and Java does not is
// exactly what this makes visible in one screen.
func formatStoreVerdicts(b *strings.Builder, verdicts []certops.RemoteStoreVerdict) {
	if len(verdicts) == 0 {
		return
	}

	width := 0
	for _, v := range verdicts {
		if len(v.Store) > width {
			width = len(v.Store)
		}
	}

	b.WriteString("\n  Trust:\n")
	for _, v := range verdicts {
		status := "untrusted"
		if v.Trusted {
			status = "trusted"
		}
		if ColorsEnabled {
			status = ColorizeTrust(status)
		}
		fmt.Fprintf(b, "    %-*s  %s", width, v.Store, status)
		switch {
		case v.Trusted && v.Anchor != "":
			fmt.Fprintf(b, "  (anchor: %s)", v.Anchor)
		case !v.Trusted && v.Reason != "":
			fmt.Fprintf(b, "  (%s)", v.Reason)
		}
		b.WriteString("\n")
		for _, w := range v.Warnings {
			fmt.Fprintf(b, "      note: %s\n", w)
		}
	}
}

func formatConnectionHuman(b *strings.Builder, conn *certops.RemoteConnectionInfo) {
	b.WriteString("  Connection:\n")
	fmt.Fprintf(b, "    TLS Version:     %s\n", conn.TLSVersion)
	fmt.Fprintf(b, "    Cipher Suite:    %s\n", conn.CipherSuite)
	if conn.ALPN != "" {
		fmt.Fprintf(b, "    ALPN:            %s\n", conn.ALPN)
	}
	if conn.SNI != "" {
		fmt.Fprintf(b, "    SNI:             %s\n", conn.SNI)
	}
	fmt.Fprintf(b, "    Remote Address:  %s\n", conn.RemoteAddress)
	fmt.Fprintf(b, "    Latency:         %dms\n", conn.LatencyMs)

	ocspStr := "no"
	if conn.OCSPStapled {
		ocspStr = "yes"
	}
	fmt.Fprintf(b, "    OCSP Stapled:    %s\n", ocspStr)
}

// Structured output for JSON/YAML

type RemoteStructuredOutput struct {
	Targets []RemoteStructuredTarget `json:"targets" yaml:"targets"`
	Summary RemoteStructuredSummary  `json:"summary" yaml:"summary"`
}

type RemoteStructuredTarget struct {
	Target       string                        `json:"target" yaml:"target"`
	TrustStores  []certops.RemoteStoreVerdict  `json:"trust_stores,omitempty" yaml:"trust_stores,omitempty"`
	Connection   *RemoteStructuredConnection   `json:"connection,omitempty" yaml:"connection,omitempty"`
	Certificates []RemoteStructuredCertificate `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	MultiIP      *RemoteStructuredMultiIP      `json:"multi_ip,omitempty" yaml:"multi_ip,omitempty"`
	Error        *string                       `json:"error" yaml:"error"`
}

type RemoteStructuredConnection struct {
	TLSVersion    string `json:"tls_version" yaml:"tls_version"`
	CipherSuite   string `json:"cipher_suite" yaml:"cipher_suite"`
	ALPN          string `json:"alpn,omitempty" yaml:"alpn,omitempty"`
	SNI           string `json:"sni,omitempty" yaml:"sni,omitempty"`
	RemoteAddress string `json:"remote_address" yaml:"remote_address"`
	LatencyMs     int64  `json:"latency_ms" yaml:"latency_ms"`
	OCSPStapled   bool   `json:"ocsp_stapled" yaml:"ocsp_stapled"`
}

// RemoteStructuredCertificate is a served certificate: the same
// StructuredCertificate the file scan emits, plus where it sat in the chain.
// Embedding rather than duplicating is what keeps the two schemas from drifting.
type RemoteStructuredCertificate struct {
	Index                 int    `json:"index" yaml:"index"`
	Role                  string `json:"role" yaml:"role"`
	StructuredCertificate `yaml:",inline"`
}

type RemoteStructuredMultiIP struct {
	ResolvedIPs  []string `json:"resolved_ips" yaml:"resolved_ips"`
	AllIdentical bool     `json:"all_identical" yaml:"all_identical"`
}

type RemoteStructuredSummary struct {
	Total     int `json:"total" yaml:"total"`
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	Failed    int `json:"failed" yaml:"failed"`
}

func buildRemoteStructured(result *certops.FetchRemoteCertResult, opts OutputOptions) RemoteStructuredOutput {
	out := RemoteStructuredOutput{
		Summary: RemoteStructuredSummary{
			Total:     result.Summary.Total,
			Succeeded: result.Summary.Succeeded,
			Failed:    result.Summary.Failed,
		},
	}

	for _, tr := range result.TargetResults {
		st := RemoteStructuredTarget{
			Target:      tr.Target,
			TrustStores: opts.StoreVerdicts[tr.Target],
		}

		if tr.Error != "" {
			errStr := tr.Error
			st.Error = &errStr
		}

		if tr.Connection != nil {
			st.Connection = &RemoteStructuredConnection{
				TLSVersion:    tr.Connection.TLSVersion,
				CipherSuite:   tr.Connection.CipherSuite,
				ALPN:          tr.Connection.ALPN,
				SNI:           tr.Connection.SNI,
				RemoteAddress: tr.Connection.RemoteAddress,
				LatencyMs:     tr.Connection.LatencyMs,
				OCSPStapled:   tr.Connection.OCSPStapled,
			}
		}

		for _, ci := range tr.Certs {
			if ci.Cert == nil || ci.Cert.Certificate == nil {
				continue
			}
			sc := BuildStructuredCert(ci.Cert)
			applyTrustFields(sc, ci.Cert.Certificate, opts)
			st.Certificates = append(st.Certificates, RemoteStructuredCertificate{
				Index:                 ci.Index,
				Role:                  ci.Role,
				StructuredCertificate: *sc,
			})
		}

		if tr.MultiIP != nil {
			st.MultiIP = &RemoteStructuredMultiIP{
				ResolvedIPs:  tr.MultiIP.ResolvedIPs,
				AllIdentical: tr.MultiIP.AllIdentical,
			}
		}

		out.Targets = append(out.Targets, st)
	}

	return out
}

func FormatRemoteJSON(result *certops.FetchRemoteCertResult) string {
	return FormatRemoteJSONOptions(result, OutputOptions{})
}

// FormatRemoteJSONOptions renders remote JSON with the options that carry trust.
func FormatRemoteJSONOptions(result *certops.FetchRemoteCertResult, opts OutputOptions) string {
	data := buildRemoteStructured(result, opts)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(b) + "\n"
}

func FormatRemoteYAML(result *certops.FetchRemoteCertResult) string {
	return FormatRemoteYAMLOptions(result, OutputOptions{})
}

// FormatRemoteYAMLOptions renders remote YAML with the options that carry trust.
func FormatRemoteYAMLOptions(result *certops.FetchRemoteCertResult, opts OutputOptions) string {
	data := buildRemoteStructured(result, opts)
	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Sprintf("error: %q\n", err.Error())
	}
	return string(b)
}
