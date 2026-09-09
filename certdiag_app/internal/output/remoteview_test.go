package output

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func makeTestFetchResult() *certops.FetchRemoteCertResult {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "example.com"},
		Issuer:             pkix.Name{CommonName: "Test CA"},
		NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber:       big.NewInt(12345),
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"example.com", "www.example.com"},
		Raw:                []byte{1, 2, 3},
	}

	return &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "example.com:443",
				Connection: &certops.RemoteConnectionInfo{
					TLSVersion:    "TLS 1.3",
					CipherSuite:   "TLS_AES_256_GCM_SHA384",
					ALPN:          "h2",
					SNI:           "example.com",
					RemoteAddress: "93.184.216.34:443",
					LatencyMs:     45,
					OCSPStapled:   true,
				},
				Certs: []certops.RemoteCertInfo{
					{
						Index: 1,
						Role:  "leaf",
						Cert: &certlib.CertItem{
							Type:        certlib.ContentCertificate,
							Certificate: cert,
							RawBytes:    cert.Raw,
						},
						RawDER: cert.Raw,
					},
				},
			},
		},
		Summary: certops.FetchSummary{
			Total:     1,
			Succeeded: 1,
			Failed:    0,
		},
	}
}

func TestFormatRemoteHuman(t *testing.T) {
	result := makeTestFetchResult()
	out := FormatRemoteHuman(result)

	checks := []string{
		"example.com:443",
		"remote/tls1.3",
		"TLS 1.3",
		"TLS_AES_256_GCM_SHA384",
		"example.com",
		"[leaf] Certificate", // the shared item renderer names the role as the alias
		"Test CA",
		"45ms",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("human output should contain %q", check)
		}
	}
}

func TestFormatRemoteHumanSerialZero(t *testing.T) {
	result := makeTestFetchResult()
	result.TargetResults[0].Certs[0].Cert.Certificate.SerialNumber = big.NewInt(0)

	out := FormatRemoteHuman(result)

	want := "Serial:      " + certlib.FormatSerial(big.NewInt(0))
	if !strings.Contains(out, want) {
		t.Errorf("serial 0 should render via shared FormatSerial (%q), got:\n%s", want, out)
	}
	if strings.Contains(out, "Serial:      \n") {
		t.Error("serial 0 rendered blank instead of via shared FormatSerial")
	}
}

func TestFormatRemoteHumanSerialNormal(t *testing.T) {
	result := makeTestFetchResult()

	out := FormatRemoteHuman(result)

	want := "Serial:      " + certlib.FormatSerial(big.NewInt(12345))
	if !strings.Contains(out, want) {
		t.Errorf("serial should render via shared FormatSerial (%q), got:\n%s", want, out)
	}
}

func TestFormatRemoteHumanError(t *testing.T) {
	result := &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "bad.example.com:443",
				Error:  "connection refused",
			},
		},
		Summary: certops.FetchSummary{Total: 1, Succeeded: 0, Failed: 1},
	}

	out := FormatRemoteHuman(result)
	if !strings.Contains(out, "remote/error") {
		t.Error("error target should show remote/error")
	}
	if !strings.Contains(out, "connection refused") {
		t.Error("should show error message")
	}
}

func TestFormatRemoteHumanMultiTarget(t *testing.T) {
	result := makeTestFetchResult()
	result.TargetResults = append(result.TargetResults, certops.TargetFetchResult{
		Target: "google.com:443",
		Error:  "timeout",
	})
	result.Summary.Total = 2
	result.Summary.Failed = 1

	out := FormatRemoteHuman(result)
	if !strings.Contains(out, "Summary:") {
		t.Error("multi-target should show summary")
	}
	if !strings.Contains(out, "1 of 2") {
		t.Error("should show 1 of 2 succeeded")
	}
}

func TestFormatRemoteJSON(t *testing.T) {
	result := makeTestFetchResult()
	out := FormatRemoteJSON(result)

	var parsed RemoteStructuredOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(parsed.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(parsed.Targets))
	}
	if parsed.Targets[0].Target != "example.com:443" {
		t.Errorf("target = %q, want %q", parsed.Targets[0].Target, "example.com:443")
	}
	if parsed.Targets[0].Connection == nil {
		t.Fatal("connection should not be nil")
	}
	if parsed.Targets[0].Connection.TLSVersion != "TLS 1.3" {
		t.Errorf("tls_version = %q, want %q", parsed.Targets[0].Connection.TLSVersion, "TLS 1.3")
	}
	if len(parsed.Targets[0].Certificates) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(parsed.Targets[0].Certificates))
	}
	if parsed.Targets[0].Certificates[0].Role != "leaf" {
		t.Errorf("role = %q, want %q", parsed.Targets[0].Certificates[0].Role, "leaf")
	}
	if parsed.Summary.Total != 1 {
		t.Errorf("summary total = %d, want %d", parsed.Summary.Total, 1)
	}
}

func TestFormatRemoteYAML(t *testing.T) {
	result := makeTestFetchResult()
	out := FormatRemoteYAML(result)

	var parsed RemoteStructuredOutput
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid YAML: %v", err)
	}

	if len(parsed.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(parsed.Targets))
	}
	if parsed.Targets[0].Target != "example.com:443" {
		t.Errorf("target = %q", parsed.Targets[0].Target)
	}
}

func TestFormatRemoteHumanMultiIP(t *testing.T) {
	result := makeTestFetchResult()
	result.TargetResults[0].MultiIP = &certops.MultiIPInfo{
		ResolvedIPs:  []string{"93.184.216.34", "93.184.216.35"},
		AllIdentical: true,
	}

	out := FormatRemoteHuman(result)
	if !strings.Contains(out, "Multi-IP:") {
		t.Error("should show multi-IP section")
	}
	if !strings.Contains(out, "identical") {
		t.Error("should show identical chains message")
	}
}

// certBlock returns the rendering from the first certificate row onward, which
// is the part the scan and the remote view must agree on.
func certBlock(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "  [leaf] Certificate")
	if i < 0 {
		t.Fatalf("no certificate block in:\n%s", out)
	}
	return strings.TrimRight(out[i:], "\n")
}

// TestRemoteHuman_FieldParityWithScan is the reason part IV exists: a served
// certificate must render exactly as a scanned one. Both paths go through
// formatContainerItems, so this fails the moment one of them grows a field the
// other lacks.
func TestRemoteHuman_FieldParityWithScan(t *testing.T) {
	for _, level := range []int{1, 2} {
		result := makeTestFetchResult()
		opts := OutputOptions{DetailLevel: level}

		store := certops.RemoteCertStore(result)
		scanned := &certlib.CertContainer{
			FilePath: "/tmp/served.pem",
			Format:   certlib.FormatPEM,
			Items:    store.Containers[0].Items,
		}

		remote := certBlock(t, FormatRemoteHumanOptions(result, opts))
		scan := certBlock(t, FormatListView(scanned, 0, opts))

		if remote != scan {
			t.Errorf("-d level %d: remote and scan renderings differ\nremote:\n%s\n\nscan:\n%s", level, remote, scan)
		}
	}
}

func TestRemoteHuman_ExtendedPrintsPEM(t *testing.T) {
	result := makeTestFetchResult()

	plain := FormatRemoteHumanOptions(result, OutputOptions{DetailLevel: 1})
	if strings.Contains(plain, "PEM:") {
		t.Error("-d must not print the PEM body")
	}
	if strings.Contains(plain, "Subject DN:") {
		t.Error("-d must not print full DNs")
	}

	extended := FormatRemoteHumanOptions(result, OutputOptions{DetailLevel: 2})
	if !strings.Contains(extended, "PEM:") {
		t.Error("-dd must print the PEM body")
	}
	if !strings.Contains(extended, "Subject DN:") {
		t.Error("-dd must print full DNs")
	}
}

// TestRemoteJSON_EmbedsStructuredCertificate pins the schema break: remote
// certificates now carry the same fields as scanned ones, under the same names.
func TestRemoteJSON_EmbedsStructuredCertificate(t *testing.T) {
	result := makeTestFetchResult()
	out := FormatRemoteJSON(result)

	var parsed struct {
		Targets []struct {
			Certificates []map[string]any `json:"certificates"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("remote JSON must parse: %v\n%s", err, out)
	}
	if len(parsed.Targets) != 1 || len(parsed.Targets[0].Certificates) != 1 {
		t.Fatalf("expected one certificate, got %s", out)
	}
	cert := parsed.Targets[0].Certificates[0]

	for _, key := range []string{"index", "role", "subject", "subject_dn", "issuer_dn", "version", "sha256", "self_signed"} {
		if _, ok := cert[key]; !ok {
			t.Errorf("remote JSON must carry %q (embedded StructuredCertificate)", key)
		}
	}
	for _, gone := range []string{"fingerprint_sha256", "fingerprint_md5", "signature_algorithm_x"} {
		if _, ok := cert[gone]; ok && strings.HasPrefix(gone, "fingerprint_") {
			t.Errorf("the flat %q field was replaced by the shared name", gone)
		}
	}
}

// TestRemoteJSON_FailedTargetStillReports keeps the error path honest after the
// schema change.
func TestRemoteJSON_FailedTargetStillReports(t *testing.T) {
	result := &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{{Target: "down:443", Error: "refused"}},
		Summary:       certops.FetchSummary{Total: 1, Failed: 1},
	}
	out := FormatRemoteJSON(result)
	if !strings.Contains(out, "refused") {
		t.Errorf("a failed target must still report its error:\n%s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Error("output must stay valid JSON")
	}
}
