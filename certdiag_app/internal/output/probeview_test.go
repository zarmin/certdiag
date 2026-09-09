package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func makeTestProbeResult() *certops.ProbeRemoteResult {
	return &certops.ProbeRemoteResult{
		Target: "example.com:443",
		Probe: &certlib.ProbeResult{
			Target: certlib.RemoteTarget{Host: "example.com", Port: 443},
			Versions: []certlib.ProbeVersionResult{
				{Version: 0x0300, VersionName: "SSLv3", Supported: false, Error: "not supported"},
				{Version: 0x0301, VersionName: "TLS 1.0", Supported: false, Error: "not supported"},
				{Version: 0x0302, VersionName: "TLS 1.1", Supported: false, Error: "not supported"},
				{Version: 0x0303, VersionName: "TLS 1.2", Supported: true, CipherSuite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				{Version: 0x0304, VersionName: "TLS 1.3", Supported: true, CipherSuite: "TLS_AES_256_GCM_SHA384"},
			},
			CipherSuites: []certlib.ProbeCipherResult{
				{CipherSuiteName: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLSVersion: "TLS 1.2", Supported: true},
				{CipherSuiteName: "TLS_AES_256_GCM_SHA384", TLSVersion: "TLS 1.3", Supported: true},
			},
			CipherPreference:    "server",
			OCSPStapled:         true,
			ALPNProtocols:       []string{"h2"},
			SecureRenegotiation: boolPtr(true),
			Compression:         boolPtr(false),
			FeaturesTLSVersion:  0x0303,
			Duration:            3200 * time.Millisecond,
		},
	}
}

func TestFormatProbeHuman(t *testing.T) {
	result := makeTestProbeResult()
	out := FormatProbeHuman(result)

	checks := []string{
		"example.com:443",
		"TLS Probe Results",
		"TLS Versions:",
		"SSLv3",
		"TLS 1.2",
		"supported",
		"not supported",
		"Cipher Suites",
		"Features:",
		"ALPN:",
		"h2",
		"OCSP Stapling:",
		"yes",
		"server",
		"Probe completed",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected %q in output", check)
		}
	}
}

func TestFormatProbeHuman_Error(t *testing.T) {
	result := &certops.ProbeRemoteResult{
		Target: "bad.example.com:443",
		Error:  "connection refused",
	}
	out := FormatProbeHuman(result)
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error in output")
	}
}

func TestFormatProbeJSON(t *testing.T) {
	result := makeTestProbeResult()
	out := FormatProbeJSON(result)

	var parsed probeJSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed.Target != "example.com:443" {
		t.Errorf("unexpected target: %s", parsed.Target)
	}
	if len(parsed.Versions) != 5 {
		t.Errorf("expected 5 versions, got %d", len(parsed.Versions))
	}
	if len(parsed.CipherSuites) != 2 {
		t.Errorf("expected 2 cipher suites, got %d", len(parsed.CipherSuites))
	}
	if parsed.CipherPreference != "server" {
		t.Errorf("expected server preference, got %s", parsed.CipherPreference)
	}
	if !parsed.Features.OCSPStapled {
		t.Error("expected OCSP stapled")
	}
}

func TestFormatProbeYAML(t *testing.T) {
	result := makeTestProbeResult()
	out := FormatProbeYAML(result)

	if !strings.Contains(out, "example.com:443") {
		t.Error("expected target in YAML")
	}
	if !strings.Contains(out, "TLS 1.3") {
		t.Error("expected TLS 1.3 in YAML")
	}
}

func TestFormatProbeJSON_Error(t *testing.T) {
	result := &certops.ProbeRemoteResult{
		Target: "bad.example.com:443",
		Error:  "connection refused",
	}
	out := FormatProbeJSON(result)

	var parsed probeJSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Error != "connection refused" {
		t.Errorf("expected error, got %q", parsed.Error)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestFormatProbeHuman_UnmeasuredFeatures: a feature the probe could not read
// is reported as such, never as a default value (M31 H4).
func TestFormatProbeHuman_UnmeasuredFeatures(t *testing.T) {
	result := makeTestProbeResult()
	result.Probe.SecureRenegotiation = nil
	result.Probe.Compression = nil
	result.Probe.FeaturesTLSVersion = 0
	out := FormatProbeHuman(result)
	if !strings.Contains(out, "Secure Renegotiation:    not probed") || !strings.Contains(out, "TLS Compression:         not probed") {
		t.Errorf("unmeasured features must read 'not probed':\n%s", out)
	}

	result.Probe.FeaturesTLSVersion = 0x0304
	out = FormatProbeHuman(result)
	if !strings.Contains(out, "not applicable (TLS 1.3") {
		t.Errorf("TLS 1.3 has no renegotiation and must say so:\n%s", out)
	}

	js := FormatProbeJSON(result)
	if !strings.Contains(js, `"secure_renegotiation": null`) {
		t.Errorf("JSON must carry null for an unmeasured feature:\n%s", js)
	}
}
