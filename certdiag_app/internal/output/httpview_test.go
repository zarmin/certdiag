package output

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func makeTestHTTPResult() *certops.HTTPRemoteResult {
	return &certops.HTTPRemoteResult{
		Target:        "https://example.com/api/health",
		RequestMethod: "GET",
		RequestPath:   "/api/health",
		RequestHost:   "example.com",
		Response: &certlib.HTTPResponse{
			StatusCode: 200,
			StatusLine: "HTTP/1.1 200 OK",
			Headers: http.Header{
				"Content-Type":   []string{"application/json"},
				"Content-Length": []string{"42"},
			},
			Body: []byte(`{"status":"healthy"}`),
			TLSInfo: certlib.TLSConnectionInfo{
				VersionName:     "TLS 1.3",
				CipherSuiteName: "TLS_AES_256_GCM_SHA384",
			},
			SecurityHeaders: certlib.SecurityHeaders{
				HSTS: &certlib.HSTSHeader{
					MaxAge:            31536000,
					IncludeSubDomains: true,
					RawValue:          "max-age=31536000; includeSubDomains",
				},
				XContentTypeOptions: "nosniff",
			},
		},
	}
}

func TestFormatHTTPHuman(t *testing.T) {
	result := makeTestHTTPResult()
	out := FormatHTTPHuman(result)

	checks := []string{
		"Connected to",
		"TLS 1.3",
		"HTTP/1.1 200 OK",
		"Content-Type",
		`"status":"healthy"`,
		"Security Headers:",
		"Strict-Transport-Security:",
		"max-age=31536000",
		"nosniff",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected %q in output", check)
		}
	}
}

func TestFormatHTTPHuman_HeaderOrderSorted(t *testing.T) {
	result := makeTestHTTPResult()
	result.Response.Headers["Server"] = []string{"nginx"}
	result.Response.Headers["Accept-Ranges"] = []string{"bytes"}
	result.Response.Headers["X-Custom"] = []string{"a"}

	first := FormatHTTPHuman(result)
	for i := 0; i < 20; i++ {
		if got := FormatHTTPHuman(result); got != first {
			t.Fatal("header output must be deterministic across runs")
		}
	}

	ordered := []string{"Accept-Ranges:", "Content-Length:", "Content-Type:", "Server:", "X-Custom:"}
	prev := -1
	for _, h := range ordered {
		idx := strings.Index(first, h)
		if idx < 0 {
			t.Fatalf("missing header %q in output", h)
		}
		if idx < prev {
			t.Errorf("headers not in sorted order at %q:\n%s", h, first)
		}
		prev = idx
	}
}

func TestFormatHTTPHuman_Error(t *testing.T) {
	result := &certops.HTTPRemoteResult{
		Target: "https://bad.example.com",
		Error:  "connection refused",
	}
	out := FormatHTTPHuman(result)
	if !strings.Contains(out, "connection refused") {
		t.Error("expected error in output")
	}
}

func TestFormatHTTPHuman_Binary(t *testing.T) {
	result := &certops.HTTPRemoteResult{
		Target:        "https://example.com/image.png",
		RequestMethod: "GET",
		RequestPath:   "/image.png",
		RequestHost:   "example.com",
		IsBinary:      true,
		Response: &certlib.HTTPResponse{
			StatusCode: 200,
			StatusLine: "HTTP/1.1 200 OK",
			Headers: http.Header{
				"Content-Type": []string{"image/png"},
			},
			Body: []byte{0x89, 0x50, 0x4E, 0x47},
		},
	}
	out := FormatHTTPHuman(result)
	if !strings.Contains(out, "Binary content") {
		t.Error("expected binary content notice")
	}
}

func TestFormatHTTPJSON(t *testing.T) {
	result := makeTestHTTPResult()
	out := FormatHTTPJSON(result)

	var parsed httpJSONOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if parsed.Target != "https://example.com/api/health" {
		t.Errorf("unexpected target: %s", parsed.Target)
	}
	if parsed.Response == nil {
		t.Fatal("expected response")
	}
	if parsed.Response.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", parsed.Response.StatusCode)
	}
	if parsed.Security == nil {
		t.Fatal("expected security headers")
	}
	if !parsed.Security.HSTS.Present {
		t.Error("expected HSTS present")
	}
}

func TestFormatHTTPYAML(t *testing.T) {
	result := makeTestHTTPResult()
	out := FormatHTTPYAML(result)

	if !strings.Contains(out, "example.com") {
		t.Error("expected target in YAML")
	}
	if !strings.Contains(out, "200") {
		t.Error("expected status code in YAML")
	}
}
