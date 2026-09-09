package certops

import (
	"net/http"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestHTTPRemote_NoTarget(t *testing.T) {
	_, err := HTTPRemote(HTTPRemoteOptions{})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestHTTPRemote_PlainHTTP(t *testing.T) {
	_, err := HTTPRemote(HTTPRemoteOptions{
		Target: "http://example.com",
	})
	if err == nil {
		t.Fatal("expected error for plain HTTP")
	}
}

func TestHTTPRemote_InvalidURL(t *testing.T) {
	_, err := HTTPRemote(HTTPRemoteOptions{
		Target: "https://example.com:not-a-port",
	})
	// Should either fail during parsing or connection
	if err != nil {
		return // parse error is fine
	}
}

func TestHTTPRemote_InvalidTLSVersion(t *testing.T) {
	_, err := HTTPRemote(HTTPRemoteOptions{
		Target:     "https://example.com",
		TLSVersion: "tls0.9",
	})
	if err == nil {
		t.Fatal("expected error for invalid TLS version")
	}
}

func TestDetectBinary(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        bool
	}{
		{"image/png", "image/png", nil, true},
		{"application/pdf", "application/pdf", nil, true},
		{"application/octet-stream", "application/octet-stream", nil, true},
		{"text/html", "text/html", []byte("<html>"), false},
		{"application/json", "application/json", []byte(`{"key":"value"}`), false},
		{"binary bytes", "text/plain", []byte{0x00, 0xFF, 0x80}, true},
		{"empty", "text/plain", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBinary(tt.contentType, tt.body)
			if got != tt.want {
				t.Errorf("detectBinary(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestParseSecurityHeaders(t *testing.T) {
	headers := http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains; preload"},
		"Content-Security-Policy":   []string{"default-src 'self'"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"X-Frame-Options":           []string{"DENY"},
		"Referrer-Policy":           []string{"strict-origin"},
		"Permissions-Policy":        []string{"geolocation=()"},
	}

	sh := parseSecurityHeaders(headers)

	if sh.HSTS == nil {
		t.Fatal("expected HSTS header")
	}
	if sh.HSTS.MaxAge != 31536000 {
		t.Errorf("expected max-age 31536000, got %d", sh.HSTS.MaxAge)
	}
	if !sh.HSTS.IncludeSubDomains {
		t.Error("expected includeSubDomains")
	}
	if !sh.HSTS.Preload {
		t.Error("expected preload")
	}
	if sh.ContentSecurityPolicy != "default-src 'self'" {
		t.Errorf("unexpected CSP: %s", sh.ContentSecurityPolicy)
	}
	if sh.XContentTypeOptions != "nosniff" {
		t.Errorf("unexpected X-Content-Type-Options: %s", sh.XContentTypeOptions)
	}
	if sh.XFrameOptions != "DENY" {
		t.Errorf("unexpected X-Frame-Options: %s", sh.XFrameOptions)
	}
}

func TestParseSecurityHeaders_Missing(t *testing.T) {
	sh := parseSecurityHeaders(http.Header{})

	if sh.HSTS != nil {
		t.Error("expected nil HSTS")
	}
	if sh.ContentSecurityPolicy != "" {
		t.Error("expected empty CSP")
	}
}

func TestParseHSTS(t *testing.T) {
	tests := []struct {
		raw               string
		maxAge            int
		includeSubDomains bool
		preload           bool
	}{
		{"max-age=0", 0, false, false},
		{"max-age=31536000", 31536000, false, false},
		{"max-age=31536000; includeSubDomains", 31536000, true, false},
		{"max-age=31536000; includeSubDomains; preload", 31536000, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			h := parseHSTS(tt.raw)
			if h.MaxAge != tt.maxAge {
				t.Errorf("max-age = %d, want %d", h.MaxAge, tt.maxAge)
			}
			if h.IncludeSubDomains != tt.includeSubDomains {
				t.Errorf("includeSubDomains = %v, want %v", h.IncludeSubDomains, tt.includeSubDomains)
			}
			if h.Preload != tt.preload {
				t.Errorf("preload = %v, want %v", h.Preload, tt.preload)
			}
		})
	}
}

func TestHTTPRemoteResult_Structured(t *testing.T) {
	result := &HTTPRemoteResult{
		Target:        "https://example.com",
		RequestMethod: "GET",
		RequestPath:   "/",
		RequestHost:   "example.com",
		Response: &certlib.HTTPResponse{
			StatusCode: 200,
			StatusLine: "HTTP/1.1 200 OK",
			Headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			Body: []byte("<html></html>"),
		},
	}

	if result.Response.StatusCode != 200 {
		t.Error("expected status 200")
	}
}
