package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"gopkg.in/yaml.v3"
)

func FormatHTTPHuman(result *certops.HTTPRemoteResult) string {
	var b strings.Builder

	if result.Error != "" {
		fmt.Fprintf(&b, "Error: %s\n", result.Error)
		return b.String()
	}

	resp := result.Response

	// Connection info
	fmt.Fprintf(&b, "Connected to %s (%s, %s)\n\n",
		result.Target,
		resp.TLSInfo.VersionName,
		resp.TLSInfo.CipherSuiteName,
	)

	// Redirect chain
	for _, r := range resp.RedirectChain {
		fmt.Fprintf(&b, "  -> %s (HTTP %d)\n", r.ToURL, r.StatusCode)
	}
	if len(resp.RedirectChain) > 0 {
		b.WriteString("\n")
	}

	// Status line
	fmt.Fprintf(&b, "%s\n", resp.StatusLine)

	// Response headers
	headerKeys := make([]string, 0, len(resp.Headers))
	for key := range resp.Headers {
		headerKeys = append(headerKeys, key)
	}
	sort.Strings(headerKeys)
	for _, key := range headerKeys {
		for _, v := range resp.Headers[key] {
			fmt.Fprintf(&b, "%s: %s\n", key, v)
		}
	}
	b.WriteString("\n")

	// Body
	if result.IsBinary {
		contentType := resp.Headers.Get("Content-Type")
		fmt.Fprintf(&b, "[Binary content: %d bytes, Content-Type: %s]\n", len(resp.Body), contentType)
	} else if len(resp.Body) > 0 {
		b.Write(resp.Body)
		if !strings.HasSuffix(string(resp.Body), "\n") {
			b.WriteString("\n")
		}
	}

	if resp.BodyTruncated {
		b.WriteString("[Body truncated at 1 MB]\n")
	}

	b.WriteString("\n")

	// Security headers
	formatSecurityHeaders(&b, resp.SecurityHeaders)

	return b.String()
}

func formatSecurityHeaders(b *strings.Builder, sh certlib.SecurityHeaders) {
	b.WriteString("Security Headers:\n")

	if sh.HSTS != nil {
		fmt.Fprintf(b, "  Strict-Transport-Security:  %s\n", sh.HSTS.RawValue)
	} else {
		b.WriteString("  Strict-Transport-Security:  (missing)\n")
	}

	if sh.ContentSecurityPolicy != "" {
		fmt.Fprintf(b, "  Content-Security-Policy:    %s\n", sh.ContentSecurityPolicy)
	} else {
		b.WriteString("  Content-Security-Policy:    (missing)\n")
	}

	if sh.XContentTypeOptions != "" {
		fmt.Fprintf(b, "  X-Content-Type-Options:     %s\n", sh.XContentTypeOptions)
	} else {
		b.WriteString("  X-Content-Type-Options:     (missing)\n")
	}

	if sh.XFrameOptions != "" {
		fmt.Fprintf(b, "  X-Frame-Options:            %s\n", sh.XFrameOptions)
	} else {
		b.WriteString("  X-Frame-Options:            (missing)\n")
	}

	if sh.ReferrerPolicy != "" {
		fmt.Fprintf(b, "  Referrer-Policy:            %s\n", sh.ReferrerPolicy)
	} else {
		b.WriteString("  Referrer-Policy:            (missing)\n")
	}

	if sh.PermissionsPolicy != "" {
		fmt.Fprintf(b, "  Permissions-Policy:         %s\n", sh.PermissionsPolicy)
	} else {
		b.WriteString("  Permissions-Policy:         (missing)\n")
	}
}

type httpJSONOutput struct {
	Target     string              `json:"target" yaml:"target"`
	Connection *httpJSONConnection `json:"connection,omitempty" yaml:"connection,omitempty"`
	Request    httpJSONRequest     `json:"request" yaml:"request"`
	Response   *httpJSONResponse   `json:"response,omitempty" yaml:"response,omitempty"`
	Redirects  []httpJSONRedirect  `json:"redirects" yaml:"redirects"`
	Security   *httpJSONSecurity   `json:"security_headers,omitempty" yaml:"security_headers,omitempty"`
	Error      string              `json:"error,omitempty" yaml:"error,omitempty"`
}

type httpJSONConnection struct {
	TLSVersion    string `json:"tls_version" yaml:"tls_version"`
	CipherSuite   string `json:"cipher_suite" yaml:"cipher_suite"`
	RemoteAddress string `json:"remote_address,omitempty" yaml:"remote_address,omitempty"`
	LatencyMs     int64  `json:"latency_ms" yaml:"latency_ms"`
}

type httpJSONRequest struct {
	Method  string            `json:"method" yaml:"method"`
	Path    string            `json:"path" yaml:"path"`
	Host    string            `json:"host" yaml:"host"`
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type httpJSONResponse struct {
	StatusCode    int                 `json:"status_code" yaml:"status_code"`
	StatusLine    string              `json:"status_line" yaml:"status_line"`
	Headers       map[string][]string `json:"headers" yaml:"headers"`
	Body          string              `json:"body,omitempty" yaml:"body,omitempty"`
	BodyTruncated bool                `json:"body_truncated" yaml:"body_truncated"`
	IsBinary      bool                `json:"is_binary" yaml:"is_binary"`
}

type httpJSONRedirect struct {
	FromURL    string `json:"from_url" yaml:"from_url"`
	ToURL      string `json:"to_url" yaml:"to_url"`
	StatusCode int    `json:"status_code" yaml:"status_code"`
}

type httpJSONSecurity struct {
	HSTS                  *httpJSONHSTS     `json:"strict_transport_security" yaml:"strict_transport_security"`
	ContentSecurityPolicy *httpJSONPresence `json:"content_security_policy" yaml:"content_security_policy"`
	XContentTypeOptions   *httpJSONPresence `json:"x_content_type_options" yaml:"x_content_type_options"`
	XFrameOptions         *httpJSONPresence `json:"x_frame_options" yaml:"x_frame_options"`
	ReferrerPolicy        *httpJSONPresence `json:"referrer_policy" yaml:"referrer_policy"`
	PermissionsPolicy     *httpJSONPresence `json:"permissions_policy" yaml:"permissions_policy"`
}

type httpJSONHSTS struct {
	Present           bool   `json:"present" yaml:"present"`
	Value             string `json:"value,omitempty" yaml:"value,omitempty"`
	MaxAge            int    `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	IncludeSubDomains bool   `json:"include_subdomains,omitempty" yaml:"include_subdomains,omitempty"`
	Preload           bool   `json:"preload,omitempty" yaml:"preload,omitempty"`
}

type httpJSONPresence struct {
	Present bool   `json:"present" yaml:"present"`
	Value   string `json:"value,omitempty" yaml:"value,omitempty"`
}

func buildHTTPStructured(result *certops.HTTPRemoteResult) httpJSONOutput {
	out := httpJSONOutput{
		Target: result.Target,
		Error:  result.Error,
		Request: httpJSONRequest{
			Method:  result.RequestMethod,
			Path:    result.RequestPath,
			Host:    result.RequestHost,
			Headers: result.RequestHeaders,
		},
		Redirects: []httpJSONRedirect{},
	}

	if result.Response == nil {
		return out
	}

	resp := result.Response

	out.Connection = &httpJSONConnection{
		TLSVersion:    resp.TLSInfo.VersionName,
		CipherSuite:   resp.TLSInfo.CipherSuiteName,
		RemoteAddress: resp.TLSInfo.RemoteAddr,
		LatencyMs:     resp.Latency.Milliseconds(),
	}

	bodyStr := ""
	if !result.IsBinary {
		bodyStr = string(resp.Body)
	}

	out.Response = &httpJSONResponse{
		StatusCode:    resp.StatusCode,
		StatusLine:    resp.StatusLine,
		Headers:       resp.Headers,
		Body:          bodyStr,
		BodyTruncated: resp.BodyTruncated,
		IsBinary:      result.IsBinary,
	}

	for _, r := range resp.RedirectChain {
		out.Redirects = append(out.Redirects, httpJSONRedirect{
			FromURL:    r.FromURL,
			ToURL:      r.ToURL,
			StatusCode: r.StatusCode,
		})
	}

	sh := resp.SecurityHeaders
	out.Security = &httpJSONSecurity{
		HSTS:                  &httpJSONHSTS{Present: sh.HSTS != nil},
		ContentSecurityPolicy: &httpJSONPresence{Present: sh.ContentSecurityPolicy != "", Value: sh.ContentSecurityPolicy},
		XContentTypeOptions:   &httpJSONPresence{Present: sh.XContentTypeOptions != "", Value: sh.XContentTypeOptions},
		XFrameOptions:         &httpJSONPresence{Present: sh.XFrameOptions != "", Value: sh.XFrameOptions},
		ReferrerPolicy:        &httpJSONPresence{Present: sh.ReferrerPolicy != "", Value: sh.ReferrerPolicy},
		PermissionsPolicy:     &httpJSONPresence{Present: sh.PermissionsPolicy != "", Value: sh.PermissionsPolicy},
	}

	if sh.HSTS != nil {
		out.Security.HSTS.Value = sh.HSTS.RawValue
		out.Security.HSTS.MaxAge = sh.HSTS.MaxAge
		out.Security.HSTS.IncludeSubDomains = sh.HSTS.IncludeSubDomains
		out.Security.HSTS.Preload = sh.HSTS.Preload
	}

	return out
}

func FormatHTTPJSON(result *certops.HTTPRemoteResult) string {
	out := buildHTTPStructured(result)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf("{\"error\": %q}\n", err.Error())
	}
	return string(data) + "\n"
}

func FormatHTTPYAML(result *certops.HTTPRemoteResult) string {
	out := buildHTTPStructured(result)
	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	return string(data)
}
