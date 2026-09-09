package certops

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

const httpMaxBodySize = 1 << 20 // 1 MB

type HTTPRemoteOptions struct {
	Target          string
	Hostname        string
	DisableSNI      bool
	TLSVersion      string
	Starttls        string
	Timeout         time.Duration
	IPv4Only        bool
	IPv6Only        bool
	ProxyURL        string
	ClientCerts     []tls.Certificate
	CustomHeaders   []string
	FollowRedirects bool
	MaxRedirects    int
	HeadersOnly     bool
}

type HTTPRemoteResult struct {
	Target         string
	Response       *certlib.HTTPResponse
	RequestMethod  string
	RequestPath    string
	RequestHost    string
	RequestHeaders map[string]string
	IsBinary       bool
	Error          string
}

func HTTPRemote(opts HTTPRemoteOptions) (*HTTPRemoteResult, error) {
	if opts.Target == "" {
		return nil, &OperationError{Op: "remote-http", Message: "no target specified"}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	starttls, err := certlib.ParseStarttlsProtocol(opts.Starttls)
	if err != nil {
		return nil, &OperationError{Op: "remote-http", Message: err.Error()}
	}

	// Parse the target URL
	targetURL := opts.Target
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, &OperationError{Op: "remote-http", Message: fmt.Sprintf("invalid URL: %v", err)}
	}

	if parsed.Scheme != "https" {
		return nil, &OperationError{Op: "remote-http", Message: "only HTTPS URLs are supported"}
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	var forcedVersion uint16
	if opts.TLSVersion != "" {
		v, err := certlib.TLSVersionFromString(opts.TLSVersion)
		if err != nil {
			return nil, &OperationError{Op: "remote-http", Message: err.Error()}
		}
		forcedVersion = v
	}

	// Capture TLS info from the connection
	var capturedTLSInfo certlib.TLSConnectionInfo
	var capturedLatency time.Duration

	transport := &http.Transport{
		DialTLSContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			start := time.Now()

			dialHost, dialPort := host, port
			if h, p, err := net.SplitHostPort(addr); err == nil {
				dialHost = h
				dialPort = p
			}

			dialSNI := dialHost
			if opts.Hostname != "" {
				dialSNI = opts.Hostname
			}
			if opts.DisableSNI {
				dialSNI = ""
			}

			remoteTarget := certlib.RemoteTarget{
				Host: dialHost,
				Port: 443,
				SNI:  dialSNI,
			}
			if p, err := strconv.Atoi(dialPort); err == nil {
				remoteTarget.Port = p
			}

			dialOpts := certlib.TLSDialOptions{
				ForcedVersion: forcedVersion,
				ServerName:    dialSNI,
				DisableSNI:    opts.DisableSNI,
				Timeout:       opts.Timeout,
				IPv4Only:      opts.IPv4Only,
				IPv6Only:      opts.IPv6Only,
				ClientCerts:   opts.ClientCerts,
				ProxyURL:      opts.ProxyURL,
				Starttls:      starttls,
				// this client speaks HTTP/1.1 only; offering h2 would let the
				// server pick a protocol the request is not written in
				ALPN: []string{"http/1.1"},
			}

			conn, tlsInfo, err := certlib.PipeConnection(remoteTarget, dialOpts)
			if err != nil {
				return nil, err
			}

			if tlsInfo != nil {
				capturedTLSInfo = *tlsInfo
			}
			capturedLatency = time.Since(start)

			return conn, nil
		},
		DisableKeepAlives: true,
		TLSNextProto:      make(map[string]func(string, *tls.Conn) http.RoundTripper), // disable h2
	}

	maxRedirects := opts.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = 10
	}

	var redirectChain []certlib.HTTPRedirect

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	if opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("exceeded max redirects (%d)", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-HTTPS URL: %s", req.URL)
			}
			if len(via) > 0 {
				statusCode := 0
				if req.Response != nil {
					statusCode = req.Response.StatusCode
				}
				redirectChain = append(redirectChain, certlib.HTTPRedirect{
					FromURL:    via[len(via)-1].URL.String(),
					ToURL:      req.URL.String(),
					StatusCode: statusCode,
				})
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	reqPath := parsed.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, &OperationError{Op: "remote-http", Message: fmt.Sprintf("creating request: %v", err)}
	}

	req.Header.Set("User-Agent", "certdiag")
	req.Header.Set("Connection", "close")

	if opts.Hostname != "" {
		req.Host = opts.Hostname
	}

	// Apply custom headers
	reqHeaders := make(map[string]string)
	for _, h := range opts.CustomHeaders {
		key, value, found := strings.Cut(h, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		req.Header.Set(key, value)
		reqHeaders[key] = value
	}

	resp, err := client.Do(req)
	if err != nil {
		return &HTTPRemoteResult{
			Target: opts.Target,
			Error:  err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	// Read body
	var body []byte
	var truncated bool
	if !opts.HeadersOnly {
		body, err = io.ReadAll(io.LimitReader(resp.Body, httpMaxBodySize+1))
		if err != nil {
			body = []byte(fmt.Sprintf("[Error reading body: %v]", err))
		}
		if len(body) > httpMaxBodySize {
			body = body[:httpMaxBodySize]
			truncated = true
		}
	}

	isBinary := detectBinary(resp.Header.Get("Content-Type"), body)

	// Parse security headers
	secHeaders := parseSecurityHeaders(resp.Header)

	httpResp := &certlib.HTTPResponse{
		StatusCode:      resp.StatusCode,
		StatusLine:      resp.Proto + " " + resp.Status,
		Headers:         resp.Header,
		Body:            body,
		BodyTruncated:   truncated,
		TLSInfo:         capturedTLSInfo,
		RedirectChain:   redirectChain,
		SecurityHeaders: secHeaders,
		Latency:         capturedLatency,
	}

	return &HTTPRemoteResult{
		Target:         opts.Target,
		Response:       httpResp,
		RequestMethod:  "GET",
		RequestPath:    reqPath,
		RequestHost:    host,
		RequestHeaders: reqHeaders,
		IsBinary:       isBinary,
	}, nil
}

func detectBinary(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") ||
		ct == "application/octet-stream" ||
		ct == "application/pdf" ||
		ct == "application/zip" {
		return true
	}

	if len(body) > 0 && !utf8.Valid(body[:min(len(body), 512)]) {
		return true
	}

	return false
}

func parseSecurityHeaders(headers http.Header) certlib.SecurityHeaders {
	sh := certlib.SecurityHeaders{
		ContentSecurityPolicy: headers.Get("Content-Security-Policy"),
		XContentTypeOptions:   headers.Get("X-Content-Type-Options"),
		XFrameOptions:         headers.Get("X-Frame-Options"),
		ReferrerPolicy:        headers.Get("Referrer-Policy"),
		PermissionsPolicy:     headers.Get("Permissions-Policy"),
	}

	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		sh.HSTS = parseHSTS(hsts)
	}

	return sh
}

func parseHSTS(raw string) *certlib.HSTSHeader {
	h := &certlib.HSTSHeader{RawValue: raw}

	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)

		if strings.HasPrefix(lower, "max-age=") {
			if v, err := strconv.Atoi(strings.TrimPrefix(lower, "max-age=")); err == nil {
				h.MaxAge = v
			}
		} else if lower == "includesubdomains" {
			h.IncludeSubDomains = true
		} else if lower == "preload" {
			h.Preload = true
		}
	}

	return h
}
