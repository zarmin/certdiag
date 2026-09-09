package certlib

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultTLSPort = 443

// IsRemoteTargetSyntax reports whether raw is written as a remote endpoint: a
// URL with a scheme, or host:port. A bare name is not one, so a mistyped file
// name never turns into a network connection (air-gapped first).
func IsRemoteTargetSyntax(raw string) bool {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return true
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || host == "" {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

// ParseTarget parses a raw target string into a RemoteTarget.
func ParseTarget(raw string) (RemoteTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RemoteTarget{}, fmt.Errorf("empty target")
	}

	t := RemoteTarget{Original: raw}

	// Detect malformed scheme (e.g. "https//example.com" missing the colon)
	if strings.Contains(raw, "//") && !strings.Contains(raw, "://") {
		suggestion := strings.Replace(raw, "//", "://", 1)
		return RemoteTarget{}, fmt.Errorf("invalid target %q (did you mean %s?)", raw, suggestion)
	}

	if i := strings.Index(raw, "://"); i >= 0 {
		if scheme := raw[:i]; scheme != "https" && scheme != "tls" {
			return RemoteTarget{}, fmt.Errorf("unsupported scheme %q (use https:// or tls://)", scheme)
		}
		return parseURLTarget(raw, t)
	}

	return parseHostTarget(raw, t)
}

func parseURLTarget(raw string, t RemoteTarget) (RemoteTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return RemoteTarget{}, fmt.Errorf("invalid URL %q: %w", raw, err)
	}

	if u.Scheme != "https" && u.Scheme != "tls" {
		return RemoteTarget{}, fmt.Errorf("unsupported scheme %q (use https:// or tls://)", u.Scheme)
	}

	if u.User != nil {
		return RemoteTarget{}, fmt.Errorf("userinfo in target URL is not supported")
	}

	t.Scheme = u.Scheme
	t.URLPath = u.Path
	if t.URLPath == "" {
		t.URLPath = "/"
	}

	host := u.Hostname()
	port := u.Port()

	if host == "" {
		return RemoteTarget{}, fmt.Errorf("empty hostname in URL %q", raw)
	}

	return finishTarget(t, host, port)
}

func parseHostTarget(raw string, t RemoteTarget) (RemoteTarget, error) {
	t.Scheme = "tls"

	// Handle IPv6 bracket notation: [::1] or [::1]:port
	if strings.HasPrefix(raw, "[") {
		closeBracket := strings.Index(raw, "]")
		if closeBracket == -1 {
			return RemoteTarget{}, fmt.Errorf("invalid IPv6 address %q: missing closing bracket", raw)
		}
		host := raw[1:closeBracket]
		rest := raw[closeBracket+1:]
		var port string
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return finishTarget(t, host, port)
	}

	// Check if it's a host:port pair (but not an IPv6 address)
	if lastColon := strings.LastIndex(raw, ":"); lastColon != -1 {
		host := raw[:lastColon]
		port := raw[lastColon+1:]
		// Ensure this isn't an IPv6 address (contains multiple colons)
		if !strings.Contains(host, ":") {
			return finishTarget(t, host, port)
		}
	}

	// Plain hostname or IPv4
	return finishTarget(t, raw, "")
}

func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

func finishTarget(t RemoteTarget, host, portStr string) (RemoteTarget, error) {
	t.Host = host

	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return RemoteTarget{}, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
		if port < 1 || port > 65535 {
			return RemoteTarget{}, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		t.Port = port
	} else {
		t.Port = defaultTLSPort
	}

	ip := net.ParseIP(t.Host)
	if ip != nil {
		t.IsIP = true
		t.IsIPv6 = ip.To4() == nil
		t.SNI = ""
	} else {
		if !isValidHostname(t.Host) {
			return RemoteTarget{}, fmt.Errorf("invalid hostname %q: contains characters not allowed in DNS names", t.Host)
		}
		t.SNI = t.Host
	}

	return t, nil
}

// TLSVersionFromString converts a version string to tls version constant.
func TLSVersionFromString(s string) (uint16, error) {
	switch strings.ToLower(s) {
	case "", "auto":
		return 0, nil
	case "tls1.0", "tls10":
		return tls.VersionTLS10, nil
	case "tls1.1", "tls11":
		return tls.VersionTLS11, nil
	case "tls1.2", "tls12":
		return tls.VersionTLS12, nil
	case "tls1.3", "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown TLS version: %q", s)
	}
}

// DialTLS connects to the target, performs the TLS handshake, extracts
// the certificate chain and connection metadata, then closes the connection.
func DialTLS(target RemoteTarget, opts TLSDialOptions) (*FetchResult, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	var timing ConnectionTiming

	// DNS resolution
	ips, err := resolveHost(ctx, target, opts, &timing)
	if err != nil {
		return &FetchResult{Target: target, Error: err}, nil
	}

	if opts.SingleIP && len(ips) > 1 {
		ips = ips[:1]
	}
	if len(ips) > MaxMultiIP {
		ips = ips[:MaxMultiIP]
	}

	// For now, connect to the first IP only for DialTLS.
	// Multi-IP is handled at the caller level.
	ip := ips[0]

	result, err := dialSingleIP(ctx, target, ip, opts, timing)
	if err != nil {
		return &FetchResult{Target: target, Error: err}, nil
	}

	return result, nil
}

// DialTLSMultiIP connects to all resolved IPs and returns a MultiIPResult.
func DialTLSMultiIP(target RemoteTarget, opts TLSDialOptions) (*MultiIPResult, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	resolveCtx, resolveCancel := context.WithTimeout(context.Background(), opts.Timeout)
	var timing ConnectionTiming
	ips, err := resolveHost(resolveCtx, target, opts, &timing)
	resolveCancel()
	if err != nil {
		return nil, err
	}

	if opts.SingleIP && len(ips) > 1 {
		ips = ips[:1]
	}
	if len(ips) > MaxMultiIP {
		ips = ips[:MaxMultiIP]
	}

	result := &MultiIPResult{
		Target:      target,
		ResolvedIPs: ips,
		Results:     make([]FetchResult, 0, len(ips)),
	}

	for _, ip := range ips {
		ipCtx, ipCancel := context.WithTimeout(context.Background(), opts.Timeout)
		fr, err := dialSingleIP(ipCtx, target, ip, opts, timing)
		ipCancel()
		if err != nil {
			result.Results = append(result.Results, FetchResult{Target: target, Error: err})
		} else {
			result.Results = append(result.Results, *fr)
		}
	}

	result.AllIdentical = compareChains(result.Results)
	return result, nil
}

func resolveHost(ctx context.Context, target RemoteTarget, opts TLSDialOptions, timing *ConnectionTiming) ([]string, error) {
	if target.IsIP {
		return []string{target.Host}, nil
	}

	// With a proxy, let the proxy resolve the hostname so DNS queries are not
	// leaked locally and proxy-only-resolvable hosts work.
	if opts.ProxyURL != "" {
		return []string{target.Host}, nil
	}

	timing.DNSStart = time.Now()
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(ctx, target.Host)
	timing.DNSDone = time.Now()
	timing.DNSDuration = timing.DNSDone.Sub(timing.DNSStart)

	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", target.Host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS returned no addresses for %s", target.Host)
	}

	if opts.IPv4Only || opts.IPv6Only {
		filtered := make([]string, 0, len(ips))
		for _, ip := range ips {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			isV4 := parsed.To4() != nil
			if (opts.IPv4Only && isV4) || (opts.IPv6Only && !isV4) {
				filtered = append(filtered, ip)
			}
		}
		if len(filtered) == 0 {
			family := "IPv4"
			if opts.IPv6Only {
				family = "IPv6"
			}
			return nil, fmt.Errorf("no %s addresses found for %s", family, target.Host)
		}
		ips = filtered
	}

	return ips, nil
}

func dialSingleIP(ctx context.Context, target RemoteTarget, ip string, opts TLSDialOptions, dnsTiming ConnectionTiming) (*FetchResult, error) {
	var timing ConnectionTiming
	timing.DNSStart = dnsTiming.DNSStart
	timing.DNSDone = dnsTiming.DNSDone
	timing.DNSDuration = dnsTiming.DNSDuration

	// Build dial address
	addr := net.JoinHostPort(ip, strconv.Itoa(target.Port))

	// TCP connect
	timing.TCPStart = time.Now()
	var tcpConn net.Conn
	var err error

	if opts.ProxyURL != "" {
		tcpConn, err = dialWithProxy(ctx, opts.ProxyURL, addr, opts.Timeout)
	} else {
		network := "tcp"
		if opts.IPv4Only {
			network = "tcp4"
		} else if opts.IPv6Only {
			network = "tcp6"
		}
		dialer := &net.Dialer{Timeout: opts.Timeout}
		tcpConn, err = dialer.DialContext(ctx, network, addr)
	}
	timing.TCPDone = time.Now()
	timing.TCPDuration = timing.TCPDone.Sub(timing.TCPStart)

	if err != nil {
		return &FetchResult{
			Target: target,
			TLSInfo: TLSConnectionInfo{
				RemoteAddr: addr,
				Timing:     timing,
			},
			Error: fmt.Errorf("TCP connect to %s failed: %w", addr, err),
		}, nil
	}

	// STARTTLS negotiation (if needed)
	if opts.Starttls != StarttlsNone {
		if err := PerformStarttls(tcpConn, opts.Starttls, target.Host, time.Now().Add(opts.Timeout)); err != nil {
			tcpConn.Close()
			return &FetchResult{
				Target: target,
				Error:  fmt.Errorf("STARTTLS %s failed: %w", opts.Starttls, err),
			}, nil
		}
	}

	// TLS handshake
	tlsConfig := buildTLSConfig(target, opts)

	timing.TLSStart = time.Now()
	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	timing.TLSDone = time.Now()
	timing.TLSDuration = timing.TLSDone.Sub(timing.TLSStart)
	timing.TotalDuration = timing.TLSDone.Sub(timing.TCPStart) + timing.DNSDuration

	if err != nil {
		tcpConn.Close()
		return &FetchResult{
			Target: target,
			TLSInfo: TLSConnectionInfo{
				RemoteAddr: addr,
				Timing:     timing,
			},
			Error: fmt.Errorf("TLS handshake with %s failed: %w", addr, err),
		}, nil
	}

	state := tlsConn.ConnectionState()
	tlsConn.Close()

	tlsInfo := TLSConnectionInfo{
		Version:           state.Version,
		VersionName:       TLSVersionName(state.Version),
		CipherSuite:       state.CipherSuite,
		CipherSuiteName:   tls.CipherSuiteName(state.CipherSuite),
		ServerName:        state.ServerName,
		NegotiatedProto:   state.NegotiatedProtocol,
		ALPNOffered:       tlsConfig.NextProtos,
		PeerCertificates:  state.PeerCertificates,
		OCSPStapled:       len(state.OCSPResponse) > 0,
		OCSPResponse:      state.OCSPResponse,
		HandshakeComplete: state.HandshakeComplete,
		ConnectedAt:       time.Now(),
		RemoteAddr:        addr,
		Timing:            timing,
	}

	// Build chain PEM
	var chainPEM bytes.Buffer
	for _, cert := range state.PeerCertificates {
		pem.Encode(&chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	return &FetchResult{
		Target:       target,
		TLSInfo:      tlsInfo,
		Certificates: state.PeerCertificates,
		ChainPEM:     chainPEM.Bytes(),
	}, nil
}

func buildTLSConfig(target RemoteTarget, opts TLSDialOptions) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	// SNI
	if opts.DisableSNI {
		config.ServerName = ""
	} else if opts.ServerName != "" {
		config.ServerName = opts.ServerName
	} else {
		config.ServerName = target.SNI
	}

	// TLS version
	if opts.ForcedVersion != 0 {
		config.MinVersion = opts.ForcedVersion
		config.MaxVersion = opts.ForcedVersion
	} else {
		if opts.MinVersion != 0 {
			config.MinVersion = opts.MinVersion
		}
		if opts.MaxVersion != 0 {
			config.MaxVersion = opts.MaxVersion
		}
	}

	// Client certs (mTLS)
	if len(opts.ClientCerts) > 0 {
		config.Certificates = opts.ClientCerts
	}

	// ALPN is offered only when the caller asked; STARTTLS sessions never
	// offer the HTTP identifiers, whatever the caller passed.
	if len(opts.ALPN) > 0 && opts.Starttls == StarttlsNone {
		config.NextProtos = append([]string(nil), opts.ALPN...)
	}

	return config
}

// PipeConnection establishes a TLS connection and returns it open.
// Caller is responsible for closing.
func PipeConnection(target RemoteTarget, opts TLSDialOptions) (*tls.Conn, *TLSConnectionInfo, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	var timing ConnectionTiming
	ips, err := resolveHost(ctx, target, opts, &timing)
	if err != nil {
		return nil, nil, err
	}

	ip := ips[0]
	addr := net.JoinHostPort(ip, strconv.Itoa(target.Port))

	// TCP connect
	timing.TCPStart = time.Now()
	var tcpConn net.Conn
	if opts.ProxyURL != "" {
		tcpConn, err = dialWithProxy(ctx, opts.ProxyURL, addr, opts.Timeout)
	} else {
		dialer := &net.Dialer{Timeout: opts.Timeout}
		tcpConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	timing.TCPDone = time.Now()
	timing.TCPDuration = timing.TCPDone.Sub(timing.TCPStart)

	if err != nil {
		return nil, nil, fmt.Errorf("TCP connect to %s failed: %w", addr, err)
	}

	// STARTTLS
	if opts.Starttls != StarttlsNone {
		if err := PerformStarttls(tcpConn, opts.Starttls, target.Host, time.Now().Add(opts.Timeout)); err != nil {
			tcpConn.Close()
			return nil, nil, fmt.Errorf("STARTTLS %s failed: %w", opts.Starttls, err)
		}
	}

	// TLS handshake
	tlsConfig := buildTLSConfig(target, opts)
	timing.TLSStart = time.Now()
	tlsConn := tls.Client(tcpConn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	timing.TLSDone = time.Now()
	timing.TLSDuration = timing.TLSDone.Sub(timing.TLSStart)
	timing.TotalDuration = timing.TLSDone.Sub(timing.TCPStart)

	if err != nil {
		tcpConn.Close()
		return nil, nil, fmt.Errorf("TLS handshake with %s failed: %w", addr, err)
	}

	// PipeConnection returns the connection open for an interactive session.
	// Clear any deadline PerformStarttls set for the STARTTLS exchange so reads
	// and writes are not killed ~timeout seconds after connecting.
	tcpConn.SetDeadline(time.Time{})

	state := tlsConn.ConnectionState()
	info := &TLSConnectionInfo{
		Version:           state.Version,
		VersionName:       TLSVersionName(state.Version),
		CipherSuite:       state.CipherSuite,
		CipherSuiteName:   tls.CipherSuiteName(state.CipherSuite),
		ServerName:        state.ServerName,
		NegotiatedProto:   state.NegotiatedProtocol,
		ALPNOffered:       tlsConfig.NextProtos,
		PeerCertificates:  state.PeerCertificates,
		OCSPStapled:       len(state.OCSPResponse) > 0,
		OCSPResponse:      state.OCSPResponse,
		HandshakeComplete: state.HandshakeComplete,
		ConnectedAt:       time.Now(),
		RemoteAddr:        addr,
		Timing:            timing,
	}

	return tlsConn, info, nil
}

// FetchResultToStore converts fetch results into a CertStore for display/checking.
func FetchResultToStore(results []FetchResult) *CertStore {
	store := NewCertStore()

	for _, fr := range results {
		if fr.Error != nil || len(fr.Certificates) == 0 {
			continue
		}

		container := CertContainer{
			FilePath: fr.Target.Address(),
			Format:   FormatPEM,
			Source:   SourceRemote,
		}

		for _, cert := range fr.Certificates {
			container.Items = append(container.Items, CertItem{
				Type:        ContentCertificate,
				RawBytes:    cert.Raw,
				Certificate: cert,
			})
		}

		// Add AIA-fetched certs
		for _, cert := range fr.AIACerts {
			container.Items = append(container.Items, CertItem{
				Type:        ContentCertificate,
				RawBytes:    cert.Raw,
				Certificate: cert,
			})
		}

		store.AddContainer(container)
	}

	return store
}

// compareChains returns true only when at least two successful results were
// compared and all of them have identical cert chains.
func compareChains(results []FetchResult) bool {
	var firstChain []*x509.Certificate
	successCount := 0
	for _, r := range results {
		if r.Error != nil {
			continue
		}
		successCount++
		if firstChain == nil {
			firstChain = r.Certificates
			continue
		}
		if !chainsEqual(firstChain, r.Certificates) {
			return false
		}
	}
	return successCount >= 2
}

func chainsEqual(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}

// dialWithProxy establishes a TCP connection through a proxy.
func dialWithProxy(ctx context.Context, proxyURL string, addr string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	switch u.Scheme {
	case "socks5":
		return dialSOCKS5(ctx, u, addr, timeout)
	case "http":
		return dialHTTPConnect(ctx, u, addr, timeout)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5:// or http://)", u.Scheme)
	}
}

func dialSOCKS5(ctx context.Context, proxyURL *url.URL, addr string, timeout time.Duration) (net.Conn, error) {
	// SOCKS5 proxy connection: connect to proxy, then request tunnel to addr.
	// Using manual SOCKS5 implementation to avoid x/net/proxy dependency for now.
	// Will be replaced with golang.org/x/net/proxy in M17.2 if needed.
	dialer := &net.Dialer{Timeout: timeout}
	proxyAddr := proxyURL.Host
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	// Bound the handshake with the caller's timeout so a stalled proxy cannot hang.
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 handshake
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	// Auth methods: no auth
	authReq := []byte{0x05, 0x01, 0x00}
	if proxyURL.User != nil {
		authReq = []byte{0x05, 0x02, 0x00, 0x02} // no auth + username/password
	}
	if _, err := conn.Write(authReq); err != nil {
		conn.Close()
		return nil, err
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		conn.Close()
		return nil, err
	}

	if authResp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 proxy returned invalid version: %d", authResp[0])
	}

	// Handle username/password auth if required
	if authResp[1] == 0x02 && proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := []byte{0x01, byte(len(username))}
		auth = append(auth, []byte(username)...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, []byte(password)...)
		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			return nil, err
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, err
		}
		if resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 proxy authentication failed")
		}
	} else if authResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 proxy requires unsupported auth method: %d", authResp[1])
	}

	// Connect request
	connectReq := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			connectReq = append(connectReq, 0x01)
			connectReq = append(connectReq, v4...)
		} else {
			connectReq = append(connectReq, 0x04)
			connectReq = append(connectReq, ip.To16()...)
		}
	} else {
		connectReq = append(connectReq, 0x03, byte(len(host)))
		connectReq = append(connectReq, []byte(host)...)
	}
	connectReq = append(connectReq, byte(port>>8), byte(port))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, err
	}

	connectResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		conn.Close()
		return nil, err
	}

	if connectResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect to %s failed with code %d", addr, connectResp[1])
	}

	// Read remaining bind-address bytes (we don't need them but must consume)
	switch connectResp[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			conn.Close()
			return nil, err
		}
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenBuf[0])+2)); err != nil {
			conn.Close()
			return nil, err
		}
	}

	// Clear the handshake deadline; the caller manages deadlines for the tunnel.
	conn.SetDeadline(time.Time{})

	return conn, nil
}

func dialHTTPConnect(ctx context.Context, proxyURL *url.URL, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	proxyAddr := proxyURL.Host
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to HTTP proxy %s: %w", proxyAddr, err)
	}

	// Bound the handshake with the caller's timeout so a stalled proxy cannot hang.
	conn.SetDeadline(time.Now().Add(timeout))

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("HTTP CONNECT proxy returned: %s", resp.Status)
	}
	resp.Body.Close()

	// Clear the handshake deadline; the caller manages deadlines for the tunnel.
	conn.SetDeadline(time.Time{})

	return conn, nil
}
