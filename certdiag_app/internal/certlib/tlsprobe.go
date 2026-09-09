package certlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	ssl3tls "github.com/runZeroInc/excrypto/crypto/ssl3/tls"
)

const probeConnTimeout = 5 * time.Second

func dialProbe(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}

// CipherClassification categorizes cipher strength.
type CipherClassification string

const (
	CipherRecommended CipherClassification = "recommended"
	CipherAcceptable  CipherClassification = "acceptable"
	CipherWeak        CipherClassification = "weak"
	CipherInsecure    CipherClassification = "insecure"
)

// ProbeServer performs a comprehensive TLS probe against a target.
func ProbeServer(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, ipv4Only, ipv6Only bool) (ProbeResult, error) {
	if timeout == 0 {
		timeout = probeConnTimeout
	}
	start := time.Now()

	if !target.IsIP && (ipv4Only || ipv6Only) {
		ips, err := resolveHost(ctx, target, TLSDialOptions{IPv4Only: ipv4Only, IPv6Only: ipv6Only}, &ConnectionTiming{})
		if err != nil {
			return ProbeResult{Target: target, Duration: time.Since(start)}, err
		}
		ip := ips[0]
		target.Host = ip
		target.IsIP = true
		target.IsIPv6 = net.ParseIP(ip).To4() == nil
	}

	result := ProbeResult{Target: target}

	// Probe TLS versions
	result.Versions = probeVersions(ctx, target, starttls, timeout)

	if err := ctx.Err(); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	// Check if all version probes failed — indicates a connection-level problem
	if err := diagnoseProbeFailure(result.Versions); err != nil {
		result.Duration = time.Since(start)
		return result, err
	}

	// Probe cipher suites for supported versions
	for _, vr := range result.Versions {
		if !vr.Supported {
			continue
		}
		ciphers := probeCiphers(ctx, target, starttls, timeout, vr.Version)
		result.CipherSuites = append(result.CipherSuites, ciphers...)
	}

	// Probe features from a standard connection
	probeFeatures(ctx, target, starttls, timeout, &result)

	// Detect cipher preference
	result.CipherPreference = detectCipherPreference(ctx, target, starttls, timeout)

	result.Duration = time.Since(start)

	return result, nil
}

func diagnoseProbeFailure(versions []ProbeVersionResult) error {
	anySupported := false
	for _, v := range versions {
		if v.Supported {
			anySupported = true
			break
		}
	}
	if anySupported {
		return nil
	}

	// All versions failed — collect all errors and pick the most specific diagnosis.
	// Priority: not-TLS > connection-refused > unreachable > timeout
	var hasNotTLS, hasRefused, hasUnreachable, hasTimeout bool
	for _, v := range versions {
		if v.Error == "" {
			continue
		}
		switch {
		case strings.Contains(v.Error, "first record does not look like a TLS handshake"):
			hasNotTLS = true
		case strings.Contains(v.Error, "connection refused"):
			hasRefused = true
		case strings.Contains(v.Error, "no route to host") || strings.Contains(v.Error, "network is unreachable"):
			hasUnreachable = true
		case strings.Contains(v.Error, "i/o timeout") || strings.Contains(v.Error, "deadline exceeded"):
			hasTimeout = true
		}
	}

	switch {
	case hasNotTLS:
		return fmt.Errorf("not a TLS port (received plaintext response); if this is a STARTTLS service, use --starttls")
	case hasRefused:
		return fmt.Errorf("connection refused")
	case hasUnreachable:
		return fmt.Errorf("host unreachable")
	case hasTimeout:
		return fmt.Errorf("connection timed out")
	}

	return nil
}

func probeVersions(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration) []ProbeVersionResult {
	versions := []struct {
		version uint16
		name    string
	}{
		{0x0300, "SSLv3"},
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	results := make([]ProbeVersionResult, len(versions))
	for i, v := range versions {
		results[i] = ProbeVersionResult{
			Version:     v.version,
			VersionName: v.name,
		}

		var cipher string
		var err error

		if v.version == 0x0300 {
			cipher, err = probeSSLv3(ctx, target, starttls, timeout)
		} else {
			cipher, err = probeStdlibVersion(ctx, target, starttls, timeout, v.version)
		}

		if err != nil {
			results[i].Error = err.Error()
		} else {
			results[i].Supported = true
			results[i].CipherSuite = cipher
		}
	}

	return results
}

func probeStdlibVersion(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, version uint16) (string, error) {
	addr := target.Address()
	conn, err := dialProbe(ctx, addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if starttls != StarttlsNone {
		if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
			return "", err
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
		ServerName:         target.SNI,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	return tls.CipherSuiteName(state.CipherSuite), nil
}

func probeSSLv3(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration) (string, error) {
	addr := target.Address()
	conn, err := dialProbe(ctx, addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if starttls != StarttlsNone {
		if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
			return "", err
		}
	}

	config := &ssl3tls.Config{
		MinVersion:         ssl3tls.VersionSSL30,
		MaxVersion:         ssl3tls.VersionSSL30,
		InsecureSkipVerify: true,
		ServerName:         target.SNI,
	}

	tlsConn := ssl3tls.Client(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return "", err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	return sslv3CipherName(state.CipherSuite), nil
}

func probeCiphers(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, version uint16) []ProbeCipherResult {
	switch version {
	case 0x0300:
		return probeSSLv3Ciphers(ctx, target, starttls, timeout)
	case tls.VersionTLS13:
		return probeTLS13Ciphers(ctx, target, starttls, timeout)
	default:
		return probeStdlibCiphers(ctx, target, starttls, timeout, version)
	}
}

func probeStdlibCiphers(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, version uint16) []ProbeCipherResult {
	var allCiphers []*tls.CipherSuite
	allCiphers = append(allCiphers, tls.CipherSuites()...)
	allCiphers = append(allCiphers, tls.InsecureCipherSuites()...)

	var results []ProbeCipherResult
	versionName := TLSVersionName(version)

	for _, cs := range allCiphers {
		// Skip ciphers not valid for this TLS version
		validForVersion := false
		for _, sv := range cs.SupportedVersions {
			if sv == version {
				validForVersion = true
				break
			}
		}
		if !validForVersion {
			continue
		}

		result := ProbeCipherResult{
			CipherSuite:     cs.ID,
			CipherSuiteName: cs.Name,
			TLSVersion:      versionName,
		}

		addr := target.Address()
		conn, err := dialProbe(ctx, addr, timeout)
		if err != nil {
			results = append(results, result)
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))

		if starttls != StarttlsNone {
			if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
				conn.Close()
				results = append(results, result)
				continue
			}
		}

		tlsConfig := &tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       []uint16{cs.ID},
			InsecureSkipVerify: true,
			ServerName:         target.SNI,
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err == nil {
			result.Supported = true
			tlsConn.Close()
		}
		conn.Close()

		results = append(results, result)
	}

	return results
}

func probeTLS13Ciphers(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration) []ProbeCipherResult {
	tls13Ciphers := []struct {
		id   uint16
		name string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
	}

	var results []ProbeCipherResult

	for _, cs := range tls13Ciphers {
		result := ProbeCipherResult{
			CipherSuite:     cs.id,
			CipherSuiteName: cs.name,
			TLSVersion:      "TLS 1.3",
		}

		addr := target.Address()
		conn, err := dialProbe(ctx, addr, timeout)
		if err != nil {
			results = append(results, result)
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))

		if starttls != StarttlsNone {
			if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
				conn.Close()
				results = append(results, result)
				continue
			}
		}

		uConn := utls.UClient(conn, &utls.Config{
			ServerName:         target.SNI,
			InsecureSkipVerify: true,
		}, utls.HelloCustom)

		spec := &utls.ClientHelloSpec{
			TLSVersMin:   utls.VersionTLS13,
			TLSVersMax:   utls.VersionTLS13,
			CipherSuites: []uint16{cs.id},
			Extensions: []utls.TLSExtension{
				&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
				&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
				&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
				&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
					{Group: utls.X25519},
				}},
				&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.PSSWithSHA256,
					utls.PKCS1WithSHA256,
				}},
				&utls.SNIExtension{ServerName: target.SNI},
			},
		}

		if err := uConn.ApplyPreset(spec); err != nil {
			conn.Close()
			results = append(results, result)
			continue
		}

		if err := uConn.Handshake(); err == nil {
			result.Supported = true
			uConn.Close()
		}
		conn.Close()

		results = append(results, result)
	}

	return results
}

func probeSSLv3Ciphers(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration) []ProbeCipherResult {
	sslv3CipherIDs := []uint16{
		0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x0004, // TLS_RSA_WITH_RC4_128_MD5
	}

	var results []ProbeCipherResult

	for _, id := range sslv3CipherIDs {
		result := ProbeCipherResult{
			CipherSuite:     id,
			CipherSuiteName: sslv3CipherName(id),
			TLSVersion:      "SSLv3",
		}

		addr := target.Address()
		conn, err := dialProbe(ctx, addr, timeout)
		if err != nil {
			results = append(results, result)
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))

		if starttls != StarttlsNone {
			if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
				conn.Close()
				results = append(results, result)
				continue
			}
		}

		config := &ssl3tls.Config{
			MinVersion:         ssl3tls.VersionSSL30,
			MaxVersion:         ssl3tls.VersionSSL30,
			CipherSuites:       []uint16{id},
			InsecureSkipVerify: true,
			ServerName:         target.SNI,
		}

		tlsConn := ssl3tls.Client(conn, config)
		if err := tlsConn.Handshake(); err == nil {
			result.Supported = true
			tlsConn.Close()
		}
		conn.Close()

		results = append(results, result)
	}

	return results
}

func probeFeatures(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, result *ProbeResult) {
	addr := target.Address()
	conn, err := dialProbe(ctx, addr, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	if remoteAddr := conn.RemoteAddr(); remoteAddr != nil {
		host, _, err := net.SplitHostPort(remoteAddr.String())
		if err == nil {
			result.ResolvedAddr = host
		}
	}

	conn.SetDeadline(time.Now().Add(timeout))

	if starttls != StarttlsNone {
		if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
			return
		}
	}

	// The feature probe goes through utls with an explicit ClientHello so the
	// ServerHello is readable: crypto/tls never exposes the renegotiation_info
	// extension or the compression method, and a value that is not measured
	// is not reported (M31 H4).
	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         target.SNI,
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := uConn.ApplyPreset(featureProbeSpec(target.SNI)); err != nil {
		return
	}
	if err := uConn.Handshake(); err != nil {
		return
	}
	defer uConn.Close()

	state := uConn.ConnectionState()
	result.FeaturesTLSVersion = state.Version

	if state.NegotiatedProtocol != "" {
		result.ALPNProtocols = append(result.ALPNProtocols, state.NegotiatedProtocol)
	}

	result.OCSPStapled = len(state.OCSPResponse) > 0

	if sh := uConn.HandshakeState.ServerHello; sh != nil {
		compression := sh.CompressionMethod != 0
		result.Compression = &compression
		// TLS 1.3 has no renegotiation at all, so the extension's absence
		// says nothing there; the renderer reports "not applicable".
		if state.Version < tls.VersionTLS13 {
			reneg := sh.SecureRenegotiationSupported
			result.SecureRenegotiation = &reneg
		}
	}
}

// featureProbeSpec is the ClientHello of a current browser-class client:
// TLS 1.2 and 1.3, the AEAD suites, renegotiation_info, status_request and
// the HTTP ALPN identifiers. Everything the feature report claims is read
// from the server's answer to this hello.
func featureProbeSpec(sni string) *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.StatusRequestExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		},
	}
}

func detectCipherPreference(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration) string {
	// Candidate AEAD suites spanning both the RSA and ECDSA families so the
	// probe works regardless of the server certificate's key type.
	candidates := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	// Determine which candidates the server actually supports.
	var supported []uint16
	for _, c := range candidates {
		if tryWithCiphers(ctx, target, starttls, timeout, []uint16{c}) != 0 {
			supported = append(supported, c)
		}
	}

	// Need at least two mutually-supported ciphers to infer ordering.
	if len(supported) < 2 {
		return "unknown"
	}

	forward := []uint16{supported[0], supported[1]}
	reversed := []uint16{supported[1], supported[0]}

	c1 := tryWithCiphers(ctx, target, starttls, timeout, forward)
	c2 := tryWithCiphers(ctx, target, starttls, timeout, reversed)

	if c1 == 0 || c2 == 0 {
		return "unknown"
	}

	if c1 == c2 {
		return "server"
	}
	return "client"
}

func tryWithCiphers(ctx context.Context, target RemoteTarget, starttls StarttlsProtocol, timeout time.Duration, ciphers []uint16) uint16 {
	addr := target.Address()
	conn, err := dialProbe(ctx, addr, timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if starttls != StarttlsNone {
		if err := PerformStarttls(conn, starttls, target.SNI, time.Now().Add(timeout)); err != nil {
			return 0
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       ciphers,
		InsecureSkipVerify: true,
		ServerName:         target.SNI,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return 0
	}
	defer tlsConn.Close()

	return tlsConn.ConnectionState().CipherSuite
}

// ClassifyCipher categorizes a cipher suite by security level. The key
// exchange is judged before the record protection: a static-RSA suite has no
// forward secrecy however good its AEAD is, so it can never be recommended.
func ClassifyCipher(name string) CipherClassification {
	upper := strings.ToUpper(name)

	// Insecure: no or broken confidentiality, or no authentication at all
	if strings.Contains(upper, "NULL") ||
		strings.Contains(upper, "EXPORT") ||
		strings.Contains(upper, "RC4") ||
		strings.Contains(upper, "DES_CBC_") ||
		strings.Contains(upper, "RC2") ||
		strings.Contains(upper, "3DES") || strings.Contains(upper, "DES_CBC3") ||
		strings.Contains(upper, "_ANON_") {
		return CipherInsecure
	}

	aead := strings.Contains(upper, "GCM") || strings.Contains(upper, "CHACHA20") || strings.Contains(upper, "CCM")

	// Static RSA key exchange: no forward secrecy. Acceptable at best.
	if strings.HasPrefix(upper, "TLS_RSA_") {
		if aead {
			return CipherAcceptable
		}
		return CipherWeak
	}

	if aead {
		return CipherRecommended
	}

	// CBC with an ephemeral key exchange: weak with a SHA-1 MAC, else acceptable
	if strings.Contains(upper, "CBC") && strings.HasSuffix(upper, "_SHA") {
		return CipherWeak
	}
	return CipherAcceptable
}

func sslv3CipherName(id uint16) string {
	names := map[uint16]string{
		0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x0004: "TLS_RSA_WITH_RC4_128_MD5",
		0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
		0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}
