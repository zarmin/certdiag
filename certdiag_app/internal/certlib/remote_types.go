package certlib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// RemoteTarget represents a parsed remote connection target.
type RemoteTarget struct {
	Original string
	Host     string
	Port     int
	SNI      string
	IsIP     bool
	IsIPv6   bool
	URLPath  string
	Scheme   string
}

// Address returns host:port as a string suitable for dialing.
func (t RemoteTarget) Address() string {
	if t.IsIPv6 {
		return fmt.Sprintf("[%s]:%d", t.Host, t.Port)
	}
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// StarttlsProtocol identifies a STARTTLS application protocol.
type StarttlsProtocol string

const (
	StarttlsNone     StarttlsProtocol = ""
	StarttlsSMTP     StarttlsProtocol = "smtp"
	StarttlsIMAP     StarttlsProtocol = "imap"
	StarttlsPOP3     StarttlsProtocol = "pop3"
	StarttlsFTP      StarttlsProtocol = "ftp"
	StarttlsLDAP     StarttlsProtocol = "ldap"
	StarttlsMySQL    StarttlsProtocol = "mysql"
	StarttlsPostgres StarttlsProtocol = "postgres"
)

// DefaultStarttlsPort returns the standard port for each STARTTLS protocol.
func DefaultStarttlsPort(proto StarttlsProtocol) int {
	switch proto {
	case StarttlsSMTP:
		return 587
	case StarttlsIMAP:
		return 143
	case StarttlsPOP3:
		return 110
	case StarttlsFTP:
		return 21
	case StarttlsLDAP:
		return 389
	case StarttlsMySQL:
		return 3306
	case StarttlsPostgres:
		return 5432
	default:
		return 443
	}
}

// ParseStarttlsProtocol converts a string to StarttlsProtocol.
func ParseStarttlsProtocol(s string) (StarttlsProtocol, error) {
	switch s {
	case "", "none":
		return StarttlsNone, nil
	case "smtp":
		return StarttlsSMTP, nil
	case "imap":
		return StarttlsIMAP, nil
	case "pop3":
		return StarttlsPOP3, nil
	case "ftp":
		return StarttlsFTP, nil
	case "ldap":
		return StarttlsLDAP, nil
	case "mysql":
		return StarttlsMySQL, nil
	case "postgres":
		return StarttlsPostgres, nil
	default:
		return StarttlsNone, fmt.Errorf("unknown STARTTLS protocol: %q", s)
	}
}

// ConnectionTiming holds timing measurements for each connection phase.
type ConnectionTiming struct {
	DNSStart      time.Time
	DNSDone       time.Time
	TCPStart      time.Time
	TCPDone       time.Time
	TLSStart      time.Time
	TLSDone       time.Time
	DNSDuration   time.Duration
	TCPDuration   time.Duration
	TLSDuration   time.Duration
	TotalDuration time.Duration
}

// TLSFingerprint holds JA3/JA4 client fingerprint info.
type TLSFingerprint struct {
	JA3     string
	JA3Full string
	JA4     string
}

// TLSConnectionInfo holds metadata about an established TLS connection.
type TLSConnectionInfo struct {
	Version         uint16
	VersionName     string
	CipherSuite     uint16
	CipherSuiteName string
	ServerName      string
	NegotiatedProto string
	// ALPNOffered is what the ClientHello offered; empty means the question
	// was never asked, and the ALPN checks stay quiet.
	ALPNOffered       []string
	PeerCertificates  []*x509.Certificate
	OCSPStapled       bool
	OCSPResponse      []byte
	HandshakeComplete bool
	ConnectedAt       time.Time
	RemoteAddr        string
	Timing            ConnectionTiming
	Fingerprint       TLSFingerprint
}

// TLSVersionName returns a human-readable TLS version name.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// TLSDialOptions configures the TLS connection.
type TLSDialOptions struct {
	MinVersion         uint16
	MaxVersion         uint16
	ForcedVersion      uint16
	ServerName         string
	DisableSNI         bool
	InsecureSkipVerify bool
	Timeout            time.Duration
	IPv4Only           bool
	IPv6Only           bool
	ClientCerts        []tls.Certificate
	Starttls           StarttlsProtocol
	ProxyURL           string
	SingleIP           bool
	// ALPN is the protocol list offered in the ClientHello. nil offers
	// nothing; an empty, non-nil slice also offers nothing. Callers that
	// speak HTTPS pass DefaultALPN (or the user's --alpn) explicitly.
	ALPN []string
}

// DefaultALPN is what an HTTPS client offers; fetch and check use it unless
// the user chose otherwise, so remote_no_alpn describes the server and not
// the probe.
var DefaultALPN = []string{"h2", "http/1.1"}

// FetchResult holds the result of fetching certs from a remote target.
type FetchResult struct {
	Target       RemoteTarget
	TLSInfo      TLSConnectionInfo
	Certificates []*x509.Certificate
	AIACerts     []*x509.Certificate
	ChainPEM     []byte
	Error        error
}

// MultiIPResult holds results for a hostname that resolved to multiple IPs.
type MultiIPResult struct {
	Target       RemoteTarget
	ResolvedIPs  []string
	Results      []FetchResult
	AllIdentical bool
}

// MaxMultiIP is the maximum number of IPs to probe per target.
const MaxMultiIP = 10

// ProbeVersionResult holds the result of probing a single TLS version.
type ProbeVersionResult struct {
	Version     uint16
	VersionName string
	Supported   bool
	CipherSuite string
	Error       string
}

// ProbeCipherResult holds the result of probing a single cipher suite.
type ProbeCipherResult struct {
	CipherSuite     uint16
	CipherSuiteName string
	TLSVersion      string
	Supported       bool
}

// ProbeResult holds the full TLS probe results.
type ProbeResult struct {
	Target           RemoteTarget
	ResolvedAddr     string
	Versions         []ProbeVersionResult
	CipherSuites     []ProbeCipherResult
	CipherPreference string
	OCSPStapled      bool
	ALPNProtocols    []string
	// FeaturesTLSVersion is the version the feature connection negotiated.
	FeaturesTLSVersion uint16
	// Compression and SecureRenegotiation are read from the ServerHello. Nil
	// means the feature connection did not complete, so nothing was measured;
	// the renderers say so instead of printing a default.
	Compression         *bool
	SecureRenegotiation *bool
	Duration            time.Duration
}

// HTTPResponse holds a simple HTTP response.
type HTTPResponse struct {
	StatusCode      int
	StatusLine      string
	Headers         http.Header
	Body            []byte
	BodyTruncated   bool
	TLSInfo         TLSConnectionInfo
	RedirectChain   []HTTPRedirect
	SecurityHeaders SecurityHeaders
	Latency         time.Duration
}

// HTTPRedirect represents one redirect hop.
type HTTPRedirect struct {
	FromURL    string
	ToURL      string
	StatusCode int
}

// SecurityHeaders holds parsed security-relevant HTTP headers.
type SecurityHeaders struct {
	HSTS                  *HSTSHeader
	ContentSecurityPolicy string
	XContentTypeOptions   string
	XFrameOptions         string
	ReferrerPolicy        string
	PermissionsPolicy     string
}

// HSTSHeader holds parsed Strict-Transport-Security values.
type HSTSHeader struct {
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
	RawValue          string
}
