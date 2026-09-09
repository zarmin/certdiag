package certops

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type FetchRemoteCertOptions struct {
	// ALPN is offered in the ClientHello; nil means DefaultALPN (h2, http/1.1),
	// an empty slice offers nothing.
	ALPN        []string
	Targets     []string
	TLSVersion  string
	Hostname    string
	DisableSNI  bool
	Starttls    string
	Timeout     time.Duration
	IPv4Only    bool
	IPv6Only    bool
	SingleIP    bool
	ProxyURL    string
	Parallel    int
	ExpiryWarn  int
	ClientCerts []tls.Certificate
}

type FetchRemoteCertResult struct {
	TargetResults []TargetFetchResult
	Summary       FetchSummary
}

type TargetFetchResult struct {
	Target string
	// TLSInfo is the raw handshake detail, kept so the checks can run later
	// without dialing again. Not part of the published schema.
	TLSInfo    *certlib.TLSConnectionInfo `json:"-" yaml:"-"`
	Connection *RemoteConnectionInfo
	Certs      []RemoteCertInfo
	MultiIP    *MultiIPInfo
	ExpiryWarn *ExpiryWarnInfo
	Error      string
}

type RemoteConnectionInfo struct {
	TLSVersion    string
	CipherSuite   string
	ALPN          string
	SNI           string
	RemoteAddress string
	LatencyMs     int64
	OCSPStapled   bool
	Timing        *RemoteTimingInfo
}

type RemoteTimingInfo struct {
	DNSMs   int64
	TCPMs   int64
	TLSMs   int64
	TotalMs int64
}

type RemoteCertInfo struct {
	Index  int
	Role   string
	Cert   *certlib.CertItem
	RawDER []byte
}

type MultiIPInfo struct {
	ResolvedIPs  []string
	AllIdentical bool
}

type ExpiryWarnInfo struct {
	ExpiringCerts []ExpiringCert
	HasExpired    bool
	HasWarning    bool
}

type ExpiringCert struct {
	Subject  string
	NotAfter time.Time
	Expired  bool
}

type FetchSummary struct {
	Total     int
	Succeeded int
	Failed    int
}

func FetchRemoteCert(opts FetchRemoteCertOptions) (*FetchRemoteCertResult, error) {
	if len(opts.Targets) == 0 {
		return nil, &OperationError{Op: "remote-fetch", Message: "no targets specified"}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	starttls, err := certlib.ParseStarttlsProtocol(opts.Starttls)
	if err != nil {
		return nil, &OperationError{Op: "remote-fetch", Message: err.Error()}
	}

	var forcedVersion uint16
	if opts.TLSVersion != "" {
		v, err := certlib.TLSVersionFromString(opts.TLSVersion)
		if err != nil {
			return nil, &OperationError{Op: "remote-fetch", Message: err.Error()}
		}
		forcedVersion = v
	}

	dialOpts := certlib.TLSDialOptions{
		ForcedVersion: forcedVersion,
		ServerName:    opts.Hostname,
		DisableSNI:    opts.DisableSNI,
		Timeout:       opts.Timeout,
		IPv4Only:      opts.IPv4Only,
		IPv6Only:      opts.IPv6Only,
		SingleIP:      opts.SingleIP,
		Starttls:      starttls,
		ProxyURL:      opts.ProxyURL,
		ClientCerts:   opts.ClientCerts,
		ALPN:          alpnOrDefault(opts.ALPN),
	}

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
	}

	result := &FetchRemoteCertResult{
		TargetResults: make([]TargetFetchResult, len(opts.Targets)),
	}
	result.Summary.Total = len(opts.Targets)

	if parallel == 1 || len(opts.Targets) == 1 {
		for i, rawTarget := range opts.Targets {
			result.TargetResults[i] = fetchSingleTarget(rawTarget, dialOpts, opts.ExpiryWarn)
		}
	} else {
		sem := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		for i, rawTarget := range opts.Targets {
			wg.Add(1)
			go func(idx int, target string) {
				defer wg.Done()
				sem <- struct{}{}
				result.TargetResults[idx] = fetchSingleTarget(target, dialOpts, opts.ExpiryWarn)
				<-sem
			}(i, rawTarget)
		}
		wg.Wait()
	}

	for _, tr := range result.TargetResults {
		if tr.Error == "" {
			result.Summary.Succeeded++
		} else {
			result.Summary.Failed++
		}
	}

	return result, nil
}

func fetchSingleTarget(rawTarget string, dialOpts certlib.TLSDialOptions, expiryWarnDays int) TargetFetchResult {
	target, err := certlib.ParseTarget(rawTarget)
	if err != nil {
		return TargetFetchResult{
			Target: rawTarget,
			Error:  err.Error(),
		}
	}

	// Apply STARTTLS default port if user didn't specify one
	if dialOpts.Starttls != certlib.StarttlsNone && target.Port == 443 {
		if !strings.Contains(rawTarget, ":") || strings.HasPrefix(rawTarget, "https://") || strings.HasPrefix(rawTarget, "tls://") {
			target.Port = certlib.DefaultStarttlsPort(dialOpts.Starttls)
		}
	}

	// Use multi-IP by default
	multiResult, err := certlib.DialTLSMultiIP(target, dialOpts)
	if err != nil {
		return TargetFetchResult{
			Target: target.Address(),
			Error:  err.Error(),
		}
	}

	if len(multiResult.Results) == 0 {
		return TargetFetchResult{
			Target: target.Address(),
			Error:  "no results from connection",
		}
	}

	// Use first successful result for display
	var primaryResult *certlib.FetchResult
	for i := range multiResult.Results {
		if multiResult.Results[i].Error == nil {
			primaryResult = &multiResult.Results[i]
			break
		}
	}

	if primaryResult == nil {
		return TargetFetchResult{
			Target: target.Address(),
			Error:  multiResult.Results[0].Error.Error(),
		}
	}

	tlsInfo := primaryResult.TLSInfo
	tr := TargetFetchResult{
		Target:  target.Address(),
		TLSInfo: &tlsInfo,
	}

	// Connection info
	timing := primaryResult.TLSInfo.Timing
	tr.Connection = &RemoteConnectionInfo{
		TLSVersion:    primaryResult.TLSInfo.VersionName,
		CipherSuite:   primaryResult.TLSInfo.CipherSuiteName,
		ALPN:          primaryResult.TLSInfo.NegotiatedProto,
		SNI:           primaryResult.TLSInfo.ServerName,
		RemoteAddress: primaryResult.TLSInfo.RemoteAddr,
		LatencyMs:     timing.TotalDuration.Milliseconds(),
		OCSPStapled:   primaryResult.TLSInfo.OCSPStapled,
		Timing: &RemoteTimingInfo{
			DNSMs:   timing.DNSDuration.Milliseconds(),
			TCPMs:   timing.TCPDuration.Milliseconds(),
			TLSMs:   timing.TLSDuration.Milliseconds(),
			TotalMs: timing.TotalDuration.Milliseconds(),
		},
	}

	// Certs
	for i, cert := range primaryResult.Certificates {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		}
		if cert.IsCA && certlib.IsSelfSigned(cert) {
			role = "root"
		}

		tr.Certs = append(tr.Certs, RemoteCertInfo{
			Index:  i + 1,
			Role:   role,
			Cert:   &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw},
			RawDER: cert.Raw,
		})
	}

	// Multi-IP info
	if len(multiResult.ResolvedIPs) > 1 {
		tr.MultiIP = &MultiIPInfo{
			ResolvedIPs:  multiResult.ResolvedIPs,
			AllIdentical: multiResult.AllIdentical,
		}
	}

	// Expiry warnings
	if expiryWarnDays > 0 {
		tr.ExpiryWarn = checkExpiry(primaryResult.Certificates, expiryWarnDays)
	}

	return tr
}

func checkExpiry(certs []*x509.Certificate, expiryWarnDays int) *ExpiryWarnInfo {
	now := time.Now()
	warnThreshold := now.Add(time.Duration(expiryWarnDays) * 24 * time.Hour)

	info := &ExpiryWarnInfo{}
	for _, cert := range certs {
		if cert.NotAfter.Before(now) {
			info.ExpiringCerts = append(info.ExpiringCerts, ExpiringCert{
				Subject:  cert.Subject.CommonName,
				NotAfter: cert.NotAfter,
				Expired:  true,
			})
			info.HasExpired = true
		} else if cert.NotAfter.Before(warnThreshold) {
			info.ExpiringCerts = append(info.ExpiringCerts, ExpiringCert{
				Subject:  cert.Subject.CommonName,
				NotAfter: cert.NotAfter,
				Expired:  false,
			})
			info.HasWarning = true
		}
	}
	return info
}

// alpnOrDefault applies the HTTPS default when the caller expressed no
// preference. An explicit empty list stays empty (offer nothing).
func alpnOrDefault(alpn []string) []string {
	if alpn == nil {
		return certlib.DefaultALPN
	}
	return alpn
}
