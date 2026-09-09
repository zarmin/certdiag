package certops

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type CheckRemoteOptions struct {
	Targets            []string
	TLSVersion         string
	Hostname           string
	DisableSNI         bool
	Starttls           string
	Timeout            time.Duration
	IPv4Only           bool
	IPv6Only           bool
	SingleIP           bool
	ProxyURL           string
	Parallel           int
	ClientCerts        []tls.Certificate
	ExpiryWarnDays     int
	ExpiryCriticalDays int
	MinSeverity        certlib.CheckSeverity
	Categories         []string
	DisabledChecks     []string
	NoAIA              bool
	Revocation         RevocationConfig
	// ALPN as in FetchRemoteCertOptions.
	ALPN []string
	// StoreLoad is the store-read seam for the anchor pool; the zero value
	// reads the machine, tests set Readers and NoRealReads.
	StoreLoad StoreLoadAllOptions
}

type CheckRemoteResult struct {
	TargetResults []TargetCheckResult
	Summary       CheckRemoteSummary
}

type TargetCheckResult struct {
	Target     string
	Connection *RemoteConnectionInfo
	Certs      []RemoteCertInfo
	Issues     []certlib.CheckIssue
	Summary    certlib.CheckSummary
	Error      string
	// StoreVerdicts holds one verdict per selected trust store, filled by the
	// command layer when --trust or a store flag was given.
	StoreVerdicts []RemoteStoreVerdict
}

type CheckRemoteSummary struct {
	Total     int
	Succeeded int
	Failed    int
	Critical  int
	Warning   int
	Info      int
}

func CheckRemote(opts CheckRemoteOptions) (*CheckRemoteResult, error) {
	if len(opts.Targets) == 0 {
		return nil, &OperationError{Op: "remote-check", Message: "no targets specified"}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	starttls, err := certlib.ParseStarttlsProtocol(opts.Starttls)
	if err != nil {
		return nil, &OperationError{Op: "remote-check", Message: err.Error()}
	}

	var forcedVersion uint16
	if opts.TLSVersion != "" {
		v, err := certlib.TLSVersionFromString(opts.TLSVersion)
		if err != nil {
			return nil, &OperationError{Op: "remote-check", Message: err.Error()}
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

	checkOpts := certlib.CheckOptions{
		ExpiryWarnDays:     opts.ExpiryWarnDays,
		ExpiryCriticalDays: opts.ExpiryCriticalDays,
		MinSeverity:        opts.MinSeverity,
		Categories:         opts.Categories,
		DisabledChecks:     opts.DisabledChecks,
	}

	// The OS anchor pool is read once for the whole run, never per target:
	// N targets in parallel used to mean N concurrent keychain and JDK reads.
	stores := osStores(opts.StoreLoad)
	roots := OSAnchorPool(stores)

	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 1
	}

	result := &CheckRemoteResult{
		TargetResults: make([]TargetCheckResult, len(opts.Targets)),
	}
	result.Summary.Total = len(opts.Targets)

	if parallel == 1 || len(opts.Targets) == 1 {
		for i, rawTarget := range opts.Targets {
			result.TargetResults[i] = checkSingleTarget(rawTarget, dialOpts, checkOpts, opts.NoAIA, opts.Revocation, roots, stores)
		}
	} else {
		sem := make(chan struct{}, parallel)
		var wg sync.WaitGroup
		for i, rawTarget := range opts.Targets {
			wg.Add(1)
			go func(idx int, target string) {
				defer wg.Done()
				sem <- struct{}{}
				result.TargetResults[idx] = checkSingleTarget(target, dialOpts, checkOpts, opts.NoAIA, opts.Revocation, roots, stores)
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
		result.Summary.Critical += tr.Summary.Critical
		result.Summary.Warning += tr.Summary.Warning
		result.Summary.Info += tr.Summary.Info
	}

	return result, nil
}

func checkSingleTarget(rawTarget string, dialOpts certlib.TLSDialOptions, checkOpts certlib.CheckOptions, noAIA bool, revCfg RevocationConfig, roots *x509.CertPool, stores []truststore.StoreContents) TargetCheckResult {
	target, err := certlib.ParseTarget(rawTarget)
	if err != nil {
		return TargetCheckResult{
			Target: rawTarget,
			Error:  err.Error(),
		}
	}

	// Apply STARTTLS default port
	if dialOpts.Starttls != certlib.StarttlsNone && target.Port == 443 {
		if !strings.Contains(rawTarget, ":") || strings.HasPrefix(rawTarget, "https://") || strings.HasPrefix(rawTarget, "tls://") {
			target.Port = certlib.DefaultStarttlsPort(dialOpts.Starttls)
		}
	}

	multiResult, err := certlib.DialTLSMultiIP(target, dialOpts)
	if err != nil {
		return TargetCheckResult{
			Target: target.Address(),
			Error:  err.Error(),
		}
	}

	if len(multiResult.Results) == 0 {
		return TargetCheckResult{
			Target: target.Address(),
			Error:  "no results from connection",
		}
	}

	var primaryResult *certlib.FetchResult
	for i := range multiResult.Results {
		if multiResult.Results[i].Error == nil {
			primaryResult = &multiResult.Results[i]
			break
		}
	}

	if primaryResult == nil {
		return TargetCheckResult{
			Target: target.Address(),
			Error:  multiResult.Results[0].Error.Error(),
		}
	}

	tr := TargetCheckResult{
		Target: target.Address(),
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

	// AIA fetching
	var aiaCerts []*x509.Certificate
	if !noAIA && len(primaryResult.Certificates) > 0 {
		aiaCerts, _ = certlib.FetchAIAIntermediates(primaryResult.Certificates[0])
	}

	// Revocation: staple is always parsed (free); live OCSP/CRL only when
	// requested. Leaf only in this milestone.
	checkOpts.RevocationEnabled = revCfg.Enabled
	checkOpts.RevocationRequire = revCfg.Require
	var revocation *certlib.RevocationResult
	if len(primaryResult.Certificates) > 0 {
		revocation = resolveLeafRevocation(primaryResult.Certificates[0], primaryResult.Certificates, aiaCerts, primaryResult.TLSInfo.OCSPResponse, revCfg)
	}

	// One shared entry point for the checks, so the TUI (which never dials
	// again) reports exactly what the CLI does.
	result := CheckFetchedTarget(CheckTargetInput{
		Target:         target,
		TLSInfo:        primaryResult.TLSInfo,
		Certificates:   primaryResult.Certificates,
		AIACerts:       aiaCerts,
		Revocation:     revocation,
		Roots:          roots,
		Stores:         stores,
		PlatformVerify: platformVerify,
	}, checkOpts)

	tr.Issues = result.Issues
	tr.Summary.Critical = result.Summary.Critical
	tr.Summary.Warning = result.Summary.Warning
	tr.Summary.Info = result.Summary.Info

	return tr
}
