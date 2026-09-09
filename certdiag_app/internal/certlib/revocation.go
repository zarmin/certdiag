package certlib

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

type RevocationStatus string

const (
	RevocationGood         RevocationStatus = "good"
	RevocationRevoked      RevocationStatus = "revoked"
	RevocationUndetermined RevocationStatus = "undetermined"
)

type RevocationMethod string

const (
	RevocationMethodStapledOCSP RevocationMethod = "stapled_ocsp"
	RevocationMethodOCSP        RevocationMethod = "ocsp"
	RevocationMethodCRL         RevocationMethod = "crl"
	RevocationMethodCRLFile     RevocationMethod = "crl_file"
	RevocationMethodAuto        RevocationMethod = "auto"
)

const (
	ocspMaxResponseSize      = 1 << 20  // 1 MB
	crlMaxResponseSize       = 10 << 20 // 10 MB
	revocationMaxRedirects   = 3
	revocationDefaultTimeout = 10 * time.Second

	ocspRequestContentType  = "application/ocsp-request"
	ocspResponseContentType = "application/ocsp-response"
	revocationSourceStaple  = "staple"
)

const (
	reasonUnspecified          = "unspecified"
	reasonKeyCompromise        = "keyCompromise"
	reasonCACompromise         = "caCompromise"
	reasonAffiliationChanged   = "affiliationChanged"
	reasonSuperseded           = "superseded"
	reasonCessationOfOperation = "cessationOfOperation"
	reasonCertificateHold      = "certificateHold"
	reasonRemoveFromCRL        = "removeFromCRL"
	reasonPrivilegeWithdrawn   = "privilegeWithdrawn"
	reasonAACompromise         = "aaCompromise"
)

// RevocationAttempt records one source that was tried, successful or not.
type RevocationAttempt struct {
	Method RevocationMethod
	Source string
	Err    string
}

// RevocationRecord ties a revocation result to the certificate it describes,
// for output that lists status per certificate (including "good" certs that
// produce no check issue).
type RevocationRecord struct {
	FilePath  string
	Filename  string
	ItemIndex int
	DN        string
	Result    *RevocationResult
}

// RevocationResult is the outcome for a single certificate.
type RevocationResult struct {
	Status     RevocationStatus
	Method     RevocationMethod
	Verified   bool
	ThisUpdate time.Time
	NextUpdate time.Time
	RevokedAt  time.Time
	Reason     string
	Attempts   []RevocationAttempt
}

// RevocationOptions controls resolution. "Require" (escalate undetermined to
// critical) is a check-severity concern and lives on CheckOptions, not here.
type RevocationOptions struct {
	Method     RevocationMethod
	Timeout    time.Duration
	CRLFile    string
	HTTPClient *http.Client
}

func (o RevocationOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return revocationDefaultTimeout
}

func (o RevocationOptions) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{
		Timeout: o.timeout(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= revocationMaxRedirects {
				return fmt.Errorf("stopped after %d redirects", revocationMaxRedirects)
			}
			return nil
		},
	}
}

// RevocationReasonString maps an RFC 5280 CRLReason code to its name.
func RevocationReasonString(code int) string {
	switch code {
	case 0:
		return reasonUnspecified
	case 1:
		return reasonKeyCompromise
	case 2:
		return reasonCACompromise
	case 3:
		return reasonAffiliationChanged
	case 4:
		return reasonSuperseded
	case 5:
		return reasonCessationOfOperation
	case 6:
		return reasonCertificateHold
	case 8:
		return reasonRemoveFromCRL
	case 9:
		return reasonPrivilegeWithdrawn
	case 10:
		return reasonAACompromise
	default:
		return fmt.Sprintf("reason(%d)", code)
	}
}

// CheckOCSPStaple parses and verifies a DER OCSP response (typically a TLS
// staple) for leaf against issuer. Returns nil when staple is empty.
func CheckOCSPStaple(staple []byte, leaf, issuer *x509.Certificate) *RevocationResult {
	if len(staple) == 0 {
		return nil
	}
	res := &RevocationResult{Method: RevocationMethodStapledOCSP}

	var resp *ocsp.Response
	var err error
	if issuer != nil {
		resp, err = ocsp.ParseResponseForCert(staple, leaf, issuer)
	} else {
		resp, err = ocsp.ParseResponse(staple, nil)
	}
	if err != nil {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodStapledOCSP, Source: revocationSourceStaple, Err: err.Error()}}
		return res
	}

	// ParseResponse (nil-issuer path) does not match the response to the cert, so
	// a staple for a different certificate would be accepted. Reject a serial
	// mismatch explicitly. (ParseResponseForCert already enforces this.)
	if leaf != nil && leaf.SerialNumber != nil && resp.SerialNumber != nil && resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodStapledOCSP, Source: revocationSourceStaple, Err: "stapled OCSP response is for a different certificate (serial mismatch)"}}
		return res
	}

	res.Verified = issuer != nil && ocspResponderAuthorized(resp)
	applyOCSPResponse(res, resp)
	res.Attempts = []RevocationAttempt{{Method: RevocationMethodStapledOCSP, Source: revocationSourceStaple, Err: applyStaleness(res, "stapled OCSP response")}}
	return res
}

// QueryOCSP performs a live OCSP query for leaf against each URL in order. The
// first parseable response wins; every URL tried is recorded in Attempts.
func QueryOCSP(leaf, issuer *x509.Certificate, urls []string, opts RevocationOptions) *RevocationResult {
	res := &RevocationResult{Method: RevocationMethodOCSP, Status: RevocationUndetermined}
	if leaf == nil {
		res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Err: "no certificate"})
		return res
	}
	if issuer == nil {
		res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Err: "issuer unavailable"})
		return res
	}

	reqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Err: err.Error()})
		return res
	}

	client := opts.httpClient()
	for _, u := range urls {
		if !isHTTPURL(u) {
			res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Source: u, Err: "unsupported URL scheme"})
			continue
		}
		respBytes, err := postOCSP(client, u, reqBytes, opts.timeout())
		if err != nil {
			res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Source: u, Err: err.Error()})
			continue
		}
		ocspResp, err := ocsp.ParseResponseForCert(respBytes, leaf, issuer)
		if err != nil {
			res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Source: u, Err: err.Error()})
			continue
		}
		res.Verified = ocspResponderAuthorized(ocspResp)
		applyOCSPResponse(res, ocspResp)
		note := applyStaleness(res, "OCSP response")
		if note == "" && ocspResp.Status == ocsp.Unknown {
			note = "responder returned unknown status"
		}
		res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodOCSP, Source: u, Err: note})
		if determinate(res) {
			return res
		}
		// Non-determinate (unknown or stale): clear this URL's verified flag and
		// timestamps so they do not leak into the final undetermined result.
		res.Verified = false
		res.ThisUpdate, res.NextUpdate = time.Time{}, time.Time{}
	}
	res.Status = RevocationUndetermined
	return res
}

// FetchCRL downloads a CRL from url with a bounded body, redirect cap, and
// http/https-only scheme allowlist.
func FetchCRL(url string, opts RevocationOptions) ([]byte, error) {
	if !isHTTPURL(url) {
		return nil, fmt.Errorf("unsupported CRL URL scheme: %s", url)
	}
	client := opts.httpClient()
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL URL returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, crlMaxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > crlMaxResponseSize {
		return nil, fmt.Errorf("CRL exceeds max size %d bytes", crlMaxResponseSize)
	}
	return data, nil
}

// CheckCRL parses a DER (or PEM) CRL and reports whether cert's serial is
// listed. It verifies the CRL signature against issuer when issuer is non-nil.
func CheckCRL(crlDER []byte, cert, issuer *x509.Certificate) *RevocationResult {
	res := &RevocationResult{Method: RevocationMethodCRL}
	if cert == nil {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: "no certificate"}}
		return res
	}

	der, err := crlToDER(crlDER)
	if err != nil {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: err.Error()}}
		return res
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: err.Error()}}
		return res
	}

	res.ThisUpdate = crl.ThisUpdate
	res.NextUpdate = crl.NextUpdate
	res.Verified = issuer != nil && crl.CheckSignatureFrom(issuer) == nil

	// If we have the issuer and the signature does not verify, the CRL is
	// forged or corrupt: do not derive a verdict from it. Undetermined (not a
	// verdict) lets resolution move on to the next distribution point. With no
	// issuer to check against, we fall through to a lookup-only, unverified
	// result as before.
	if issuer != nil && !res.Verified {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: "CRL signature verification failed"}}
		return res
	}

	issuerMatch, partial, scopeNote := crlScope(crl, cert)

	listed := false
	var entry x509.RevocationListEntry
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber != nil && cert.SerialNumber != nil && e.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			listed = true
			entry = e
			break
		}
	}

	// A CRL from a different issuer proves nothing about this cert either way; a
	// serial match there is coincidental.
	if !issuerMatch {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: "CRL issuer does not match certificate issuer"}}
		return res
	}

	if listed {
		// Being listed is authoritative even for a partition/delta CRL: you cannot
		// be wrongly present in a CRL signed by your own issuer.
		res.Status = RevocationRevoked
		res.RevokedAt = entry.RevocationTime
		res.Reason = RevocationReasonString(entry.ReasonCode)
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: applyStaleness(res, "CRL")}}
		return res
	}

	// Absence only proves "good" when the CRL is complete for this cert's scope.
	if partial {
		res.Status = RevocationUndetermined
		res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: scopeNote}}
		return res
	}

	res.Status = RevocationGood
	res.Attempts = []RevocationAttempt{{Method: RevocationMethodCRL, Err: applyStaleness(res, "CRL")}}
	return res
}

var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// crlScope reports whether a CRL covers cert. issuerMatch is false when the CRL
// was signed by a different issuer (a not-listed result then proves nothing);
// partial is true for a partitioned (issuing distribution point) or delta CRL,
// which is incomplete on its own so absence cannot be read as "good".
func crlScope(crl *x509.RevocationList, cert *x509.Certificate) (issuerMatch, partial bool, note string) {
	issuerMatch = len(cert.RawIssuer) == 0 || len(crl.RawIssuer) == 0 || bytes.Equal(crl.RawIssuer, cert.RawIssuer)
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			partial, note = true, "delta CRL is incomplete without its base CRL"
		case ext.Id.Equal(oidIssuingDistributionPoint):
			partial, note = true, "partitioned CRL (issuing distribution point) may not cover this certificate"
		}
	}
	return issuerMatch, partial, note
}

// ResolveRevocation orchestrates staple -> OCSP -> CRL according to opts.Method
// (auto tries all in that order). The first determinate, answer wins; all tried
// sources are recorded in the returned Attempts.
func ResolveRevocation(cert, issuer *x509.Certificate, staple []byte, opts RevocationOptions) *RevocationResult {
	method := opts.Method
	if method == "" {
		method = RevocationMethodAuto
	}

	agg := &RevocationResult{Status: RevocationUndetermined}
	if cert == nil {
		agg.Attempts = []RevocationAttempt{{Method: method, Err: "no certificate"}}
		return agg
	}

	tryStaple := len(staple) > 0 && (method == RevocationMethodAuto || method == RevocationMethodOCSP)
	tryOCSP := (method == RevocationMethodAuto || method == RevocationMethodOCSP) && len(cert.OCSPServer) > 0
	tryCRL := method == RevocationMethodAuto || method == RevocationMethodCRL

	if tryStaple {
		if r := CheckOCSPStaple(staple, cert, issuer); r != nil {
			agg.Attempts = append(agg.Attempts, r.Attempts...)
			if determinate(r) {
				return withAttempts(r, agg.Attempts)
			}
		}
	}
	if tryOCSP {
		r := QueryOCSP(cert, issuer, cert.OCSPServer, opts)
		agg.Attempts = append(agg.Attempts, r.Attempts...)
		if determinate(r) {
			return withAttempts(r, agg.Attempts)
		}
	}
	if tryCRL {
		r := resolveCRL(cert, issuer, opts)
		agg.Attempts = append(agg.Attempts, r.Attempts...)
		if determinate(r) {
			return withAttempts(r, agg.Attempts)
		}
	}
	return agg
}

func resolveCRL(cert, issuer *x509.Certificate, opts RevocationOptions) *RevocationResult {
	if opts.CRLFile != "" {
		data, err := os.ReadFile(opts.CRLFile)
		if err != nil {
			return &RevocationResult{Status: RevocationUndetermined, Method: RevocationMethodCRLFile,
				Attempts: []RevocationAttempt{{Method: RevocationMethodCRLFile, Source: opts.CRLFile, Err: err.Error()}}}
		}
		r := CheckCRL(data, cert, issuer)
		relabelCRL(r, RevocationMethodCRLFile, opts.CRLFile)
		return r
	}

	res := &RevocationResult{Method: RevocationMethodCRL, Status: RevocationUndetermined}
	for _, u := range cert.CRLDistributionPoints {
		data, err := FetchCRL(u, opts)
		if err != nil {
			res.Attempts = append(res.Attempts, RevocationAttempt{Method: RevocationMethodCRL, Source: u, Err: err.Error()})
			continue
		}
		r := CheckCRL(data, cert, issuer)
		relabelCRL(r, RevocationMethodCRL, u)
		res.Attempts = append(res.Attempts, r.Attempts...)
		if determinate(r) {
			return withAttempts(r, res.Attempts)
		}
	}
	return res
}

// relabelCRL stamps the method and source onto a CheckCRL result whose attempt
// was produced without knowledge of where the bytes came from.
func relabelCRL(r *RevocationResult, method RevocationMethod, source string) {
	r.Method = method
	for i := range r.Attempts {
		r.Attempts[i].Method = method
		if r.Attempts[i].Source == "" {
			r.Attempts[i].Source = source
		}
	}
}

func withAttempts(r *RevocationResult, attempts []RevocationAttempt) *RevocationResult {
	r.Attempts = attempts
	return r
}

func determinate(r *RevocationResult) bool {
	return r != nil && (r.Status == RevocationGood || r.Status == RevocationRevoked)
}

// applyStaleness downgrades a "good" verdict from an expired source (nextUpdate
// in the past) to undetermined: stale data cannot prove the absence of a
// revocation, while a stale "revoked" listing is still evidence. Returns the
// note to record on the attempt ("" when the source is fresh).
func applyStaleness(res *RevocationResult, kind string) string {
	if res.NextUpdate.IsZero() || time.Now().Before(res.NextUpdate) {
		return ""
	}
	note := kind + " is expired (nextUpdate in the past)"
	if res.Status == RevocationGood {
		res.Status = RevocationUndetermined
	}
	return note
}

func ocspResponderAuthorized(resp *ocsp.Response) bool {
	if resp.Certificate == nil {
		// Issuer signed the response directly; the parse already verified it.
		return true
	}
	return slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
}

func applyOCSPResponse(res *RevocationResult, resp *ocsp.Response) {
	res.ThisUpdate = resp.ThisUpdate
	res.NextUpdate = resp.NextUpdate
	switch resp.Status {
	case ocsp.Good:
		res.Status = RevocationGood
	case ocsp.Revoked:
		res.Status = RevocationRevoked
		res.RevokedAt = resp.RevokedAt
		res.Reason = RevocationReasonString(resp.RevocationReason)
	default:
		res.Status = RevocationUndetermined
	}
}

func postOCSP(client *http.Client, url string, reqBody []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ocspRequestContentType)
	req.Header.Set("Accept", ocspResponseContentType)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP responder returned status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, ocspMaxResponseSize))
}

func crlToDER(data []byte) ([]byte, error) {
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes, nil
	}
	return data, nil
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
