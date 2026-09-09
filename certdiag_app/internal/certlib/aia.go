package certlib

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/smallstep/pkcs7"
)

// Authority Information Access: fetching the issuer a chain is missing.
//
// A CA rolling to a new root publishes the new root both self-signed and
// cross-signed by the old one, and serves only the self-signed copy. Clients
// that chase AIA (browsers, the macOS and Windows verifiers) find the
// cross-signed copy and complete the path; clients that do not (Java, most
// command-line tools) fail. That difference is the whole reason this exists,
// and why a path completed this way is labelled rather than silently accepted.

const (
	aiaFetchTimeout    = 10 * time.Second
	aiaMaxResponseSize = 1 << 20 // 1 MB
	aiaDefaultDepth    = 5
)

// AIAFetcher retrieves the certificates published at one CA Issuers URL.
type AIAFetcher interface {
	Fetch(ctx context.Context, url string) ([]*x509.Certificate, error)
}

// AIACache stores fetched certificates between runs. It caches bytes, never
// verdicts: a cached certificate is signature-checked again on every use.
type AIACache interface {
	Get(url string) (AIAFetched, bool)
	Put(f AIAFetched) error
}

// DefaultAIAFetcher is the production fetcher. Tests replace it, and a guard
// test fails if the real one is ever reached from a test binary.
var DefaultAIAFetcher AIAFetcher = httpAIAFetcher{}

// AIASource says where a certificate came from. Every surface that shows one
// says which, because "fetched just now" and "remembered from three weeks ago"
// are different claims.
type AIASource int

const (
	AIASourceFetched AIASource = iota
	AIASourceCached
)

func (s AIASource) String() string {
	if s == AIASourceCached {
		return "cache"
	}
	return "fetched"
}

// AIAFetched is one certificate obtained over AIA.
type AIAFetched struct {
	Cert      *x509.Certificate
	URL       string
	Source    AIASource
	FetchedAt time.Time
	// For is the certificate whose AIA extension pointed here.
	For *x509.Certificate
}

// AIAFailure records a URL that did not yield a usable issuer, with the reason.
// Failures are reported rather than swallowed: "the CA's server is down" and
// "the CA published the wrong certificate" call for different responses.
type AIAFailure struct {
	URL    string
	For    *x509.Certificate
	Reason string
}

// AIAResult is what one chase produced.
type AIAResult struct {
	Fetched  []AIAFetched
	Failures []AIAFailure
}

// Certificates returns just the certificates.
func (r AIAResult) Certificates() []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(r.Fetched))
	for _, f := range r.Fetched {
		out = append(out, f.Cert)
	}
	return out
}

// Contains reports whether a certificate came from this chase.
func (r AIAResult) Contains(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, f := range r.Fetched {
		if f.Cert != nil && f.Cert.Equal(cert) {
			return true
		}
	}
	return false
}

// AIAOptions configures a chase.
type AIAOptions struct {
	MaxDepth int
	Fetcher  AIAFetcher
	Cache    AIACache
	Ctx      context.Context
}

// ChaseAIA follows CA Issuers URLs upward from every input certificate.
//
// Every candidate at a hop is kept, not just the first that verifies: a
// cross-signed CA is published at more than one URL and path building needs
// both copies. Starting from every input rather than only the leaf means a scan
// of a lone intermediate works too.
func ChaseAIA(certs []*x509.Certificate, opts AIAOptions) AIAResult {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = DefaultAIAFetcher
	}
	depth := opts.MaxDepth
	if depth <= 0 {
		depth = aiaDefaultDepth
	}

	var result AIAResult
	seenURL := make(map[string]bool)
	seenCert := make(map[string]bool)
	for _, c := range certs {
		if c != nil {
			seenCert[string(c.Raw)] = true
		}
	}

	frontier := append([]*x509.Certificate(nil), certs...)
	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []*x509.Certificate
		for _, cert := range frontier {
			if cert == nil || IsSelfSigned(cert) {
				continue
			}
			for _, url := range cert.IssuingCertificateURL {
				if seenURL[url] {
					continue
				}
				seenURL[url] = true

				found, failure := resolveAIAURL(ctx, url, cert, fetcher, opts.Cache)
				if failure != nil {
					result.Failures = append(result.Failures, *failure)
					continue
				}
				for _, f := range found {
					if seenCert[string(f.Cert.Raw)] {
						continue
					}
					seenCert[string(f.Cert.Raw)] = true
					result.Fetched = append(result.Fetched, f)
					next = append(next, f.Cert)
				}
			}
		}
		frontier = next
	}

	return result
}

// resolveAIAURL fetches one URL and keeps the certificates that actually signed
// the requester. A CA that publishes the wrong file is a failure with a reason,
// not a silently dropped result.
func resolveAIAURL(ctx context.Context, url string, requester *x509.Certificate, fetcher AIAFetcher, cache AIACache) ([]AIAFetched, *AIAFailure) {
	if cache != nil {
		if hit, ok := cache.Get(url); ok && hit.Cert != nil {
			if requester.CheckSignatureFrom(hit.Cert) == nil {
				hit.For = requester
				hit.Source = AIASourceCached
				return []AIAFetched{hit}, nil
			}
		}
	}

	certs, err := fetcher.Fetch(ctx, url)
	if err != nil {
		return nil, &AIAFailure{URL: url, For: requester, Reason: err.Error()}
	}
	if len(certs) == 0 {
		return nil, &AIAFailure{URL: url, For: requester, Reason: "no certificate in response"}
	}

	var out []AIAFetched
	for _, cert := range certs {
		if requester.CheckSignatureFrom(cert) != nil {
			continue
		}
		f := AIAFetched{
			Cert:      cert,
			URL:       url,
			Source:    AIASourceFetched,
			FetchedAt: time.Now(),
			For:       requester,
		}
		out = append(out, f)
		if cache != nil {
			_ = cache.Put(f)
		}
	}
	if len(out) == 0 {
		return nil, &AIAFailure{URL: url, For: requester, Reason: "signature does not verify"}
	}
	return out, nil
}

// FetchAIAIntermediates is the pre-M30b entry point, kept for callers that only
// want the certificates.
func FetchAIAIntermediates(leaf *x509.Certificate) ([]*x509.Certificate, error) {
	if leaf == nil {
		return nil, nil
	}
	return ChaseAIA([]*x509.Certificate{leaf}, AIAOptions{}).Certificates(), nil
}

type httpAIAFetcher struct{}

func (httpAIAFetcher) Fetch(ctx context.Context, url string) ([]*x509.Certificate, error) {
	client := &http.Client{
		Timeout: aiaFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// A redirect to file:// or ftp:// is not a certificate fetch.
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect refused: %s", req.URL.Scheme)
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

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
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, aiaMaxResponseSize))
	if err != nil {
		return nil, err
	}
	return ParseAIAPayload(data)
}

// ParseAIAPayload decodes what a CA Issuers URL served: a bare DER certificate,
// a PEM file, or a PKCS#7 bundle. A bundle can carry the whole path, so every
// certificate in it is returned rather than only the first.
func ParseAIAPayload(data []byte) ([]*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{cert}, nil
	}

	if container, err := readPEM("aia", data, nil, nil); err == nil {
		var out []*x509.Certificate
		for _, item := range container.Items {
			if item.Type == ContentCertificate && item.Certificate != nil {
				out = append(out, item.Certificate)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}

	if p7, err := pkcs7.Parse(data); err == nil && len(p7.Certificates) > 0 {
		return p7.Certificates, nil
	}

	return nil, errors.New("not a certificate")
}
