package truststore

import (
	"crypto/x509"
	"time"
)

func VerifyChain(certs []*x509.Certificate, store StoreInfo, pool *x509.CertPool, hostname string) VerifyResult {
	if len(certs) == 0 {
		return VerifyResult{
			Store:   store,
			Reason:  "no certificates to verify",
			Trusted: false,
		}
	}

	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         pool,
		CurrentTime:   time.Now(),
		// Without this a client-auth or code-signing certificate reads as
		// untrusted for the wrong reason: the path is fine, the purpose is not
		// what the default assumes.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if hostname != "" {
		opts.DNSName = hostname
	}

	chains, err := leaf.Verify(opts)
	if err != nil {
		reason, suggestions := ClassifyVerifyError(err, hostname)
		return VerifyResult{
			Store:       store,
			Trusted:     false,
			Chain:       certs,
			Error:       err,
			Reason:      reason,
			Suggestions: suggestions,
			Hostname:    hostname,
		}
	}

	var chain []*x509.Certificate
	if len(chains) > 0 {
		chain = chains[0]
	}

	var anchor *x509.Certificate
	if len(chain) > 0 {
		anchor = chain[len(chain)-1]
	}

	return VerifyResult{
		Store:       store,
		Trusted:     true,
		Chain:       chain,
		TrustAnchor: anchor,
		Hostname:    hostname,
	}
}
