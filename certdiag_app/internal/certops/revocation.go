package certops

import (
	"crypto/x509"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// RevocationConfig carries the revocation settings from the CLI into the scan
// and remote-check pipelines. Network resolution lives here in the certops
// layer, never inside a pure check function.
type RevocationConfig struct {
	Enabled bool
	Require bool
	Method  certlib.RevocationMethod
	CRLFile string
}

func (c RevocationConfig) options() certlib.RevocationOptions {
	return certlib.RevocationOptions{
		Method:  c.Method,
		CRLFile: c.CRLFile,
	}
}

// computeRevocation resolves revocation for every non-self-signed certificate
// item in the store. Results are keyed by ItemRef identically to how RunChecks
// builds them, so the file-side checks can look them up. Self-signed
// certificates are skipped: a trust anchor has no revocation mechanism of its
// own.
func computeRevocation(store *certlib.CertStore, cfg RevocationConfig) map[certlib.ItemRef]*certlib.RevocationResult {
	results := make(map[certlib.ItemRef]*certlib.RevocationResult)
	revOpts := cfg.options()

	for ci := range store.Containers {
		c := &store.Containers[ci]
		if c.RelationsOnly {
			continue
		}
		for ii := range c.Items {
			cert := c.Items[ii].Certificate
			if cert == nil || certlib.IsSelfSigned(cert) {
				continue
			}
			ref := certlib.ItemRef{ContainerIdx: ci, ItemIdx: ii, FilePath: c.FilePath, Alias: c.Items[ii].Alias}
			issuer := findIssuerInStore(store, cert)
			// A missing issuer may be fetched over AIA, but never under an
			// offline method: --crl-file promises no network (M31 M8).
			if issuer == nil && cfg.Method != certlib.RevocationMethodCRLFile {
				if fetched, _ := certlib.FetchAIAIntermediates(cert); len(fetched) > 0 {
					issuer = fetched[0]
				}
			}
			results[ref] = certlib.ResolveRevocation(cert, issuer, nil, revOpts)
		}
	}
	return results
}

// resolveLeafRevocation resolves revocation for a remote leaf. The staple, when
// present, is always parsed (free); live OCSP/CRL only when cfg.Enabled.
func resolveLeafRevocation(leaf *x509.Certificate, chain, aiaCerts []*x509.Certificate, staple []byte, cfg RevocationConfig) *certlib.RevocationResult {
	issuer := pickIssuer(leaf, chain, aiaCerts)
	if cfg.Enabled {
		return certlib.ResolveRevocation(leaf, issuer, staple, cfg.options())
	}
	if len(staple) > 0 {
		return certlib.CheckOCSPStaple(staple, leaf, issuer)
	}
	return nil
}

func findIssuerInStore(store *certlib.CertStore, cert *x509.Certificate) *x509.Certificate {
	for ci := range store.Containers {
		for ii := range store.Containers[ci].Items {
			cand := store.Containers[ci].Items[ii].Certificate
			if cand == nil || cand.Equal(cert) {
				continue
			}
			if issuerMatches(cert, cand) {
				return cand
			}
		}
	}
	return nil
}

func pickIssuer(leaf *x509.Certificate, chain, aiaCerts []*x509.Certificate) *x509.Certificate {
	for _, candidates := range [][]*x509.Certificate{chain, aiaCerts} {
		for _, c := range candidates {
			if c.Equal(leaf) {
				continue
			}
			if issuerMatches(leaf, c) {
				return c
			}
		}
	}
	return nil
}

func issuerMatches(cert, candidate *x509.Certificate) bool {
	return candidate.Subject.String() == cert.Issuer.String() && cert.CheckSignatureFrom(candidate) == nil
}
