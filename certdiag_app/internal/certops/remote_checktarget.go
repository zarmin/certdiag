package certops

import (
	"crypto/x509"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// CheckTargetInput is everything the checks need about one fetched endpoint.
// It exists so the CLI (which dials) and the TUI (which already has a result)
// run the same code and cannot drift into reporting different things.
type CheckTargetInput struct {
	Target       certlib.RemoteTarget
	TLSInfo      certlib.TLSConnectionInfo
	Certificates []*x509.Certificate
	AIACerts     []*x509.Certificate
	Revocation   *certlib.RevocationResult

	// Roots is the anchor pool the trust verdict is built from. Nil means the
	// trust checks are skipped rather than silently answered by the platform.
	Roots *x509.CertPool
	// Stores are the loaded trust stores Roots was built from. With them the
	// ordinary chain checks know whether a served chain completes through the
	// local store, so a cross-signed CA whose issuer is not served is an info,
	// not a warning. Empty means the chain checks judge the served bytes alone.
	Stores []truststore.StoreContents
	// PlatformVerify is the operating system's own verifier, reported as a
	// separate finding. Nil to skip it.
	PlatformVerify func(leaf *x509.Certificate, intermediates *x509.CertPool) error
}

// CheckFetchedTarget runs the remote checks and the ordinary certificate checks
// on one target and merges them, which is what "check this endpoint" means.
func CheckFetchedTarget(in CheckTargetInput, opts certlib.CheckOptions) *certlib.CheckResult {
	remoteResult := certlib.RunRemoteChecks(certlib.RemoteCheckContext{
		Target:         in.Target,
		TLSInfo:        in.TLSInfo,
		Certificates:   in.Certificates,
		AIACerts:       in.AIACerts,
		Revocation:     in.Revocation,
		Roots:          in.Roots,
		PlatformVerify: in.PlatformVerify,
	}, opts)

	store := certlib.NewCertStore()
	container := certlib.CertContainer{
		FilePath: in.Target.Address(),
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceRemote,
	}
	for _, cert := range in.Certificates {
		container.Items = append(container.Items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Certificate: cert,
			RawBytes:    cert.Raw,
		})
	}
	store.AddContainer(container)
	relations := certlib.DetectRelations(store)
	// The same engine and pool as the TRUST column: nothing is loaded here,
	// the stores were read once by the caller.
	if opts.TrustIndex == nil && len(in.Stores) > 0 {
		if index, err := EvaluateTrust(TrustEvalOptions{Store: store, Stores: in.Stores}); err == nil {
			opts.TrustIndex = index
		}
	}
	standardResult := certlib.RunChecks(store, certlib.BuildRelationIndex(relations, store), opts)

	merged := &certlib.CheckResult{
		FilesScanned: standardResult.FilesScanned,
		Revocations:  standardResult.Revocations,
	}
	merged.Issues = append(merged.Issues, remoteResult.Issues...)
	merged.Issues = append(merged.Issues, standardResult.Issues...)
	for _, issue := range merged.Issues {
		switch issue.Severity {
		case certlib.SeverityCritical:
			merged.Summary.Critical++
		case certlib.SeverityWarning:
			merged.Summary.Warning++
		case certlib.SeverityInfo:
			merged.Summary.Info++
		}
	}
	merged.Summary.FilesWithIssues = standardResult.Summary.FilesWithIssues
	if len(remoteResult.Issues) > 0 && merged.Summary.FilesWithIssues == 0 {
		merged.Summary.FilesWithIssues = 1
	}
	return merged
}

// platformVerify asks the operating system's verifier. Passing a nil root pool
// is what routes x509.Verify to it; that is exactly why the rest of certdiag
// never does so, and why this is confined to one clearly named function.
func platformVerify(leaf *x509.Certificate, intermediates *x509.CertPool) error {
	_, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates})
	return err
}

// OSAnchorPool builds the anchor pool from already-loaded stores, excluding
// anything the user has explicitly distrusted. Nil when there is no OS store
// among them, which the callers treat as "do not answer" rather than
// "untrusted".
func OSAnchorPool(stores []truststore.StoreContents) *x509.CertPool {
	return osRootPool(stores, osMembership(stores))
}

// osAnchorPool reads the OS trust store and builds the pool from it. The
// options carry the read seam so a test never touches the real machine.
func osAnchorPool(opts StoreLoadAllOptions) *x509.CertPool {
	return OSAnchorPool(osStores(opts))
}

// osStores reads the OS trust stores once through the seam in opts; nil when
// nothing could be read.
func osStores(opts StoreLoadAllOptions) []truststore.StoreContents {
	opts.SkipNSS = true
	opts.SkipBundles = true
	loaded, err := StoreLoadAll(opts)
	if err != nil || loaded == nil {
		return nil
	}
	return loaded.Stores
}
