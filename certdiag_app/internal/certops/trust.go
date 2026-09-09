package certops

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// AnchorContainerLabel names the synthesized container that carries the trust
// anchors into the relation graph.
const AnchorContainerLabel = "OS Trust Store"

type TrustEvalOptions struct {
	Store *certlib.CertStore
	// Stores are the loaded trust stores. Only OS stores contribute anchor
	// membership; the TRUST column answers the OS question, and presence in
	// other stores is shown by the STORES column instead.
	Stores []truststore.StoreContents
	Ctx    context.Context
	// AIA carries certificates fetched over Authority Information Access. They
	// join the intermediate pool, and a path that completes only through one is
	// labelled: that is exactly the trust a client which does not chase AIA
	// does not have.
	AIA *certlib.AIAResult
}

// EvaluateTrust resolves a trust verdict for every certificate in the store.
//
// Two tiers: chain verification through the platform verifier (Roots nil), and
// membership in the OS trust store. Membership wins, so a root the OS holds
// reads ANCHOR rather than the weaker TRUSTED, and an explicitly distrusted one
// reads DENIED.
func EvaluateTrust(opts TrustEvalOptions) (*truststore.TrustIndex, error) {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	index := truststore.NewTrustIndex()
	if opts.Store == nil {
		return index, nil
	}

	members := osMembership(opts.Stores)
	certs := storeCertificates(opts.Store)

	intermediates := x509.NewCertPool()
	for _, c := range certs {
		intermediates.AddCert(c)
	}
	if opts.AIA != nil {
		for _, c := range opts.AIA.Certificates() {
			intermediates.AddCert(c)
		}
	}
	roots := osRootPool(opts.Stores, members)

	for _, cert := range certs {
		select {
		case <-ctx.Done():
			return index, ctx.Err()
		default:
		}

		if trust, ok := members[truststore.CertFingerprint(cert)]; ok {
			index.Set(cert, truststore.VerdictFromTrustStatus(trust.Overall), cert)
			continue
		}

		verdict, anchor := verifyChain(cert, intermediates, roots)
		if verdict == truststore.VerdictUntrusted {
			if a := crossSignedAnchor(cert, opts.Stores, members); a != nil {
				verdict, anchor = truststore.VerdictTrusted, a
			}
		}
		detail := truststore.TrustDetail{Verdict: verdict, Anchor: anchor}
		switch {
		case verdict == truststore.VerdictUntrusted:
			detail.Hint = trustHint(cert, certs)
		case opts.AIA != nil && verdict == truststore.VerdictTrusted:
			detail.ViaAIA = pathNeedsAIA(cert, certs, roots, opts.AIA)
		}
		index.SetDetail(cert, detail)
	}

	return index, nil
}

// verifyChain runs the chain check that decides trusted / expired / untrusted.
//
// Roots is always the explicit pool built from the OS store contents, never nil.
// Two reasons, both learned the hard way:
//
//   - A nil pool routes to the platform verifier, and Security.framework
//     refuses to evaluate a CA as the leaf ("certificate is not standards
//     compliant") regardless of the requested key usage. That marked every
//     intermediate and root UNTRUSTED. x509.SystemCertPool is no escape: on
//     darwin it returns an empty pool that Verify still routes to the platform.
//   - Using the platform verifier for leaves and an explicit pool for CAs meant
//     two engines answering one question, so a leaf and its own intermediate
//     could disagree.
//
// The pool is the certificates certdiag actually read out of the OS store, with
// anything the store distrusts left out, so this answers "does this machine's
// trust store contain an anchor for this certificate" exactly and uniformly.
// It does not apply platform policy (CT, EV, OS-level revocation), so it can
// differ from `certdiag verify --os` on a chain the platform rejects for policy
// rather than for path reasons. Revocation is covered separately by the
// revocation checks.
//
// KeyUsages must be ExtKeyUsageAny: the zero value means ExtKeyUsageServerAuth,
// which would mark every client-auth, code-signing and S/MIME certificate
// untrusted. DNSName stays empty because no hostname is known for a file scan.
func verifyChain(cert *x509.Certificate, intermediates, roots *x509.CertPool) (truststore.TrustVerdict, *x509.Certificate) {
	if roots == nil {
		return truststore.VerdictUntrusted, nil
	}

	chains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		var anchor *x509.Certificate
		if len(chains) > 0 && len(chains[0]) > 0 {
			anchor = chains[0][len(chains[0])-1]
		}
		return truststore.VerdictTrusted, anchor
	}

	if isExpiryError(err) {
		return truststore.VerdictExpired, nil
	}
	return truststore.VerdictUntrusted, nil
}

// crossSignedAnchor finds the OS anchor a cross-signed CA is a copy of: same
// subject, same public key, different issuer. The path builder cannot chain the
// copy (its issuer is elsewhere or nowhere), but every path through it ends at
// that anchor, which is how every client treats it. Nil when there is none.
func crossSignedAnchor(cert *x509.Certificate, stores []truststore.StoreContents, members map[string]truststore.CertTrust) *x509.Certificate {
	if !cert.IsCA {
		return nil
	}
	for i := range stores {
		if stores[i].Info.Type != truststore.StoreTypeOS {
			continue
		}
		for _, root := range stores[i].Certificates {
			if t, ok := members[truststore.CertFingerprint(root)]; ok && t.Overall == truststore.TrustDenied {
				continue
			}
			if bytes.Equal(root.RawSubject, cert.RawSubject) && bytes.Equal(root.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) {
				return root
			}
		}
	}
	return nil
}

// isExpiryError separates "the chain is fine but something in it is outside its
// validity window" from a genuine path failure. The platform verifiers return
// coarser errors than the Go verifier, so this degrades to untrusted rather
// than guessing.
func isExpiryError(err error) bool {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		return invalid.Reason == x509.Expired
	}
	return false
}

// osMembership maps fingerprint to trust setting for every certificate in an OS
// trust store.
func osMembership(stores []truststore.StoreContents) map[string]truststore.CertTrust {
	members := make(map[string]truststore.CertTrust)
	for i := range stores {
		if stores[i].Info.Type != truststore.StoreTypeOS {
			continue
		}
		for _, cert := range stores[i].Certificates {
			fp := truststore.CertFingerprint(cert)
			trust := stores[i].GetTrust(cert)
			if existing, ok := members[fp]; ok && existing.Overall == truststore.TrustDenied {
				continue
			}
			members[fp] = trust
		}
	}
	return members
}

// StoreCertificates returns every certificate in a store.
func StoreCertificates(store *certlib.CertStore) []*x509.Certificate {
	return storeCertificates(store)
}

func storeCertificates(store *certlib.CertStore) []*x509.Certificate {
	var certs []*x509.Certificate
	for ci := range store.Containers {
		c := &store.Containers[ci]
		for ii := range c.Items {
			item := &c.Items[ii]
			if item.Type == certlib.ContentCertificate && item.Certificate != nil {
				certs = append(certs, item.Certificate)
			}
		}
	}
	return certs
}

// AnchorContainer builds a RelationsOnly container holding the trust anchors
// that are relevant to the scanned certificates, so DetectRelations and
// AssembleChains can complete chains up to a root the machine trusts.
//
// Only the issuer closure is injected, not every root on the machine: starting
// from the issuer DNs in the scan, pull in store certificates whose subject
// matches, and repeat until nothing new appears. In practice that is one to
// three certificates, which keeps the O(n^2) relation pass and the same_cert
// output focused.
func AnchorContainer(store *certlib.CertStore, stores []truststore.StoreContents) *certlib.CertContainer {
	if store == nil || len(stores) == 0 {
		return nil
	}

	bySubject := make(map[string][]*x509.Certificate)
	for i := range stores {
		if stores[i].Info.Type != truststore.StoreTypeOS {
			continue
		}
		for _, cert := range stores[i].Certificates {
			subj := cert.Subject.String()
			bySubject[subj] = append(bySubject[subj], cert)
		}
	}
	if len(bySubject) == 0 {
		return nil
	}

	// Certificates already in the scan must not be duplicated into the anchor
	// container; they are their own nodes.
	inScan := make(map[string]bool)
	wanted := make(map[string]bool)
	for _, cert := range storeCertificates(store) {
		inScan[truststore.CertFingerprint(cert)] = true
		wanted[cert.Issuer.String()] = true
	}

	picked := make(map[string]bool)
	var anchors []*x509.Certificate

	for len(wanted) > 0 {
		next := make(map[string]bool)
		for subject := range wanted {
			for _, cert := range bySubject[subject] {
				fp := truststore.CertFingerprint(cert)
				if picked[fp] || inScan[fp] {
					continue
				}
				picked[fp] = true
				anchors = append(anchors, cert)
				if issuer := cert.Issuer.String(); issuer != cert.Subject.String() {
					next[issuer] = true
				}
			}
		}
		wanted = next
	}

	if len(anchors) == 0 {
		return nil
	}
	items := buildStoreItems(anchors)

	return &certlib.CertContainer{
		Label:         AnchorContainerLabel,
		Source:        certlib.SourceTrustStore,
		Format:        certlib.FormatPEM,
		RelationsOnly: true,
		Items:         items,
	}
}

// osRootPool builds an explicit pool from the OS store contents, skipping
// anything the store explicitly distrusts. Filtering here is what makes macOS
// "Never Trust" real rather than cosmetic: a denied root cannot anchor anything.
func osRootPool(stores []truststore.StoreContents, members map[string]truststore.CertTrust) *x509.CertPool {
	pool := x509.NewCertPool()
	added := 0
	for i := range stores {
		if stores[i].Info.Type != truststore.StoreTypeOS {
			continue
		}
		for _, cert := range stores[i].Certificates {
			if t, ok := members[truststore.CertFingerprint(cert)]; ok && t.Overall == truststore.TrustDenied {
				continue
			}
			pool.AddCert(cert)
			added++
		}
	}
	if added == 0 {
		return nil
	}
	return pool
}

// trustHint explains an untrusted verdict when the explanation is actionable.
//
// The common case, and the one that makes certdiag disagree with a browser, is
// a path that stops at a certificate whose issuer is simply not in the scan
// while the issuer is published at a well-known URL. Saying so turns a dead end
// into a next step, and costs nothing: this walks what is already in hand and
// never touches the network.
func trustHint(cert *x509.Certificate, scanned []*x509.Certificate) string {
	terminal := terminalOfPath(cert, scanned)
	if terminal == nil || len(terminal.IssuingCertificateURL) == 0 {
		return ""
	}
	if certlib.IsSelfSigned(terminal) {
		return ""
	}
	return fmt.Sprintf("issuer %q is not in the scan; it is published at %s",
		certlib.FormatDNName(terminal.Issuer), terminal.IssuingCertificateURL[0])
}

// terminalOfPath follows the issuer links present in the scan and returns the
// last certificate reached: the point where the chain runs out.
func terminalOfPath(cert *x509.Certificate, scanned []*x509.Certificate) *x509.Certificate {
	current := cert
	seen := map[string]bool{string(current.Raw): true}

	for range scanned {
		if certlib.IsSelfSigned(current) {
			return current
		}
		var next *x509.Certificate
		for _, cand := range scanned {
			if seen[string(cand.Raw)] {
				continue
			}
			if current.CheckSignatureFrom(cand) == nil {
				next = cand
				break
			}
		}
		if next == nil {
			return current
		}
		seen[string(next.Raw)] = true
		current = next
	}
	return current
}

// pathNeedsAIA reports whether the chain completes only because of a fetched
// certificate. Re-verifying without them is the honest test: if the path still
// stands, AIA was not what made it work.
func pathNeedsAIA(cert *x509.Certificate, scanned []*x509.Certificate, roots *x509.CertPool, aia *certlib.AIAResult) bool {
	if aia == nil || len(aia.Fetched) == 0 {
		return false
	}
	withoutAIA := x509.NewCertPool()
	for _, c := range scanned {
		withoutAIA.AddCert(c)
	}
	verdict, _ := verifyChain(cert, withoutAIA, roots)
	return verdict != truststore.VerdictTrusted
}
