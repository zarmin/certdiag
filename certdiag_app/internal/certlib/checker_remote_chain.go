package certlib

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

// Checks on the shape of the chain a server actually sent.
//
// A server can serve a complete-looking chain that no strict client accepts:
// an intermediate left over from before a CA rotation, an unrelated certificate
// concatenated into the bundle, the root nobody needs. Browsers hide most of
// this by building paths from any order and fetching what is missing, so it
// stays invisible until a client that does neither (Java, an appliance) fails.

// IntermediatePool returns the served certificates other than the leaf, plus
// anything fetched over AIA.
func (ctx RemoteCheckContext) IntermediatePool() *x509.CertPool {
	pool := x509.NewCertPool()
	if len(ctx.Certificates) > 1 {
		for _, cert := range ctx.Certificates[1:] {
			pool.AddCert(cert)
		}
	}
	for _, cert := range ctx.AIACerts {
		pool.AddCert(cert)
	}
	return pool
}

// ServedChainPath reports which served certificates lie on the path upward from
// the leaf. Exported for the TUI, which marks the ones that do not.
func ServedChainPath(certs []*x509.Certificate) []int { return servedPath(certs) }

// servedPath returns the indices of the served certificates that lie on the
// path upward from the leaf, in order. Membership is decided by signature, not
// by subject names, so a stale intermediate with the right name is not on it.
func servedPath(certs []*x509.Certificate) []int {
	if len(certs) == 0 {
		return nil
	}
	path := []int{0}
	onPath := map[int]bool{0: true}
	current := certs[0]

	for {
		if IsSelfSigned(current) {
			break
		}
		next := -1
		for i, cand := range certs {
			if onPath[i] {
				continue
			}
			if current.CheckSignatureFrom(cand) == nil {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		path = append(path, next)
		onPath[next] = true
		current = certs[next]
	}
	return path
}

func init() {
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_extraneous",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server sent a certificate that is not part of the leaf's chain",
		check:       checkChainExtraneous,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_wrong_intermediate",
		Category:    categoryRemote,
		Severity:    SeverityCritical,
		Description: "Server sent a CA with the right name whose signature does not match",
		check:       checkChainWrongIntermediate,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_order",
		Category:    categoryRemote,
		Severity:    SeverityInfo,
		Description: "Served certificates are not in issuance order from the leaf",
		check:       checkRemoteChainOrder,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_sent_root",
		Category:    categoryRemote,
		Severity:    SeverityInfo,
		Description: "Server sends the self-signed root, which every client already has or does not trust",
		check:       checkChainSentRoot,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "must_staple_no_staple",
		Category:    categoryRemote,
		Severity:    SeverityCritical,
		Description: "Certificate requires a stapled OCSP response and the server did not send one",
		check:       checkMustStaple,
	})
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_platform_rejects",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "This machine's own verifier rejects a chain that reaches a trusted root",
		check:       checkPlatformRejects,
	})
}

// checkChainExtraneous: bytes on every handshake that no client can use, and
// usually the sign of a bundle assembled by hand.
func checkChainExtraneous(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) < 2 {
		return nil
	}

	onPath := make(map[int]bool)
	for _, i := range servedPath(ctx.Certificates) {
		onPath[i] = true
	}

	var issues []CheckIssue
	for i, cert := range ctx.Certificates {
		if onPath[i] {
			continue
		}
		reason := "signed nothing else the server sent"
		for j, other := range ctx.Certificates {
			if i != j && bytes.Equal(cert.RawSubject, other.RawSubject) && bytes.Equal(cert.RawTBSCertificate, other.RawTBSCertificate) {
				reason = "duplicate of another served certificate"
				break
			}
		}
		issues = append(issues, makeRemoteIssue(
			SeverityWarning,
			"remote_chain_extraneous",
			ctx.Target.Address(),
			fmt.Sprintf("Served certificate %d (%s) is not part of the chain: %s", i, FormatDNName(cert.Subject), reason),
			map[string]any{
				"index":   i,
				"subject": FormatDNName(cert.Subject),
				"reason":  reason,
			},
		))
	}
	return issues
}

// checkChainWrongIntermediate is the classic "renewed the leaf, forgot the
// intermediate": a CA with exactly the right subject whose key is not the one
// that signed. The name matching makes it look correct in every listing.
func checkChainWrongIntermediate(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) < 2 {
		return nil
	}

	var issues []CheckIssue
	reported := make(map[string]bool)

	for _, child := range ctx.Certificates {
		if IsSelfSigned(child) {
			continue
		}
		signed := false
		var impostors []*x509.Certificate
		for _, cand := range ctx.Certificates {
			if cand == child || !bytes.Equal(cand.RawSubject, child.RawIssuer) {
				continue
			}
			if child.CheckSignatureFrom(cand) == nil {
				signed = true
				break
			}
			impostors = append(impostors, cand)
		}
		if signed {
			continue
		}
		for _, cand := range impostors {
			key := FormatDNName(child.Subject) + "|" + FormatDNName(cand.Subject)
			if reported[key] {
				continue
			}
			reported[key] = true
			issues = append(issues, makeRemoteIssue(
				SeverityCritical,
				"remote_chain_wrong_intermediate",
				ctx.Target.Address(),
				fmt.Sprintf("Served CA %q has the issuer name of %q but did not sign it (signature does not verify)",
					FormatDNName(cand.Subject), FormatDNName(child.Subject)),
				map[string]any{
					"ca":      FormatDNName(cand.Subject),
					"subject": FormatDNName(child.Subject),
				},
			))
		}
	}
	return issues
}

// checkRemoteChainOrder: RFC 8446 lets the certificates after the leaf come in any
// order, so this is information, not a fault. Clients that still care exist.
func checkRemoteChainOrder(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) < 2 {
		return nil
	}

	path := servedPath(ctx.Certificates)
	if len(path) < 2 {
		return nil
	}
	ordered := true
	for i, idx := range path {
		if idx != i {
			ordered = false
			break
		}
	}
	if ordered {
		return nil
	}

	return []CheckIssue{makeRemoteIssue(
		SeverityInfo,
		"remote_chain_order",
		ctx.Target.Address(),
		"Served certificates are not in issuance order from the leaf (allowed by TLS 1.3, rejected by some older clients)",
		map[string]any{"path": path},
	)}
}

// checkChainSentRoot: the root is either already trusted by the client, in
// which case it is wasted bytes on every handshake, or it is not, in which case
// sending it changes nothing.
func checkChainSentRoot(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) < 2 {
		return nil
	}

	var issues []CheckIssue
	for i, cert := range ctx.Certificates {
		if i == 0 {
			continue // a self-signed leaf is remote_self_signed, a different fault
		}
		if cert.IsCA && IsSelfSigned(cert) {
			issues = append(issues, makeRemoteIssue(
				SeverityInfo,
				"remote_chain_sent_root",
				ctx.Target.Address(),
				fmt.Sprintf("Server sends the self-signed root %q, which clients do not need", FormatDNName(cert.Subject)),
				map[string]any{"index": i, "subject": FormatDNName(cert.Subject)},
			))
		}
	}
	return issues
}

// checkPlatformRejects reports the operating system's own opinion when it
// disagrees with the pool verdict. certdiag's TRUST vocabulary is built on the
// explicit pool alone; the platform additionally applies policy (Certificate
// Transparency, distrust dates, OS revocation), and that difference is worth
// knowing on the machine the user is sitting at. When the pool verdict is
// already untrusted, remote_chain_untrusted has said so and this stays quiet.
func checkPlatformRejects(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 || ctx.Roots == nil || ctx.PlatformVerify == nil {
		return nil
	}

	leaf := ctx.Certificates[0]
	intermediates := ctx.IntermediatePool()

	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         ctx.Roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil
	}

	err := ctx.PlatformVerify(leaf, intermediates)
	if err == nil {
		return nil
	}

	return []CheckIssue{makeRemoteIssue(
		SeverityWarning,
		"remote_platform_rejects",
		ctx.Target.Address(),
		fmt.Sprintf("The chain reaches a trusted root, but this machine's verifier rejects it: %v", err),
		map[string]any{"platform_error": err.Error()},
	)}
}

// checkMustStaple: a certificate carrying the TLS Feature status_request
// extension is telling clients to reject it when no stapled response arrives.
// A missing staple is ordinarily an observation; here it is a failure the
// server chose to opt into.
func checkMustStaple(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 {
		return nil
	}
	leaf := ctx.Certificates[0]
	if !extensions.Parse(leaf).MustStaple {
		return nil
	}
	if ctx.TLSInfo.OCSPStapled {
		return nil
	}
	return []CheckIssue{makeRemoteIssue(
		SeverityCritical,
		"must_staple_no_staple",
		ctx.Target.Address(),
		"Certificate requires a stapled OCSP response (TLS Feature status_request) but the server sent none; strict clients reject this",
		map[string]any{"must_staple": true, "stapled": false},
	)}
}
