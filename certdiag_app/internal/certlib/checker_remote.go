package certlib

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

const categoryRemote = "remote"

// RemoteCheckContext holds all the data needed for remote-specific checks.
type RemoteCheckContext struct {
	Target       RemoteTarget
	TLSInfo      TLSConnectionInfo
	Certificates []*x509.Certificate
	AIACerts     []*x509.Certificate
	// Revocation is the leaf's revocation result. Non-nil when a staple was
	// present (always parsed) or live revocation was requested.
	Revocation *RevocationResult

	// Roots is the trust anchor pool the verdict is built from. It is always an
	// explicit pool built from the OS store contents (M30a option A): a nil pool
	// routes x509.Verify to the platform verifier, whose answer differs per OS
	// and cannot be tested. When nil, the trust checks do not run at all rather
	// than quietly falling back.
	Roots *x509.CertPool

	// PlatformVerify, when set, asks the operating system's own verifier for a
	// second opinion. It is reported separately from the verdict, never folded
	// into it: the platform applies policy (CT, distrust dates, OS revocation)
	// that the pool does not. Nil on platforms without one, and in tests.
	PlatformVerify func(leaf *x509.Certificate, intermediates *x509.CertPool) error
}

// RemoteCheckDefinition defines a remote-specific check.
type RemoteCheckDefinition struct {
	ID          string
	Category    string
	Severity    CheckSeverity
	Description string
	check       remoteCheckFunc
}

type remoteCheckFunc func(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue

var allRemoteChecks []RemoteCheckDefinition

func registerRemoteCheck(def RemoteCheckDefinition) {
	allRemoteChecks = append(allRemoteChecks, def)
}

// AllRemoteChecks returns all registered remote check definitions.
func AllRemoteChecks() []RemoteCheckDefinition {
	return allRemoteChecks
}

// RunRemoteChecks runs remote-specific checks against the given context.
func RunRemoteChecks(ctx RemoteCheckContext, opts CheckOptions) *CheckResult {
	opts = opts.Defaults()

	disabledSet := make(map[string]bool, len(opts.DisabledChecks))
	for _, id := range opts.DisabledChecks {
		disabledSet[id] = true
	}

	categorySet := make(map[string]bool, len(opts.Categories))
	for _, cat := range opts.Categories {
		categorySet[cat] = true
	}

	result := &CheckResult{}

	for _, def := range allRemoteChecks {
		if disabledSet[def.ID] {
			continue
		}
		if len(categorySet) > 0 && !categorySet[def.Category] {
			continue
		}

		issues := def.check(ctx, opts)
		for _, issue := range issues {
			if opts.MinSeverity != "" && issue.Severity.Rank() < opts.MinSeverity.Rank() {
				continue
			}
			result.Issues = append(result.Issues, issue)
		}
	}

	for _, issue := range result.Issues {
		switch issue.Severity {
		case SeverityCritical:
			result.Summary.Critical++
		case SeverityWarning:
			result.Summary.Warning++
		case SeverityInfo:
			result.Summary.Info++
		}
	}

	return result
}

func makeRemoteIssue(sev CheckSeverity, checkID, target, msg string, details map[string]any) CheckIssue {
	return CheckIssue{
		Severity: sev,
		Category: categoryRemote,
		CheckID:  checkID,
		FilePath: target,
		Filename: target,
		Message:  msg,
		Details:  details,
	}
}

func init() {
	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_untrusted",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server's chain doesn't validate against system trust store",
		check:       checkChainUntrusted,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_hostname_mismatch",
		Category:    categoryRemote,
		Severity:    SeverityCritical,
		Description: "Certificate doesn't match target hostname",
		check:       checkHostnameMismatch,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_chain_incomplete",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server doesn't send intermediates, only leaf",
		check:       checkRemoteChainIncomplete,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_self_signed",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server presents a self-signed leaf certificate",
		check:       checkSelfSigned,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_no_ocsp_staple",
		Category:    categoryRemote,
		Severity:    SeverityInfo,
		Description: "Server doesn't provide OCSP stapling",
		check:       checkNoOCSPStaple,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_weak_tls",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Server negotiated TLS 1.0 or 1.1",
		check:       checkWeakTLS,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_weak_cipher",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "Negotiated cipher uses RC4, 3DES, or NULL",
		check:       checkWeakCipher,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_no_alpn",
		Category:    categoryRemote,
		Severity:    SeverityInfo,
		Description: "Server doesn't negotiate any ALPN protocol",
		check:       checkNoALPN,
	})

	registerRemoteCheck(RemoteCheckDefinition{
		ID:          "remote_sni_mismatch",
		Category:    categoryRemote,
		Severity:    SeverityWarning,
		Description: "SNI was sent but cert doesn't match the sent SNI",
		check:       checkSNIMismatch,
	})
}

func checkChainUntrusted(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 {
		return nil
	}

	leaf := ctx.Certificates[0]

	if ctx.Roots == nil {
		return nil
	}
	intermediates := ctx.IntermediatePool()

	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         ctx.Roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(verifyOpts)
	if err != nil {
		return []CheckIssue{makeRemoteIssue(
			SeverityWarning,
			"remote_chain_untrusted",
			ctx.Target.Address(),
			fmt.Sprintf("Chain not trusted: %v", err),
			map[string]any{
				"verify_error": err.Error(),
				"chain_length": len(ctx.Certificates),
			},
		)}
	}
	return nil
}

func checkHostnameMismatch(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 {
		return nil
	}

	leaf := ctx.Certificates[0]
	host := expectedRemoteHostname(ctx)
	if host == "" {
		return nil
	}

	err := leaf.VerifyHostname(host)
	if err != nil {
		return []CheckIssue{makeRemoteIssue(
			SeverityCritical,
			"remote_hostname_mismatch",
			ctx.Target.Address(),
			fmt.Sprintf("Hostname mismatch: %v", err),
			map[string]any{
				"hostname":     host,
				"verify_error": err.Error(),
				"sans":         FormatSANs(leaf),
			},
		)}
	}
	return nil
}

func checkRemoteChainIncomplete(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) < 2 {
		// Only leaf sent, no intermediates
		if len(ctx.Certificates) == 1 {
			leaf := ctx.Certificates[0]
			// Self-signed certs are handled by a different check
			if leaf.Subject.String() == leaf.Issuer.String() {
				return nil
			}
			// Say whether the issuer was fetched over AIA: with AIA off (the
			// default) the finding is what a client on this network sees.
			msg := "Server only sent leaf certificate, no intermediates"
			details := map[string]any{
				"chain_length":   1,
				"missing_issuer": FormatDNName(leaf.Issuer),
			}
			if len(leaf.IssuingCertificateURL) > 0 {
				details["aia_issuer_url"] = leaf.IssuingCertificateURL[0]
				if len(ctx.AIACerts) > 0 {
					msg += " (issuer fetched over AIA)"
				} else {
					msg += " (issuer not fetched over AIA)"
				}
			}
			// When the issuer sits in this machine's own store the chain
			// completes here regardless; that is an info for this host and a
			// warning only for clients that do not carry the issuer.
			if anchor := localAnchorFor(leaf, ctx.Roots); anchor != nil {
				details["anchor"] = FormatDNName(anchor.Subject)
				return []CheckIssue{makeRemoteIssue(
					SeverityInfo,
					"remote_chain_incomplete",
					ctx.Target.Address(),
					"Server only sent the leaf; its issuer is in the local trust store, clients without it will fail",
					details,
				)}
			}
			return []CheckIssue{makeRemoteIssue(
				SeverityWarning,
				"remote_chain_incomplete",
				ctx.Target.Address(),
				msg,
				details,
			)}
		}
	}
	return nil
}

// localAnchorFor returns the store certificate that terminates a path from the
// leaf built from the local store alone, nil when there is none.
func localAnchorFor(leaf *x509.Certificate, roots *x509.CertPool) *x509.Certificate {
	if roots == nil {
		return nil
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(chains) == 0 || len(chains[0]) == 0 {
		return nil
	}
	return chains[0][len(chains[0])-1]
}

func checkSelfSigned(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 {
		return nil
	}

	leaf := ctx.Certificates[0]

	selfSignatureOK := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	if leaf.Subject.String() == leaf.Issuer.String() && selfSignatureOK {
		return []CheckIssue{makeRemoteIssue(
			SeverityWarning,
			"remote_self_signed",
			ctx.Target.Address(),
			"Self-signed server certificate",
			nil,
		)}
	}
	return nil
}

func checkNoOCSPStaple(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if !ctx.TLSInfo.OCSPStapled {
		return []CheckIssue{makeRemoteIssue(
			SeverityInfo,
			"remote_no_ocsp_staple",
			ctx.Target.Address(),
			"No OCSP stapling",
			nil,
		)}
	}
	return nil
}

func checkWeakTLS(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	v := ctx.TLSInfo.Version
	if v == tls.VersionTLS10 || v == tls.VersionTLS11 {
		return []CheckIssue{makeRemoteIssue(
			SeverityWarning,
			"remote_weak_tls",
			ctx.Target.Address(),
			fmt.Sprintf("Weak TLS version: %s", ctx.TLSInfo.VersionName),
			map[string]any{
				"tls_version": ctx.TLSInfo.VersionName,
			},
		)}
	}
	return nil
}

func checkWeakCipher(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	name := strings.ToUpper(ctx.TLSInfo.CipherSuiteName)
	weak := false
	reason := ""

	if strings.Contains(name, "RC4") {
		weak = true
		reason = "RC4"
	} else if strings.Contains(name, "3DES") || strings.Contains(name, "DES_CBC3") {
		weak = true
		reason = "3DES"
	} else if strings.Contains(name, "NULL") {
		weak = true
		reason = "NULL"
	}

	if weak {
		return []CheckIssue{makeRemoteIssue(
			SeverityWarning,
			"remote_weak_cipher",
			ctx.Target.Address(),
			fmt.Sprintf("Weak cipher: %s (%s)", ctx.TLSInfo.CipherSuiteName, reason),
			map[string]any{
				"cipher_suite": ctx.TLSInfo.CipherSuiteName,
				"weakness":     reason,
			},
		)}
	}
	return nil
}

func checkNoALPN(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	// Only an offer that went unanswered says something about the server.
	if len(ctx.TLSInfo.ALPNOffered) == 0 || ctx.TLSInfo.NegotiatedProto != "" {
		return nil
	}
	return []CheckIssue{makeRemoteIssue(
		SeverityInfo,
		"remote_no_alpn",
		ctx.Target.Address(),
		fmt.Sprintf("No ALPN protocol negotiated (offered: %s)", strings.Join(ctx.TLSInfo.ALPNOffered, ", ")),
		map[string]any{"offered": ctx.TLSInfo.ALPNOffered},
	)}
}

func checkSNIMismatch(ctx RemoteCheckContext, opts CheckOptions) []CheckIssue {
	if len(ctx.Certificates) == 0 {
		return nil
	}

	sni := ctx.TLSInfo.ServerName
	if sni == "" {
		return nil // No SNI sent, nothing to check
	}
	// When the SNI is the name the hostname check verifies, one mismatch must
	// not be reported twice (M31 WP12).
	if sni == expectedRemoteHostname(ctx) {
		return nil
	}

	leaf := ctx.Certificates[0]
	err := leaf.VerifyHostname(sni)
	if err != nil {
		return []CheckIssue{makeRemoteIssue(
			SeverityWarning,
			"remote_sni_mismatch",
			ctx.Target.Address(),
			fmt.Sprintf("SNI mismatch: cert doesn't match SNI %q", sni),
			map[string]any{
				"sni":          sni,
				"sans":         FormatSANs(leaf),
				"verify_error": err.Error(),
			},
		)}
	}
	return nil
}

// expectedRemoteHostname is the name the certificate is expected to match:
// the SNI when one was sent (--hostname, or the target's own name), else the
// target host.
func expectedRemoteHostname(ctx RemoteCheckContext) string {
	if ctx.TLSInfo.ServerName != "" {
		return ctx.TLSInfo.ServerName
	}
	return ctx.Target.Host
}
