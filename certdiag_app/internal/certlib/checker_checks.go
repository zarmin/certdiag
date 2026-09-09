package certlib

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
	"math"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func init() {
	registerExpiryChecks()
	registerKeyStrengthChecks()
	registerAlgorithmChecks()
	registerConfigChecks()
	registerChainChecks()
	registerStructureChecks()
	registerInfoChecks()
	registerRevocationChecks()
	registerTrustChecks()
}

// --- expiry checks ---

// wholeDays truncates a duration to whole days. Truncation is the
// conservative direction for alerting: a certificate with 7 days and one hour
// left is "7 days" and still inside a 7-day threshold.
func wholeDays(d time.Duration) int {
	return int(d.Hours() / 24)
}

// daysPhrase says "less than a day" instead of "0 days".
func daysPhrase(days int) string {
	switch days {
	case 0:
		return "less than a day"
	case 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

func checkExpired(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	now := time.Now()
	if cert.NotAfter.Before(now) {
		days := wholeDays(now.Sub(cert.NotAfter))
		msg := fmt.Sprintf("Expired %s ago (%s)", daysPhrase(days), cert.NotAfter.Format("2006-01-02"))
		return []CheckIssue{makeIssue(SeverityCritical, "expiry", "expired", c, item, ref, msg, map[string]any{
			"not_after":    cert.NotAfter.Format(time.RFC3339),
			"days_expired": days,
		})}
	}
	return nil
}

func checkExpiringSoonCritical(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	now := time.Now()
	if cert.NotAfter.Before(now) {
		return nil // handled by expired check
	}
	daysLeft := wholeDays(time.Until(cert.NotAfter))
	if daysLeft <= opts.ExpiryCriticalDays {
		msg := fmt.Sprintf("Expires in %s (%s)", daysPhrase(daysLeft), cert.NotAfter.Format("2006-01-02"))
		return []CheckIssue{makeIssue(SeverityCritical, "expiry", "expiring_soon_critical", c, item, ref, msg, map[string]any{
			"not_after": cert.NotAfter.Format(time.RFC3339),
			"days_left": daysLeft,
			"threshold": opts.ExpiryCriticalDays,
		})}
	}
	return nil
}

func checkExpiringSoonWarning(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	now := time.Now()
	if cert.NotAfter.Before(now) {
		return nil
	}
	daysLeft := wholeDays(time.Until(cert.NotAfter))
	if daysLeft > opts.ExpiryCriticalDays && daysLeft <= opts.ExpiryWarnDays {
		msg := fmt.Sprintf("Expires in %s (%s)", daysPhrase(daysLeft), cert.NotAfter.Format("2006-01-02"))
		return []CheckIssue{makeIssue(SeverityWarning, "expiry", "expiring_soon_warning", c, item, ref, msg, map[string]any{
			"not_after": cert.NotAfter.Format(time.RFC3339),
			"days_left": daysLeft,
			"threshold": opts.ExpiryWarnDays,
		})}
	}
	return nil
}

func checkNotYetValid(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	now := time.Now()
	if cert.NotBefore.After(now) {
		daysUntil := wholeDays(time.Until(cert.NotBefore))
		msg := fmt.Sprintf("Not yet valid (starts %s, %s from now)", cert.NotBefore.Format("2006-01-02"), daysPhrase(daysUntil))
		return []CheckIssue{makeIssue(SeverityWarning, "expiry", "not_yet_valid", c, item, ref, msg, map[string]any{
			"not_before": cert.NotBefore.Format(time.RFC3339),
			"days_until": daysUntil,
		})}
	}
	return nil
}

// --- key_strength checks ---

func getRSABits(item *CertItem) (int, bool) {
	if item.Certificate != nil {
		if pub, ok := item.Certificate.PublicKey.(*rsa.PublicKey); ok {
			return pub.N.BitLen(), true
		}
	}
	if item.PrivateKey != nil {
		if priv, ok := item.PrivateKey.(*rsa.PrivateKey); ok {
			return priv.N.BitLen(), true
		}
	}
	return 0, false
}

func checkVeryWeakRSA(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	bits, ok := getRSABits(item)
	if !ok {
		return nil
	}
	if bits < 1024 {
		msg := fmt.Sprintf("Very weak RSA key (%d bits)", bits)
		return []CheckIssue{makeIssue(SeverityCritical, "key_strength", "very_weak_rsa", c, item, ref, msg, map[string]any{
			"algorithm": "RSA", "key_bits": bits,
		})}
	}
	return nil
}

func checkWeakRSA(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	bits, ok := getRSABits(item)
	if !ok {
		return nil
	}
	if bits >= 1024 && bits < 2048 {
		msg := fmt.Sprintf("Weak RSA key (%d bits)", bits)
		return []CheckIssue{makeIssue(SeverityWarning, "key_strength", "weak_rsa", c, item, ref, msg, map[string]any{
			"algorithm": "RSA", "key_bits": bits, "recommended_bits": 2048,
		})}
	}
	return nil
}

func checkWeakECCurve(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	var curve elliptic.Curve
	if item.Certificate != nil {
		if pub, ok := item.Certificate.PublicKey.(*ecdsa.PublicKey); ok {
			curve = pub.Curve
		}
	}
	if item.PrivateKey != nil {
		if priv, ok := item.PrivateKey.(*ecdsa.PrivateKey); ok {
			curve = priv.Curve
		}
	}
	if curve == nil {
		return nil
	}
	bits := curve.Params().BitSize
	if bits < 256 {
		msg := fmt.Sprintf("Weak ECDSA curve (%s, %d bits)", curve.Params().Name, bits)
		return []CheckIssue{makeIssue(SeverityWarning, "key_strength", "weak_ec_curve", c, item, ref, msg, map[string]any{
			"algorithm": "ECDSA", "curve": curve.Params().Name, "bits": bits,
		})}
	}
	return nil
}

func checkRSAExponent(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	var exp int
	if item.Certificate != nil {
		if pub, ok := item.Certificate.PublicKey.(*rsa.PublicKey); ok {
			exp = pub.E
		}
	}
	if item.PrivateKey != nil {
		if priv, ok := item.PrivateKey.(*rsa.PrivateKey); ok {
			exp = priv.E
		}
	}
	if exp == 0 {
		return nil
	}
	if exp != 65537 {
		msg := fmt.Sprintf("RSA public exponent is %d (expected 65537)", exp)
		return []CheckIssue{makeIssue(SeverityWarning, "key_strength", "rsa_exponent", c, item, ref, msg, map[string]any{
			"exponent": exp, "expected": 65537,
		})}
	}
	return nil
}

func checkDeprecatedKey(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	isDSA := false
	if item.Certificate != nil {
		if _, ok := item.Certificate.PublicKey.(*dsa.PublicKey); ok {
			isDSA = true
		}
	}
	if item.PrivateKey != nil {
		if _, ok := item.PrivateKey.(*dsa.PrivateKey); ok {
			isDSA = true
		}
	}
	if isDSA {
		return []CheckIssue{makeIssue(SeverityWarning, "key_strength", "deprecated_key", c, item, ref,
			"Deprecated key type (DSA)", map[string]any{"algorithm": "DSA"})}
	}
	return nil
}

// --- algorithm checks ---

func checkMD5Sig(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	algo := item.Certificate.SignatureAlgorithm
	if algo == x509.MD5WithRSA || algo == x509.MD2WithRSA {
		msg := fmt.Sprintf("MD5 signature algorithm (%s)", algo.String())
		return []CheckIssue{makeIssue(SeverityCritical, "algorithm", "md5_sig", c, item, ref, msg, map[string]any{
			"signature_algorithm": algo.String(),
		})}
	}
	return nil
}

func checkSHA1Sig(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	algo := item.Certificate.SignatureAlgorithm
	if algo == x509.SHA1WithRSA || algo == x509.ECDSAWithSHA1 {
		msg := fmt.Sprintf("SHA-1 signature algorithm (%s)", algo.String())
		return []CheckIssue{makeIssue(SeverityWarning, "algorithm", "sha1_sig", c, item, ref, msg, map[string]any{
			"signature_algorithm": algo.String(),
		})}
	}
	return nil
}

func checkSigMismatch(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil || len(item.RawBytes) == 0 {
		return nil
	}
	// Parse the raw DER to compare outer and TBS signature algorithm OIDs
	var cert struct {
		TBSCertificate struct {
			Raw                asn1.RawContent
			Version            asn1.RawValue `asn1:"optional,explicit,tag:0"`
			SerialNumber       *big.Int
			SignatureAlgorithm asn1.RawValue
		}
		SignatureAlgorithm asn1.RawValue
	}
	raw := item.RawBytes
	if raw == nil && item.Certificate != nil {
		raw = item.Certificate.Raw
	}
	if raw == nil {
		return nil
	}
	if _, err := asn1.Unmarshal(raw, &cert); err != nil {
		return nil
	}
	if !asn1Equal(cert.TBSCertificate.SignatureAlgorithm.FullBytes, cert.SignatureAlgorithm.FullBytes) {
		return []CheckIssue{makeIssue(SeverityWarning, "algorithm", "sig_mismatch", c, item, ref,
			"Outer and TBS signature algorithms differ", map[string]any{
				"outer_algorithm": item.Certificate.SignatureAlgorithm.String(),
			})}
	}
	return nil
}

func asn1Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- config checks ---

func checkUnprotectedKey(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Type != ContentPrivateKey {
		return nil
	}
	if !item.Encrypted && c.Format == FormatPEM {
		return []CheckIssue{makeIssue(SeverityInfo, "config", "unprotected_key", c, item, ref,
			"Private key not password-protected", nil)}
	}
	return nil
}

func checkEmptyPassword(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Type != ContentPrivateKey {
		return nil
	}
	if c.Password != nil && len(c.Password) == 0 {
		return []CheckIssue{makeIssue(SeverityInfo, "config", "empty_password", c, item, ref,
			"Protected with empty password", nil)}
	}
	if item.EntryPassword != nil && len(item.EntryPassword) == 0 {
		return []CheckIssue{makeIssue(SeverityInfo, "config", "empty_password", c, item, ref,
			"Key entry protected with empty password", nil)}
	}
	return nil
}

func checkEntryPasswordMismatch(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Type != ContentPrivateKey || item.EntryPassword == nil {
		return nil
	}
	if !bytes.Equal(item.EntryPassword, c.Password) {
		msg := fmt.Sprintf("Key entry '%s' uses a different password than the store", item.Alias)
		return []CheckIssue{makeIssue(SeverityInfo, "config", "entry_password_mismatch", c, item, ref, msg, nil)}
	}
	return nil
}

func checkMissingSANs(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	// A CN-only CA is normal; the SAN expectation is a leaf expectation.
	if item.Certificate == nil || item.Certificate.IsCA {
		return nil
	}
	cert := item.Certificate
	if cert.Subject.CommonName != "" &&
		len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 &&
		len(cert.EmailAddresses) == 0 && len(cert.URIs) == 0 {
		return []CheckIssue{makeIssue(SeverityInfo, "config", "missing_sans", c, item, ref,
			"Missing SANs (CN-only, deprecated by browsers)", map[string]any{
				"cn": cert.Subject.CommonName,
			})}
	}
	return nil
}

func checkCANoKeyUsage(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil || !item.Certificate.IsCA {
		return nil
	}
	if item.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return []CheckIssue{makeIssue(SeverityWarning, "config", "ca_no_keyusage", c, item, ref,
			"CA cert missing keyCertSign in key usage", nil)}
	}
	return nil
}

func checkCANoBC(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	// Check if cert acts as CA (has keyCertSign) but has no BasicConstraints
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 && !cert.BasicConstraintsValid {
		return []CheckIssue{makeIssue(SeverityWarning, "config", "ca_no_bc", c, item, ref,
			"CA cert missing BasicConstraints extension", nil)}
	}
	return nil
}

func checkLeafCertSign(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	if !cert.IsCA && cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return []CheckIssue{makeIssue(SeverityWarning, "config", "leaf_certsign", c, item, ref,
			"Non-CA cert has keyCertSign key usage (possible misconfiguration)", nil)}
	}
	return nil
}

func checkIPInCN(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cn := item.Certificate.Subject.CommonName
	if cn == "" {
		return nil
	}
	ip := net.ParseIP(cn)
	if ip == nil {
		return nil
	}
	for _, sanIP := range item.Certificate.IPAddresses {
		if sanIP.Equal(ip) {
			return nil
		}
	}
	return []CheckIssue{makeIssue(SeverityInfo, "config", "ip_in_cn", c, item, ref,
		fmt.Sprintf("IP address %s in CN but not in SAN", cn), map[string]any{
			"cn_ip": cn,
		})}
}

// --- chain checks ---

func checkChainIncomplete(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, relIndex RelationIndex, store *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	if IsSelfSigned(cert) {
		return nil
	}
	if rels, ok := relIndex[ref]; ok {
		for _, r := range rels {
			if r.Type != RelationSignedBy || r.Direction != DirectionOutgoing {
				continue
			}
			// An issuer that came from a synthesized trust store completes the
			// chain for trust purposes but not for the file, which is what this
			// check is about. The TRUST column carries the trust answer.
			if RefFromTrustStore(r.Peer, store) {
				continue
			}
			return nil
		}
	}
	issuerCN := cert.Issuer.CommonName
	if issuerCN == "" {
		issuerCN = FormatDNName(cert.Issuer)
	}
	where := "not found in scan"
	if c.Source == SourceRemote {
		where = "not served by the endpoint"
	}
	details := map[string]any{"issuer": FormatDNName(cert.Issuer)}

	// Whether the machine trusts the chain anyway is known only when trust was
	// evaluated (--trust); the answer then comes from the same explicit pool
	// as the TRUST column, never from a second engine. Without it the check
	// says what it knows, which is that the file is incomplete.
	if opts.TrustIndex != nil {
		d := opts.TrustIndex.Detail(cert)
		if d.Verdict == truststore.VerdictTrusted || d.Verdict == truststore.VerdictAnchor {
			details["trust"] = string(d.Verdict)
			if d.Anchor != nil {
				details["anchor"] = FormatDNName(d.Anchor.Subject)
			}
			return []CheckIssue{makeIssue(SeverityInfo, "chain", "chain_incomplete", c, item, ref,
				fmt.Sprintf("Issuer %q %s; the chain completes through the trust store", issuerCN, where), details)}
		}
	}
	return []CheckIssue{makeIssue(SeverityWarning, "chain", "chain_incomplete", c, item, ref,
		fmt.Sprintf("Chain incomplete: issuer %q %s", issuerCN, where), details)}
}

func checkChainOrder(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, store *CertStore) []CheckIssue {
	if item.Certificate == nil || c.Format != FormatPEM {
		return nil
	}
	// Only flag if this is a bundle (multiple items) and the first cert is a CA (not a leaf)
	if ref.ItemIdx != 0 {
		return nil // only check once per container
	}
	if len(c.Items) < 2 {
		return nil
	}
	firstCert := c.Items[0].Certificate
	if firstCert == nil {
		return nil
	}
	if firstCert.IsCA && !IsSelfSigned(firstCert) {
		// First cert is an intermediate CA - likely wrong order
		// Check if there's a non-CA cert later in the chain
		for _, other := range c.Items[1:] {
			if other.Certificate != nil && !other.Certificate.IsCA {
				return []CheckIssue{makeIssue(SeverityInfo, "chain", "chain_order", c, item, ref,
					"PEM chain in wrong order (leaf should be first)", nil)}
			}
		}
	}
	return nil
}

func checkKeyCertMismatch(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, relIndex RelationIndex, store *CertStore) []CheckIssue {
	// Key-centric: flag a private key only when it matches NO certificate in the
	// same container. Checking per-certificate produced false positives on every
	// intermediate/root of a valid key+fullchain bundle (they legitimately do not
	// match the leaf's key).
	if item.Type != ContentPrivateKey || item.PrivateKey == nil {
		return nil
	}
	hasCert := false
	for i := range c.Items {
		other := &c.Items[i]
		if other.Type != ContentCertificate || other.Certificate == nil {
			continue
		}
		hasCert = true
		if KeyMatchesCert(item.PrivateKey, other.Certificate) {
			return nil // key matches at least one cert in the bundle
		}
	}
	if !hasCert {
		return nil // key-only container: nothing to compare against
	}
	return []CheckIssue{makeIssue(SeverityWarning, "chain", "key_cert_mismatch", c, item, ref,
		"Private key does not match any certificate in the bundle", nil)}
}

// --- structure checks ---

func checkSerial(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	serial := item.Certificate.SerialNumber
	if serial == nil {
		return []CheckIssue{makeIssue(SeverityWarning, "structure", "serial", c, item, ref,
			"Serial number is missing", nil)}
	}
	if serial.Sign() <= 0 {
		msg := "Serial number is zero"
		if serial.Sign() < 0 {
			msg = "Serial number is negative"
		}
		return []CheckIssue{makeIssue(SeverityWarning, "structure", "serial", c, item, ref, msg, map[string]any{
			"serial": serial.String(),
		})}
	}
	if len(serial.Bytes()) > 20 {
		return []CheckIssue{makeIssue(SeverityWarning, "structure", "serial", c, item, ref,
			fmt.Sprintf("Serial number is too long (%d octets, max 20)", len(serial.Bytes())), map[string]any{
				"serial_octets": len(serial.Bytes()),
			})}
	}
	return nil
}

func checkVersion(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	if cert.Version < 3 && len(cert.Extensions) > 0 {
		return []CheckIssue{makeIssue(SeverityInfo, "structure", "version", c, item, ref,
			fmt.Sprintf("Certificate v%d uses extensions (should be v3)", cert.Version), map[string]any{
				"version":    cert.Version,
				"extensions": len(cert.Extensions),
			})}
	}
	if cert.Version == 1 && len(cert.Extensions) == 0 {
		return []CheckIssue{makeIssue(SeverityWarning, "structure", "version", c, item, ref,
			"Certificate is X.509 v1 (no extensions support)", map[string]any{
				"version": cert.Version,
			})}
	}
	return nil
}

func checkUnknownExt(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	for _, ext := range item.Certificate.Extensions {
		if ext.Critical && !extensions.Known(ext.Id) {
			return []CheckIssue{makeIssue(SeverityInfo, "structure", "unknown_ext", c, item, ref,
				fmt.Sprintf("Non-standard critical extension (%s)", ext.Id.String()), map[string]any{
					"oid": ext.Id.String(),
				})}
		}
	}
	return nil
}

func checkLongValidity(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil || item.Certificate.IsCA {
		return nil
	}
	cert := item.Certificate
	days := int(math.Ceil(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24))
	limit, since := LeafValidityLimit(cert.NotBefore)
	if days > limit {
		return []CheckIssue{makeIssue(SeverityInfo, "structure", "long_validity", c, item, ref,
			fmt.Sprintf("Leaf cert valid for %d days (> %d day CA/B Forum limit for certificates issued since %s)", days, limit, since.Format("2006-01-02")), map[string]any{
				"validity_days": days,
				"limit_days":    limit,
				"limit_since":   since.Format("2006-01-02"),
			})}
	}
	return nil
}

// --- info checks ---

func checkSelfSignedLeaf(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	cert := item.Certificate
	if !cert.IsCA && IsSelfSigned(cert) {
		return []CheckIssue{makeIssue(SeverityInfo, "info", "self_signed_leaf", c, item, ref,
			"Self-signed leaf certificate", nil)}
	}
	return nil
}

func checkWildcard(c *CertContainer, item *CertItem, ref ItemRef, opts CheckOptions, _ RelationIndex, _ *CertStore) []CheckIssue {
	if item.Certificate == nil {
		return nil
	}
	var wildcards []string
	for _, dns := range item.Certificate.DNSNames {
		if strings.HasPrefix(dns, "*.") {
			wildcards = append(wildcards, dns)
		}
	}
	if len(wildcards) > 0 {
		return []CheckIssue{makeIssue(SeverityInfo, "info", "wildcard", c, item, ref,
			fmt.Sprintf("Wildcard certificate (%s)", strings.Join(wildcards, ", ")), map[string]any{
				"wildcards": wildcards,
			})}
	}
	return nil
}
