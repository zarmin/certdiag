package output

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

func FormatListView(container *certlib.CertContainer, containerIdx int, options OutputOptions) string {
	var sb strings.Builder

	hasKey := false
	hasCert := false
	hasCSR := false
	for _, item := range container.Items {
		if item.Type == certlib.ContentPrivateKey {
			hasKey = true
		}
		if item.Type == certlib.ContentCertificate {
			hasCert = true
		}
		if item.Type == certlib.ContentCSR {
			hasCSR = true
		}
	}

	filename := filepath.Base(container.FilePath)
	coloredFilename := ColorizeFilename(filename, hasKey, hasCert, hasCSR)
	sb.WriteString(fmt.Sprintf("%s [%s]\n", coloredFilename, container.Format))
	sb.WriteString(formatPasswordInfo(container))
	if options.Details() {
		sb.WriteString(formatFileMetadata(container))
	}

	sb.WriteString(formatContainerItems(container, containerIdx, options))

	for _, err := range container.ParseErrors {
		sb.WriteString(fmt.Sprintf("  ! %s\n", ColorizeError(fmt.Sprintf("Error: %s", err))))
	}

	return sb.String()
}

func formatPasswordInfo(container *certlib.CertContainer) string {
	if len(container.UnlockSources) > 0 {
		parts := make([]string, len(container.UnlockSources))
		for i, s := range container.UnlockSources {
			parts[i] = string(s)
		}
		return fmt.Sprintf("  password: unlocked via %s\n", strings.Join(parts, ", "))
	}
	for _, e := range container.ParseErrors {
		if strings.Contains(e, "password required") || strings.Contains(e, "failed to decrypt") {
			return "  password: locked\n"
		}
	}
	return "  password: not protected\n"
}

func formatFileMetadata(container *certlib.CertContainer) string {
	var sb strings.Builder
	absPath, err := filepath.Abs(container.FilePath)
	if err == nil {
		sb.WriteString(fmt.Sprintf("  path:     %s\n", absPath))
	}
	sb.WriteString(fmt.Sprintf("  size:     %s\n", FormatFileSize(container.FileSize)))
	if !container.FileModTime.IsZero() {
		sb.WriteString(fmt.Sprintf("  modified: %s\n", container.FileModTime.Format(time.DateTime)))
	}
	if !container.FileAccessTime.IsZero() {
		sb.WriteString(fmt.Sprintf("  accessed: %s\n", container.FileAccessTime.Format(time.DateTime)))
	}
	if !container.FileCreateTime.IsZero() {
		sb.WriteString(fmt.Sprintf("  created:  %s\n", container.FileCreateTime.Format(time.DateTime)))
	}
	return sb.String()
}

func formatItem(item *certlib.CertItem, container *certlib.CertContainer, options OutputOptions) string {
	var sb strings.Builder

	switch item.Type {
	case certlib.ContentCertificate:
		sb.WriteString(formatCertificate(item, options))
	case certlib.ContentPrivateKey:
		sb.WriteString(formatPrivateKey(item, container, options))
	case certlib.ContentPublicKey:
		sb.WriteString(formatPublicKey(item, options))
	case certlib.ContentCSR:
		sb.WriteString(formatCSR(item, options))
	}

	return sb.String()
}

// formatContainerItems renders every item of a container with its relations and
// inline warnings. The file scan and the remote view share it, so a field added
// to one appears in the other instead of drifting.
func formatContainerItems(container *certlib.CertContainer, containerIdx int, options OutputOptions) string {
	var sb strings.Builder
	for ii, item := range container.Items {
		sb.WriteString(formatItem(&item, container, options))
		ref := certlib.ItemRef{
			ContainerIdx: containerIdx,
			ItemIdx:      ii,
			FilePath:     container.FilePath,
			Alias:        item.Alias,
		}
		if options.RelationIndex != nil {
			sb.WriteString(formatRelations(ref, options))
		}
		if options.CheckResult != nil {
			sb.WriteString(formatInlineWarnings(ref, options))
		}
	}
	return sb.String()
}

func formatCertificate(item *certlib.CertItem, options OutputOptions) string {
	var sb strings.Builder
	cert := item.Certificate

	if cert == nil {
		if item.Alias != "" {
			sb.WriteString(fmt.Sprintf("  [%s] Certificate (locked)\n", item.Alias))
		} else {
			sb.WriteString("  Certificate: (failed to parse)\n")
		}
		return sb.String()
	}

	if item.Alias != "" {
		sb.WriteString(fmt.Sprintf("  [%s] Certificate\n", item.Alias))
	} else {
		sb.WriteString("  Certificate\n")
	}

	sb.WriteString(fmt.Sprintf("    Subject:     %s\n", formatDN(cert.Subject)))
	sb.WriteString(fmt.Sprintf("    Issuer:      %s\n", ColorizeIssuer(FormatIssuer(cert), certlib.IsSelfSigned(cert))))
	sb.WriteString(fmt.Sprintf("    Validity:    %s to %s\n",
		ColorizeNotBefore(cert.NotBefore),
		ColorizeExpiry(cert.NotAfter)))
	if options.Details() {
		sb.WriteString(fmt.Sprintf("    Serial:      %s\n", certlib.FormatSerialDetailed(cert.SerialNumber)))
	} else {
		sb.WriteString(fmt.Sprintf("    Serial:      %s\n", certlib.FormatSerial(cert.SerialNumber)))
	}
	sb.WriteString(fmt.Sprintf("    Algorithm:   %s\n", FormatKeyAlgo(cert.PublicKey)))

	if verdict := options.TrustVerdict(cert); verdict != "" {
		sb.WriteString(fmt.Sprintf("    Trust:       %s\n", ColorizeTrust(verdict)))
		if anchor := options.TrustIndex.AnchorFor(cert); anchor != nil && !certlib.IsSelfSigned(cert) {
			sb.WriteString(fmt.Sprintf("    Anchor:      %s\n", FormatSubject(anchor)))
		}
		if hint := options.TrustIndex.Detail(cert).Hint; hint != "" {
			sb.WriteString(fmt.Sprintf("    Trust hint:  %s\n", hint))
		}
	}
	if options.StoreTags != nil {
		if tags := options.StoreTags(cert); len(tags) > 0 {
			sb.WriteString(fmt.Sprintf("    Stores:      %s\n", strings.Join(tags, " ")))
		}
	}

	sans := FormatSANs(cert)
	if sans != "" {
		sb.WriteString(fmt.Sprintf("    SANs:        %s\n", sans))
	}

	if ian := certlib.ParseIssuerAltNames(cert); len(ian) > 0 {
		sb.WriteString(fmt.Sprintf("    Issuer Alt:  %s\n", strings.Join(ian, ", ")))
	}

	if cert.IsCA {
		caLabel := ColorizeCA(true)
		if caLabel != "" {
			sb.WriteString(fmt.Sprintf("    %s\n", caLabel))
		} else {
			sb.WriteString("    CA:          true\n")
		}
	}

	if options.Details() {
		sb.WriteString(formatCertDetails(cert, options))
	}

	return sb.String()
}

func formatCertDetails(cert *x509.Certificate, options OutputOptions) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("    Version:     v%d\n", cert.Version))
	sb.WriteString(fmt.Sprintf("    Signature:   %s\n", cert.SignatureAlgorithm.String()))

	if cert.KeyUsage != 0 {
		sb.WriteString(fmt.Sprintf("    Key Usage:   %s\n", formatKeyUsage(cert.KeyUsage)))
	}

	if len(cert.ExtKeyUsage) > 0 {
		sb.WriteString(fmt.Sprintf("    Ext Key Usage: %s\n", formatExtKeyUsage(cert.ExtKeyUsage)))
	}

	if len(cert.SubjectKeyId) > 0 {
		sb.WriteString(fmt.Sprintf("    Subject Key ID: %x\n", cert.SubjectKeyId))
	}

	if len(cert.AuthorityKeyId) > 0 {
		sb.WriteString(fmt.Sprintf("    Authority Key ID: %x\n", cert.AuthorityKeyId))
	}

	if len(cert.CRLDistributionPoints) > 0 {
		sb.WriteString(fmt.Sprintf("    CRL Dist Points: %s\n", strings.Join(cert.CRLDistributionPoints, ", ")))
	}

	if len(cert.OCSPServer) > 0 || len(cert.IssuingCertificateURL) > 0 {
		var aia []string
		for _, u := range cert.OCSPServer {
			aia = append(aia, "OCSP:"+u)
		}
		for _, u := range cert.IssuingCertificateURL {
			aia = append(aia, "CA Issuers:"+u)
		}
		sb.WriteString(fmt.Sprintf("    Auth Info Access: %s\n", strings.Join(aia, ", ")))
	}

	for _, fp := range options.Fingerprints(cert) {
		sb.WriteString(fmt.Sprintf("    %-12s %s\n", fp.Label+":", fp.Value))
	}

	sb.WriteString(formatExtensionDetails(cert, options))

	// The PEM body is bulky enough to drown the rest of -d, so it belongs to
	// the extended level.
	if options.Extended() {
		sb.WriteString(fmt.Sprintf("    Subject DN:  %s\n", cert.Subject.String()))
		sb.WriteString(fmt.Sprintf("    Issuer DN:   %s\n", cert.Issuer.String()))

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		sb.WriteString("    PEM:\n")
		pemData := pem.EncodeToMemory(pemBlock)
		for _, line := range strings.Split(string(pemData), "\n") {
			if line != "" {
				sb.WriteString(fmt.Sprintf("      %s\n", line))
			}
		}
	}

	return sb.String()
}

func formatPrivateKey(item *certlib.CertItem, container *certlib.CertContainer, options OutputOptions) string {
	var sb strings.Builder

	label := "Private Key"
	if item.EntryPassword != nil && !bytes.Equal(item.EntryPassword, container.Password) {
		label = "Private Key [different password]"
	}
	if item.Alias != "" {
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", item.Alias, label))
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", label))
	}

	if item.Encrypted && item.PrivateKey == nil {
		sb.WriteString("    (encrypted, password required)\n")
		return sb.String()
	}

	if item.PrivateKey != nil {
		sb.WriteString(fmt.Sprintf("    Algorithm:   %s\n", FormatPrivateKeyAlgo(item.PrivateKey)))

		if options.InsecureDetails {
			pemBlock := marshalPrivateKeyToPEM(item.PrivateKey)
			if pemBlock != nil {
				sb.WriteString("    PEM:\n")
				pemData := pem.EncodeToMemory(pemBlock)
				for _, line := range strings.Split(string(pemData), "\n") {
					if line != "" {
						sb.WriteString(fmt.Sprintf("      %s\n", line))
					}
				}
			}
		}
	}

	return sb.String()
}

func marshalPrivateKeyToPEM(key crypto.PrivateKey) *pem.Block {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil
		}
		return &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}
	default:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil
		}
		return &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	}
}

func formatPublicKey(item *certlib.CertItem, options OutputOptions) string {
	var sb strings.Builder

	sb.WriteString("  Public Key\n")
	if item.PublicKey != nil {
		sb.WriteString(fmt.Sprintf("    Algorithm:   %s\n", FormatKeyAlgo(item.PublicKey)))
	}

	return sb.String()
}

func formatCSR(item *certlib.CertItem, options OutputOptions) string {
	var sb strings.Builder
	csr := item.CSR

	if csr == nil {
		sb.WriteString("  CSR: (failed to parse)\n")
		return sb.String()
	}

	sb.WriteString("  Certificate Request\n")
	sb.WriteString(fmt.Sprintf("    Subject:     %s\n", formatDN(csr.Subject)))
	sb.WriteString(fmt.Sprintf("    Algorithm:   %s\n", FormatKeyAlgo(csr.PublicKey)))
	sb.WriteString(fmt.Sprintf("    Signature:   %s\n", csr.SignatureAlgorithm.String()))

	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, fmt.Sprintf("DNS:%s", dns))
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, fmt.Sprintf("IP:%s", ip.String()))
	}
	if len(sans) > 0 {
		sb.WriteString(fmt.Sprintf("    Requested SANs: %s\n", strings.Join(sans, ", ")))
	}

	return sb.String()
}

func formatRelations(ref certlib.ItemRef, opts OutputOptions) string {
	var lines []string

	if chain, ok := opts.Chains[ref]; ok {
		lines = append(lines, "      "+certlib.FormatChainLabel(chain, opts.Store, func(s string) string { return BoldAttr.Sprint(s) }))
	}

	rels := opts.RelationIndex[ref]
	for _, rel := range rels {
		lines = append(lines, fmt.Sprintf("      %s", rel.Label))
	}

	if len(lines) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("    Relations:\n")
	for _, line := range lines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatInlineWarnings(ref certlib.ItemRef, options OutputOptions) string {
	if options.CheckResult == nil {
		return ""
	}
	var warnings []string
	for _, issue := range options.CheckResult.Issues {
		if issue.ItemRef == ref {
			sev := ColorizeSeverity(issue.Severity)
			warnings = append(warnings, fmt.Sprintf("      %s  %s", sev, issue.Message))
		}
	}
	if len(warnings) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("    Warnings:\n")
	for _, w := range warnings {
		sb.WriteString(w)
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatDN(name interface{}) string {
	switch n := name.(type) {
	case pkix.Name:
		return certlib.FormatDNName(n)
	default:
		dn := name.(interface{ String() string })
		return dn.String()
	}
}

func formatKeyUsage(ku x509.KeyUsage) string {
	usages := certlib.FormatKeyUsage(ku)
	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) string {
	return strings.Join(certlib.FormatExtKeyUsage(eku), ", ")
}

// formatExtensionDetails renders the extensions Go's x509 package does not
// surface, and at -dd lists everything else by OID. An extension certdiag
// cannot decode should still be visible: "there is something here I do not
// read" is useful, silence is not.
func formatExtensionDetails(cert *x509.Certificate, options OutputOptions) string {
	var sb strings.Builder
	ext := extensions.Parse(cert)

	if ext.IsPrecertificate {
		sb.WriteString("    Precertificate: yes (CT poison; not usable as a certificate)\n")
	}
	if ext.MustStaple {
		sb.WriteString("    Must-staple: yes (TLS feature status_request)\n")
	}
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		sb.WriteString(fmt.Sprintf("    Path Length: %d\n", cert.MaxPathLen))
	}
	if nc := FormatNameConstraints(cert); nc != "" {
		sb.WriteString(fmt.Sprintf("    Name Constraints: %s\n", nc))
	} else if hasExtension(cert, extensions.OIDNameConstraints) {
		// Go exposes DNS, IP, email and URI subtrees only. A CA constrained by
		// directoryName - which is how bridge PKIs do it - would otherwise show
		// nothing at all, which reads as "unconstrained".
		sb.WriteString("    Name Constraints: present, of a type certdiag does not decode (directoryName)\n")
	}
	if pol := FormatPolicies(cert); pol != "" {
		sb.WriteString(fmt.Sprintf("    Policies:    %s\n", pol))
	}
	if len(ext.SCTs) > 0 {
		sb.WriteString(fmt.Sprintf("    SCTs:        %s\n", formatSCTs(ext.SCTs)))
	}
	if len(ext.QCStatements) > 0 {
		var parts []string
		for _, q := range ext.QCStatements {
			if q.Name != "" {
				parts = append(parts, q.Name)
			} else {
				parts = append(parts, q.OID)
			}
		}
		sb.WriteString(fmt.Sprintf("    QC Statements: %s\n", strings.Join(parts, ", ")))
	}
	if ext.MSTemplateName != "" {
		sb.WriteString(fmt.Sprintf("    MS Template: %s\n", ext.MSTemplateName))
	}
	if ext.MSTemplate != nil {
		sb.WriteString(fmt.Sprintf("    MS Template: %s v%d.%d\n",
			ext.MSTemplate.OID, ext.MSTemplate.MajorVersion, ext.MSTemplate.MinorVersion))
	}
	if len(ext.NetscapeCertType) > 0 {
		sb.WriteString(fmt.Sprintf("    Netscape Type: %s\n", strings.Join(ext.NetscapeCertType, ", ")))
	}
	if ext.PolicyConstraints != nil {
		sb.WriteString(fmt.Sprintf("    Policy Constraints: %s\n", ext.PolicyConstraints.String()))
	}
	if ext.InhibitAnyPolicy != nil {
		sb.WriteString(fmt.Sprintf("    Inhibit anyPolicy: %d\n", *ext.InhibitAnyPolicy))
	}
	if ext.OCSPNoCheck {
		sb.WriteString("    OCSP No Check: yes\n")
	}

	if options.Extended() && len(ext.Other) > 0 {
		sb.WriteString("    Other extensions:\n")
		for _, r := range ext.Other {
			name := r.Name
			if name == "" {
				name = "(not decoded)"
			}
			crit := ""
			if r.Critical {
				crit = " critical"
			}
			sb.WriteString(fmt.Sprintf("      %s  %s%s, %d bytes\n", r.OID, name, crit, r.Length))
		}
	}

	return sb.String()
}

func formatSCTs(scts []extensions.SCT) string {
	var parts []string
	for _, s := range scts {
		name := s.LogName
		if name == "" {
			name = s.LogID[:16] + "..."
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", name, s.Timestamp.Format("2006-01-02")))
	}
	return fmt.Sprintf("%d: %s", len(scts), strings.Join(parts, ", "))
}

// FormatNameConstraints renders the permitted and excluded subtrees a CA
// imposes on everything below it.
func FormatNameConstraints(cert *x509.Certificate) string {
	var parts []string
	add := func(label string, values []string) {
		if len(values) > 0 {
			parts = append(parts, label+":"+strings.Join(values, ","))
		}
	}
	add("permitted DNS", cert.PermittedDNSDomains)
	add("excluded DNS", cert.ExcludedDNSDomains)
	add("permitted email", cert.PermittedEmailAddresses)
	add("excluded email", cert.ExcludedEmailAddresses)
	add("permitted URI", cert.PermittedURIDomains)
	add("excluded URI", cert.ExcludedURIDomains)
	for _, ipNet := range cert.PermittedIPRanges {
		parts = append(parts, "permitted IP:"+ipNet.String())
	}
	for _, ipNet := range cert.ExcludedIPRanges {
		parts = append(parts, "excluded IP:"+ipNet.String())
	}
	return strings.Join(parts, "; ")
}

// FormatPolicies renders the certificate policies, naming the ones that say
// how the subject was validated.
func FormatPolicies(cert *x509.Certificate) string {
	var parts []string
	for _, oid := range cert.PolicyIdentifiers {
		if name := extensions.PolicyName(oid); name != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", name, oid.String()))
			continue
		}
		parts = append(parts, oid.String())
	}
	return strings.Join(parts, ", ")
}

// hasExtension reports whether a certificate carries an extension, regardless of
// whether anything managed to decode it.
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}
