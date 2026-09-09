package output

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type StructuredOutput struct {
	Files []StructuredFile `json:"files" yaml:"files" jsonschema_description:"List of scanned certificate files"`
	// Skipped names what a directory scan could not read, so an absent file is
	// never mistaken for a file without certificates.
	Skipped []certlib.SkippedFile `json:"skipped,omitempty" yaml:"skipped,omitempty" jsonschema_description:"Files and directories the scan could not read, with the reason"`
}

func (StructuredOutput) JSONSchemaExtend(schema *jsonschema.Schema) {
	schema.Title = "certdiag output"
	schema.Description = "Structured output from certdiag certificate diagnostics tool"
}

type StructuredFile struct {
	FilePath string           `json:"file_path" yaml:"file_path" jsonschema_description:"Absolute or relative path to the certificate file"`
	Filename string           `json:"filename" yaml:"filename" jsonschema_description:"Base filename without directory"`
	FileSize int64            `json:"file_size" yaml:"file_size" jsonschema_description:"File size in bytes"`
	Modified string           `json:"modified,omitempty" yaml:"modified,omitempty" jsonschema_description:"File modification time (ISO 8601)"`
	Accessed string           `json:"accessed,omitempty" yaml:"accessed,omitempty" jsonschema_description:"File last access time (ISO 8601)"`
	Created  string           `json:"created,omitempty" yaml:"created,omitempty" jsonschema_description:"File creation time (ISO 8601), available on macOS and Windows"`
	Format   string           `json:"format" yaml:"format" jsonschema_description:"Detected file format (pem, der, pkcs12, pkcs7, jks)"`
	Password PasswordStatus   `json:"password" yaml:"password" jsonschema_description:"Password protection status"`
	Items    []StructuredItem `json:"items" yaml:"items" jsonschema_description:"Certificate items found in the file"`
	Errors   []string         `json:"errors,omitempty" yaml:"errors,omitempty" jsonschema_description:"Parse errors encountered for this file"`
}

type PasswordStatus struct {
	Protected bool     `json:"protected" yaml:"protected" jsonschema_description:"Whether the file is password-protected"`
	Unlocked  bool     `json:"unlocked" yaml:"unlocked" jsonschema_description:"Whether the file was successfully unlocked"`
	Sources   []string `json:"sources,omitempty" yaml:"sources,omitempty" jsonschema_description:"Password sources used to unlock (cli, config, env, interactive)"`
}

type StructuredItem struct {
	Type        string                 `json:"type" yaml:"type" jsonschema_description:"Item type (certificate, private_key, public_key, csr)"`
	Alias       string                 `json:"alias,omitempty" yaml:"alias,omitempty" jsonschema_description:"Alias or label for the item (e.g. keystore entry name)"`
	Certificate *StructuredCertificate `json:"certificate,omitempty" yaml:"certificate,omitempty" jsonschema_description:"Certificate details, present when type is certificate"`
	PrivateKey  *StructuredPrivateKey  `json:"private_key,omitempty" yaml:"private_key,omitempty" jsonschema_description:"Private key details, present when type is private_key"`
	PublicKey   *StructuredPublicKey   `json:"public_key,omitempty" yaml:"public_key,omitempty" jsonschema_description:"Public key details, present when type is public_key"`
	CSR         *StructuredCSR         `json:"csr,omitempty" yaml:"csr,omitempty" jsonschema_description:"Certificate signing request details, present when type is csr"`
	Relations   []StructuredRelation   `json:"relations,omitempty" yaml:"relations,omitempty" jsonschema_description:"Relations to other items (signing, key-cert pairs, key-csr pairs, csr-cert pairs, duplicates, chains)"`
}

type StructuredCertificate struct {
	Subject                string                   `json:"subject" yaml:"subject" jsonschema_description:"Common name or display name of the subject"`
	SubjectDN              string                   `json:"subject_dn" yaml:"subject_dn" jsonschema_description:"Full subject distinguished name"`
	Issuer                 string                   `json:"issuer" yaml:"issuer" jsonschema_description:"Issuer display name, or Self-signed"`
	IssuerDN               string                   `json:"issuer_dn" yaml:"issuer_dn" jsonschema_description:"Full issuer distinguished name"`
	SelfSigned             bool                     `json:"self_signed" yaml:"self_signed" jsonschema_description:"Whether the certificate is self-signed"`
	NotBefore              string                   `json:"not_before" yaml:"not_before" jsonschema_description:"Certificate validity start (ISO 8601)"`
	NotAfter               string                   `json:"not_after" yaml:"not_after" jsonschema_description:"Certificate validity end (ISO 8601)"`
	Serial                 string                   `json:"serial" yaml:"serial" jsonschema_description:"Certificate serial number in hex"`
	Algorithm              string                   `json:"algorithm" yaml:"algorithm" jsonschema_description:"Public key algorithm and size (e.g. RSA-2048, EC-P256)"`
	SANs                   []string                 `json:"sans,omitempty" yaml:"sans,omitempty" jsonschema_description:"Subject Alternative Names (DNS:, IP:, email:, URI:)"`
	IsCA                   bool                     `json:"is_ca" yaml:"is_ca" jsonschema_description:"Whether the certificate has the CA basic constraint"`
	SignatureAlgo          string                   `json:"signature_algorithm" yaml:"signature_algorithm" jsonschema_description:"Signature algorithm (e.g. SHA256-RSA)"`
	KeyUsage               []string                 `json:"key_usage,omitempty" yaml:"key_usage,omitempty" jsonschema_description:"Key usage flags (Digital Signature, Key Encipherment, etc.)"`
	ExtKeyUsage            []string                 `json:"ext_key_usage,omitempty" yaml:"ext_key_usage,omitempty" jsonschema_description:"Extended key usage (Server Auth, Client Auth, etc.)"`
	SubjectKeyID           string                   `json:"subject_key_id,omitempty" yaml:"subject_key_id,omitempty" jsonschema_description:"Subject Key Identifier in hex"`
	AuthKeyID              string                   `json:"authority_key_id,omitempty" yaml:"authority_key_id,omitempty" jsonschema_description:"Authority Key Identifier in hex"`
	MD5                    string                   `json:"md5" yaml:"md5" jsonschema_description:"MD5 fingerprint of the DER-encoded certificate (lowercase hex)"`
	SHA1                   string                   `json:"sha1" yaml:"sha1" jsonschema_description:"SHA-1 fingerprint of the DER-encoded certificate (lowercase hex)"`
	SHA256                 string                   `json:"sha256" yaml:"sha256" jsonschema_description:"SHA-256 fingerprint of the DER-encoded certificate (lowercase hex)"`
	SHA384                 string                   `json:"sha384" yaml:"sha384" jsonschema_description:"SHA-384 fingerprint of the DER-encoded certificate (lowercase hex)"`
	SHA512                 string                   `json:"sha512" yaml:"sha512" jsonschema_description:"SHA-512 fingerprint of the DER-encoded certificate (lowercase hex)"`
	Version                int                      `json:"version" yaml:"version" jsonschema_description:"X.509 certificate version (1, 2, or 3)"`
	IssuerAltNames         []string                 `json:"issuer_alt_names,omitempty" yaml:"issuer_alt_names,omitempty" jsonschema_description:"Issuer Alternative Names (DNS:, IP:, email:, URI:)"`
	CRLDistributionPoints  []string                 `json:"crl_distribution_points,omitempty" yaml:"crl_distribution_points,omitempty" jsonschema_description:"CRL Distribution Point URLs"`
	OCSPServers            []string                 `json:"ocsp_servers,omitempty" yaml:"ocsp_servers,omitempty" jsonschema_description:"OCSP responder URLs from Authority Information Access"`
	IssuingCertificateURLs []string                 `json:"issuing_certificate_urls,omitempty" yaml:"issuing_certificate_urls,omitempty" jsonschema_description:"CA Issuer URLs from Authority Information Access"`
	Trust                  string                   `json:"trust,omitempty" yaml:"trust,omitempty" jsonschema_description:"Trust verdict for this machine: anchor, trusted, expired, untrusted or denied. Present only when trust evaluation was requested."`
	TrustAnchor            string                   `json:"trust_anchor,omitempty" yaml:"trust_anchor,omitempty" jsonschema_description:"Subject of the trust anchor that terminated the chain"`
	TrustViaAIA            bool                     `json:"trust_via_aia,omitempty" yaml:"trust_via_aia,omitempty" jsonschema_description:"True when the chain completes only through a certificate fetched over AIA, which a client that does not chase AIA will not accept"`
	TrustHint              string                   `json:"trust_hint,omitempty" yaml:"trust_hint,omitempty" jsonschema_description:"Why an untrusted verdict came out that way, when the reason is actionable (for example the missing issuer's published URL)"`
	MaxPathLen             int                      `json:"max_path_len,omitempty" yaml:"max_path_len,omitempty" jsonschema_description:"Basic Constraints path length, when set"`
	NameConstraints        string                   `json:"name_constraints,omitempty" yaml:"name_constraints,omitempty" jsonschema_description:"Permitted and excluded name subtrees this CA imposes"`
	Policies               []string                 `json:"policies,omitempty" yaml:"policies,omitempty" jsonschema_description:"Certificate policy OIDs, named where known (DV, OV, EV, ETSI)"`
	SCTs                   []extensions.SCT         `json:"scts,omitempty" yaml:"scts,omitempty" jsonschema_description:"Embedded Signed Certificate Timestamps"`
	Precertificate         bool                     `json:"precertificate,omitempty" yaml:"precertificate,omitempty" jsonschema_description:"True when the CT poison extension is present; the certificate is not usable"`
	MustStaple             bool                     `json:"must_staple,omitempty" yaml:"must_staple,omitempty" jsonschema_description:"True when the TLS Feature extension requires a stapled OCSP response"`
	QCStatements           []extensions.QCStatement `json:"qc_statements,omitempty" yaml:"qc_statements,omitempty" jsonschema_description:"eIDAS qualified certificate statements"`
	MSTemplate             string                   `json:"ms_template,omitempty" yaml:"ms_template,omitempty" jsonschema_description:"Microsoft certificate template the CA issued from"`
	Extensions             []extensions.Residue     `json:"extensions,omitempty" yaml:"extensions,omitempty" jsonschema_description:"Extensions not rendered by a field of their own, by OID"`
	Stores                 []string                 `json:"stores,omitempty" yaml:"stores,omitempty" jsonschema_description:"Short tags of the trust stores holding this exact certificate (OS, J21, SSL, FF, MOZ, CHR)"`
}

type StructuredPrivateKey struct {
	Algorithm         string `json:"algorithm" yaml:"algorithm" jsonschema_description:"Key algorithm and size (e.g. RSA-2048)"`
	Encrypted         bool   `json:"encrypted" yaml:"encrypted" jsonschema_description:"Whether the private key is encrypted"`
	DifferentPassword bool   `json:"different_password,omitempty" yaml:"different_password,omitempty" jsonschema_description:"Whether the entry uses a different password than the store (JKS)"`
}

type StructuredPublicKey struct {
	Algorithm string `json:"algorithm" yaml:"algorithm" jsonschema_description:"Key algorithm and size"`
}

type StructuredCSR struct {
	Subject       string   `json:"subject" yaml:"subject" jsonschema_description:"Common name of the CSR subject"`
	SubjectDN     string   `json:"subject_dn" yaml:"subject_dn" jsonschema_description:"Full subject distinguished name"`
	Algorithm     string   `json:"algorithm" yaml:"algorithm" jsonschema_description:"Public key algorithm and size"`
	SignatureAlgo string   `json:"signature_algorithm" yaml:"signature_algorithm" jsonschema_description:"Signature algorithm"`
	SANs          []string `json:"sans,omitempty" yaml:"sans,omitempty" jsonschema_description:"Subject Alternative Names requested in the CSR"`
}

type StructuredRelation struct {
	Type     string `json:"type" yaml:"type" jsonschema_description:"Relation type (signed_by, issuer_of, key_cert_pair, key_csr_pair, csr_cert_pair, same_cert, chain)"`
	Peer     string `json:"peer" yaml:"peer" jsonschema_description:"Peer reference (filename:alias or filename:#index)"`
	PeerPath string `json:"peer_path" yaml:"peer_path" jsonschema_description:"Full file path of the peer item"`
	Label    string `json:"label" yaml:"label" jsonschema_description:"Human-readable description of the relation"`
}

func BuildStructuredOutput(containers []*certlib.CertContainer, opts OutputOptions) *StructuredOutput {
	// An empty scan is an empty list, in JSON as in YAML: consumers index
	// into files and must never meet null.
	out := &StructuredOutput{Files: []StructuredFile{}, Skipped: opts.Skipped}

	containerIndices := resolveContainerIndices(containers, opts)

	for i, c := range containers {
		if c.RelationsOnly {
			continue
		}
		sf := StructuredFile{
			FilePath: c.FilePath,
			Filename: filepath.Base(c.FilePath),
			FileSize: c.FileSize,
			Format:   string(c.Format),
			Password: buildPasswordStatus(c),
			Errors:   c.ParseErrors,
		}
		if !c.FileModTime.IsZero() {
			sf.Modified = c.FileModTime.Format(time.RFC3339)
		}
		if !c.FileAccessTime.IsZero() {
			sf.Accessed = c.FileAccessTime.Format(time.RFC3339)
		}
		if !c.FileCreateTime.IsZero() {
			sf.Created = c.FileCreateTime.Format(time.RFC3339)
		}

		storeIdx := containerIndices[i]

		for ii, item := range c.Items {
			si := buildStructuredItem(&item, c.Password)
			if si.Certificate != nil {
				applyTrustFields(si.Certificate, item.Certificate, opts)
			}
			if opts.RelationIndex != nil {
				ref := certlib.ItemRef{
					ContainerIdx: storeIdx,
					ItemIdx:      ii,
					FilePath:     c.FilePath,
					Alias:        item.Alias,
				}
				si.Relations = buildStructuredRelations(ref, opts)
			}
			sf.Items = append(sf.Items, si)
		}

		out.Files = append(out.Files, sf)
	}

	return out
}

func resolveContainerIndices(containers []*certlib.CertContainer, opts OutputOptions) map[int]int {
	result := make(map[int]int)
	if opts.Store == nil {
		for i := range containers {
			result[i] = i
		}
		return result
	}
	for i, c := range containers {
		idx := -1
		for si := range opts.Store.Containers {
			if &opts.Store.Containers[si] == c {
				idx = si
				break
			}
		}
		result[i] = idx
	}
	return result
}

func buildPasswordStatus(c *certlib.CertContainer) PasswordStatus {
	if len(c.UnlockSources) > 0 {
		sources := make([]string, len(c.UnlockSources))
		for i, s := range c.UnlockSources {
			sources[i] = string(s)
		}
		return PasswordStatus{Protected: true, Unlocked: true, Sources: sources}
	}
	for _, e := range c.ParseErrors {
		if strings.Contains(e, "password required") || strings.Contains(e, "failed to decrypt") {
			return PasswordStatus{Protected: true, Unlocked: false}
		}
	}
	return PasswordStatus{Protected: false, Unlocked: false}
}

// applyTrustFields fills the optional trust fields. Values stay canonical
// lowercase: this struct is the published JSON/YAML contract, so it must not
// depend on display choices.
func applyTrustFields(sc *StructuredCertificate, cert *x509.Certificate, opts OutputOptions) {
	if cert == nil {
		return
	}
	if opts.TrustIndex != nil {
		verdict := opts.TrustIndex.Verdict(cert)
		if verdict != truststore.VerdictUnknown {
			sc.Trust = string(verdict)
		}
		if anchor := opts.TrustIndex.AnchorFor(cert); anchor != nil {
			sc.TrustAnchor = FormatSubject(anchor)
		}
		detail := opts.TrustIndex.Detail(cert)
		sc.TrustHint = detail.Hint
		sc.TrustViaAIA = detail.ViaAIA
	}
	if opts.StoreTags != nil {
		if tags := opts.StoreTags(cert); len(tags) > 0 {
			sc.Stores = tags
		}
	}
}

func buildStructuredItem(item *certlib.CertItem, containerPassword []byte) StructuredItem {
	si := StructuredItem{
		Type:  string(item.Type),
		Alias: item.Alias,
	}

	switch item.Type {
	case certlib.ContentCertificate:
		if item.Certificate != nil {
			si.Certificate = BuildStructuredCert(item)
		}
	case certlib.ContentPrivateKey:
		si.PrivateKey = buildStructuredPrivateKey(item, containerPassword)
	case certlib.ContentPublicKey:
		if item.PublicKey != nil {
			si.PublicKey = &StructuredPublicKey{
				Algorithm: FormatKeyAlgo(item.PublicKey),
			}
		}
	case certlib.ContentCSR:
		if item.CSR != nil {
			si.CSR = buildStructuredCSR(item)
		}
	}

	return si
}

// applyExtensionFields fills the extension-derived fields. They are all
// omitempty, so a certificate without them is unchanged in the output.
func applyExtensionFields(sc *StructuredCertificate, cert *x509.Certificate) {
	if cert == nil {
		return
	}
	ext := extensions.Parse(cert)

	sc.SCTs = ext.SCTs
	sc.Precertificate = ext.IsPrecertificate
	sc.MustStaple = ext.MustStaple
	sc.QCStatements = ext.QCStatements
	sc.Extensions = ext.Other
	if ext.MSTemplate != nil {
		sc.MSTemplate = ext.MSTemplate.OID
	}
	if ext.MSTemplateName != "" {
		sc.MSTemplate = ext.MSTemplateName
	}
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		sc.MaxPathLen = cert.MaxPathLen
	}
	sc.NameConstraints = FormatNameConstraints(cert)
	for _, oid := range cert.PolicyIdentifiers {
		if name := extensions.PolicyName(oid); name != "" {
			sc.Policies = append(sc.Policies, oid.String()+" ("+name+")")
			continue
		}
		sc.Policies = append(sc.Policies, oid.String())
	}
}

func BuildStructuredCert(item *certlib.CertItem) *StructuredCertificate {
	cert := item.Certificate
	selfSigned := certlib.IsSelfSigned(cert)

	issuer := certlib.FormatDNName(cert.Issuer)
	if selfSigned {
		issuer = "Self-signed"
	} else if cert.Issuer.CommonName != "" {
		issuer = cert.Issuer.CommonName
	}

	sc := &StructuredCertificate{
		Subject:       FormatSubject(cert),
		SubjectDN:     certlib.FormatDNName(cert.Subject),
		Issuer:        issuer,
		IssuerDN:      certlib.FormatDNName(cert.Issuer),
		SelfSigned:    selfSigned,
		NotBefore:     cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:      cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		Serial:        certlib.FormatSerial(cert.SerialNumber),
		Algorithm:     FormatKeyAlgo(cert.PublicKey),
		IsCA:          cert.IsCA,
		SignatureAlgo: cert.SignatureAlgorithm.String(),
	}

	sans := buildSANsList(cert)
	if len(sans) > 0 {
		sc.SANs = sans
	}

	if cert.KeyUsage != 0 {
		sc.KeyUsage = buildKeyUsageList(cert.KeyUsage)
	}

	if len(cert.ExtKeyUsage) > 0 {
		sc.ExtKeyUsage = buildExtKeyUsageList(cert.ExtKeyUsage)
	}

	if len(cert.SubjectKeyId) > 0 {
		sc.SubjectKeyID = fmt.Sprintf("%x", cert.SubjectKeyId)
	}

	if len(cert.AuthorityKeyId) > 0 {
		sc.AuthKeyID = fmt.Sprintf("%x", cert.AuthorityKeyId)
	}

	// Always canonical lowercase hex: this struct is the JSON/YAML contract and
	// the source for `certdiag schema`. Display layers re-format it.
	sc.MD5 = certlib.CertFingerprint(cert, certlib.FingerprintMD5, certlib.FingerprintHex)
	sc.SHA1 = certlib.CertFingerprint(cert, certlib.FingerprintSHA1, certlib.FingerprintHex)
	sc.SHA256 = certlib.CertFingerprint(cert, certlib.FingerprintSHA256, certlib.FingerprintHex)
	sc.SHA384 = certlib.CertFingerprint(cert, certlib.FingerprintSHA384, certlib.FingerprintHex)
	sc.SHA512 = certlib.CertFingerprint(cert, certlib.FingerprintSHA512, certlib.FingerprintHex)

	sc.Version = cert.Version

	if ian := certlib.ParseIssuerAltNames(cert); len(ian) > 0 {
		sc.IssuerAltNames = ian
	}

	if len(cert.CRLDistributionPoints) > 0 {
		sc.CRLDistributionPoints = cert.CRLDistributionPoints
	}

	if len(cert.OCSPServer) > 0 {
		sc.OCSPServers = cert.OCSPServer
	}

	if len(cert.IssuingCertificateURL) > 0 {
		sc.IssuingCertificateURLs = cert.IssuingCertificateURL
	}
	applyExtensionFields(sc, cert)

	return sc
}

func buildStructuredPrivateKey(item *certlib.CertItem, containerPassword []byte) *StructuredPrivateKey {
	pk := &StructuredPrivateKey{
		Encrypted: item.Encrypted,
	}
	if item.PrivateKey != nil {
		pk.Algorithm = FormatPrivateKeyAlgo(item.PrivateKey)
	}
	if item.EntryPassword != nil && !bytes.Equal(item.EntryPassword, containerPassword) {
		pk.DifferentPassword = true
	}
	return pk
}

func buildStructuredCSR(item *certlib.CertItem) *StructuredCSR {
	csr := item.CSR
	sc := &StructuredCSR{
		Subject:       csr.Subject.CommonName,
		SubjectDN:     certlib.FormatDNName(csr.Subject),
		Algorithm:     FormatKeyAlgo(csr.PublicKey),
		SignatureAlgo: csr.SignatureAlgorithm.String(),
	}
	if sc.Subject == "" {
		sc.Subject = sc.SubjectDN
	}

	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, fmt.Sprintf("DNS:%s", dns))
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, fmt.Sprintf("IP:%s", ip.String()))
	}
	if len(sans) > 0 {
		sc.SANs = sans
	}

	return sc
}

func buildSANsList(cert *x509.Certificate) []string {
	return certlib.FormatSANs(cert)
}

func buildKeyUsageList(ku x509.KeyUsage) []string {
	return certlib.FormatKeyUsage(ku)
}

func buildStructuredRelations(ref certlib.ItemRef, opts OutputOptions) []StructuredRelation {
	var result []StructuredRelation

	if chain, ok := opts.Chains[ref]; ok {
		result = append(result, StructuredRelation{
			Type:  "chain",
			Label: certlib.FormatChainLabel(chain, opts.Store, nil),
		})
	}

	rels := opts.RelationIndex[ref]
	for _, rel := range rels {
		sr := StructuredRelation{
			Type:     structuredRelationType(rel),
			PeerPath: rel.Peer.FilePath,
			Label:    rel.Label,
		}
		peerFilename := filepath.Base(rel.Peer.FilePath)
		if rel.Peer.Alias != "" {
			sr.Peer = fmt.Sprintf("%s:%s", peerFilename, rel.Peer.Alias)
		} else {
			sr.Peer = fmt.Sprintf("%s:#%d", peerFilename, rel.Peer.ItemIdx+1)
		}
		result = append(result, sr)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func structuredRelationType(rel certlib.ResolvedRelation) string {
	return certlib.RelationDisplayKey(rel.Type, rel.Direction)
}

func buildExtKeyUsageList(eku []x509.ExtKeyUsage) []string {
	return certlib.FormatExtKeyUsage(eku)
}

type WriteSummary struct {
	Operation string
	Items     []WriteSummaryItem
}

type WriteSummaryItem struct {
	Path      string
	Format    string
	Type      string
	Subject   string
	Issuer    string
	NotBefore string
	NotAfter  string
	Algorithm string
	Serial    string
}

func FormatWriteSummary(summary *WriteSummary) string {
	if summary == nil || len(summary.Items) == 0 {
		return ""
	}

	var b strings.Builder
	for _, item := range summary.Items {
		op := summary.Operation
		if len(op) > 0 {
			op = strings.ToUpper(op[:1]) + op[1:]
		}
		fmt.Fprintf(&b, "%s: %s (%s, %s)", op, item.Path, item.Format, item.Type)
		if item.Subject != "" {
			fmt.Fprintf(&b, "\n  Subject:   %s", item.Subject)
		}
		if item.Issuer != "" {
			fmt.Fprintf(&b, "\n  Issuer:    %s", item.Issuer)
		}
		if item.Algorithm != "" {
			fmt.Fprintf(&b, "\n  Algorithm: %s", item.Algorithm)
		}
		if item.Serial != "" {
			fmt.Fprintf(&b, "\n  Serial:    %s", item.Serial)
		}
		if item.NotBefore != "" && item.NotAfter != "" {
			fmt.Fprintf(&b, "\n  Validity:  %s -- %s", item.NotBefore, item.NotAfter)
		}
		b.WriteString("\n")
	}
	return b.String()
}
