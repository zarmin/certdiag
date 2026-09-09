package certlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func TemplateFromCert(cert *x509.Certificate) CertGenOptions {
	subject := cert.Subject
	// Preserve non-standard DN attributes (emailAddress, domainComponent) that
	// pkix.Name re-marshaling drops; standard fields stay editable via MergeSubject.
	subject.ExtraNames = nonStandardSubjectNames(cert.Subject.Names)

	opts := CertGenOptions{
		Subject: subject,
		SANs: SANList{
			DNSNames:       cert.DNSNames,
			IPAddresses:    cert.IPAddresses,
			EmailAddresses: cert.EmailAddresses,
			URIs:           cert.URIs,
		},
		IsCA:        cert.IsCA,
		KeyUsage:    cert.KeyUsage,
		ExtKeyUsage: cert.ExtKeyUsage,

		CRLDistributionPoints: cert.CRLDistributionPoints,
		OCSPServer:            cert.OCSPServer,
		IssuingCertificateURL: cert.IssuingCertificateURL,
		PolicyIdentifiers:     cert.PolicyIdentifiers,
		Policies:              cert.Policies,

		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		PermittedIPRanges:           cert.PermittedIPRanges,
		ExcludedIPRanges:            cert.ExcludedIPRanges,
		PermittedEmailAddresses:     cert.PermittedEmailAddresses,
		ExcludedEmailAddresses:      cert.ExcludedEmailAddresses,
		PermittedURIDomains:         cert.PermittedURIDomains,
		ExcludedURIDomains:          cert.ExcludedURIDomains,
	}

	// Compute days from cert validity; round up so renew never shortens.
	dur := cert.NotAfter.Sub(cert.NotBefore)
	opts.Days = int(math.Ceil(dur.Hours() / 24))
	if opts.Days < 1 {
		opts.Days = 1
	}

	// PathLength extraction
	if cert.IsCA {
		if cert.MaxPathLen > 0 {
			opts.PathLength = cert.MaxPathLen
		} else if cert.MaxPathLen == 0 && cert.MaxPathLenZero {
			opts.PathLength = 0
		} else {
			opts.PathLength = -1
		}
	}

	return opts
}

var standardSubjectOIDs = []asn1.ObjectIdentifier{
	{2, 5, 4, 3},  // commonName
	{2, 5, 4, 5},  // serialNumber
	{2, 5, 4, 6},  // country
	{2, 5, 4, 7},  // locality
	{2, 5, 4, 8},  // province
	{2, 5, 4, 9},  // streetAddress
	{2, 5, 4, 10}, // organization
	{2, 5, 4, 11}, // organizationalUnit
	{2, 5, 4, 17}, // postalCode
}

func nonStandardSubjectNames(names []pkix.AttributeTypeAndValue) []pkix.AttributeTypeAndValue {
	var extra []pkix.AttributeTypeAndValue
	for _, atv := range names {
		standard := false
		for _, oid := range standardSubjectOIDs {
			if atv.Type.Equal(oid) {
				standard = true
				break
			}
		}
		if !standard {
			extra = append(extra, atv)
		}
	}
	return extra
}

type CertProfile struct {
	Kind        string           `yaml:"kind"`
	Version     string           `yaml:"version"`
	Name        string           `yaml:"name"`
	Description string           `yaml:"description,omitempty"`
	Subject     SubjectProfile   `yaml:"subject"`
	SANs        SANProfile       `yaml:"sans"`
	Key         KeyProfile       `yaml:"key"`
	Validity    *ValidityProfile `yaml:"validity,omitempty"`
	CA          *bool            `yaml:"ca,omitempty"`
	PathLength  *int             `yaml:"path_length,omitempty"`
	KeyUsage    []string         `yaml:"key_usage"`
	ExtKeyUsage []string         `yaml:"ext_key_usage"`
	// NameConstraints restricts what a CA created from this profile may issue.
	NameConstraints *NameConstraintProfile `yaml:"name_constraints,omitempty"`
}

// NameConstraintProfile is the YAML form of a CA's name constraints.
type NameConstraintProfile struct {
	Critical  *bool                  `yaml:"critical,omitempty"`
	Permitted NameConstraintSubtrees `yaml:"permitted,omitempty"`
	Excluded  NameConstraintSubtrees `yaml:"excluded,omitempty"`
}

// NameConstraintSubtrees is one side of the constraint, by name type.
type NameConstraintSubtrees struct {
	DNS    []string `yaml:"dns,omitempty"`
	IPs    []string `yaml:"ips,omitempty"`
	Emails []string `yaml:"emails,omitempty"`
	URIs   []string `yaml:"uris,omitempty"`
}

// Resolve turns the profile form into constraints, reporting a bad CIDR rather
// than silently dropping it.
func (p *NameConstraintProfile) Resolve() (NameConstraints, error) {
	var nc NameConstraints
	if p == nil {
		return nc, nil
	}
	nc.Critical = true
	if p.Critical != nil {
		nc.Critical = *p.Critical
	}

	nc.PermittedDNS = p.Permitted.DNS
	nc.PermittedEmail = p.Permitted.Emails
	nc.PermittedURI = p.Permitted.URIs
	nc.ExcludedDNS = p.Excluded.DNS
	nc.ExcludedEmail = p.Excluded.Emails
	nc.ExcludedURI = p.Excluded.URIs

	for _, cidr := range p.Permitted.IPs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nc, fmt.Errorf("permitted IP %q must be CIDR: %w", cidr, err)
		}
		nc.PermittedIP = append(nc.PermittedIP, n)
	}
	for _, cidr := range p.Excluded.IPs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nc, fmt.Errorf("excluded IP %q must be CIDR: %w", cidr, err)
		}
		nc.ExcludedIP = append(nc.ExcludedIP, n)
	}
	return nc, nil
}

type SubjectProfile struct {
	CommonName         string `yaml:"common_name"`
	Organization       string `yaml:"organization"`
	OrganizationalUnit string `yaml:"organizational_unit"`
	Country            string `yaml:"country"`
	State              string `yaml:"state"`
	Locality           string `yaml:"locality"`
}

type SANProfile struct {
	DNS    []string `yaml:"dns"`
	IPs    []string `yaml:"ips"`
	Emails []string `yaml:"emails"`
}

type KeyProfile struct {
	Algorithm string `yaml:"algorithm"`
	KeySize   int    `yaml:"key_size,omitempty"`
	Curve     string `yaml:"curve,omitempty"`
}

type ValidityProfile struct {
	Days int `yaml:"days"`
}

func LoadCertProfile(path string) (*CertProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p CertProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid profile YAML: %w", err)
	}

	if p.Kind != "certdiag-cert-profile" {
		return nil, fmt.Errorf("invalid profile: kind must be 'certdiag-cert-profile', got %q", p.Kind)
	}
	if p.Version != "1" {
		return nil, fmt.Errorf("invalid profile: unsupported version %q", p.Version)
	}

	return &p, nil
}

func (p *CertProfile) ToCertGenOptions() (CertGenOptions, KeyGenOptions, error) {
	var opts CertGenOptions
	var keyOpts KeyGenOptions

	// Subject
	opts.Subject = p.buildSubject()

	// SANs
	sans, err := p.buildSANs()
	if err != nil {
		return opts, keyOpts, err
	}
	opts.SANs = sans

	// Validity
	if p.Validity != nil && p.Validity.Days > 0 {
		opts.Days = p.Validity.Days
	}

	// CA
	if p.CA != nil {
		opts.IsCA = *p.CA
	}

	// PathLength
	if p.PathLength != nil {
		opts.PathLength = *p.PathLength
	}

	// Key usage
	if len(p.KeyUsage) > 0 {
		ku, err := ParseKeyUsageList(p.KeyUsage)
		if err != nil {
			return opts, keyOpts, fmt.Errorf("profile key_usage: %w", err)
		}
		opts.KeyUsage = ku
	}

	// Extended key usage
	if len(p.ExtKeyUsage) > 0 {
		eku, err := ParseExtKeyUsageList(p.ExtKeyUsage)
		if err != nil {
			return opts, keyOpts, fmt.Errorf("profile ext_key_usage: %w", err)
		}
		opts.ExtKeyUsage = eku
	}

	// Key options
	if p.Key.Algorithm != "" {
		keyOpts.Algorithm = strings.ToLower(p.Key.Algorithm)
	}
	if p.Key.KeySize > 0 {
		keyOpts.KeySize = p.Key.KeySize
	}
	if p.Key.Curve != "" {
		keyOpts.Curve = strings.ToLower(p.Key.Curve)
	}

	if p.NameConstraints != nil {
		nc, err := p.NameConstraints.Resolve()
		if err != nil {
			return opts, keyOpts, fmt.Errorf("profile name_constraints: %w", err)
		}
		nc.ApplyTo(&opts)
	}

	return opts, keyOpts, nil
}

func (p *CertProfile) buildSubject() pkix.Name {
	var name pkix.Name
	if p.Subject.CommonName != "" {
		name.CommonName = p.Subject.CommonName
	}
	if p.Subject.Organization != "" {
		name.Organization = []string{p.Subject.Organization}
	}
	if p.Subject.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{p.Subject.OrganizationalUnit}
	}
	if p.Subject.Country != "" {
		name.Country = []string{p.Subject.Country}
	}
	if p.Subject.State != "" {
		name.Province = []string{p.Subject.State}
	}
	if p.Subject.Locality != "" {
		name.Locality = []string{p.Subject.Locality}
	}
	return name
}

func (p *CertProfile) buildSANs() (SANList, error) {
	var sans SANList
	sans.DNSNames = p.SANs.DNS
	sans.EmailAddresses = p.SANs.Emails
	for _, ipStr := range p.SANs.IPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return sans, fmt.Errorf("profile sans.ips: invalid IP address %q", ipStr)
		}
		sans.IPAddresses = append(sans.IPAddresses, ip)
	}
	return sans, nil
}

// MergeSubject merges template subject fields into the target. Template fields
// fill in empty fields in target; they do NOT overwrite non-empty target values.
func MergeSubject(target, tmpl pkix.Name) pkix.Name {
	if target.CommonName == "" {
		target.CommonName = tmpl.CommonName
	}
	if len(target.Organization) == 0 && len(tmpl.Organization) > 0 {
		target.Organization = tmpl.Organization
	}
	if len(target.OrganizationalUnit) == 0 && len(tmpl.OrganizationalUnit) > 0 {
		target.OrganizationalUnit = tmpl.OrganizationalUnit
	}
	if len(target.Country) == 0 && len(tmpl.Country) > 0 {
		target.Country = tmpl.Country
	}
	if len(target.Province) == 0 && len(tmpl.Province) > 0 {
		target.Province = tmpl.Province
	}
	if len(target.Locality) == 0 && len(tmpl.Locality) > 0 {
		target.Locality = tmpl.Locality
	}
	if target.SerialNumber == "" {
		target.SerialNumber = tmpl.SerialNumber
	}
	if len(target.StreetAddress) == 0 && len(tmpl.StreetAddress) > 0 {
		target.StreetAddress = tmpl.StreetAddress
	}
	if len(target.PostalCode) == 0 && len(tmpl.PostalCode) > 0 {
		target.PostalCode = tmpl.PostalCode
	}
	return target
}

// ApplyParsedDN overwrites non-empty fields from parsed into target.
// Unlike MergeSubject (which only fills empty slots), this always overrides.
func ApplyParsedDN(target *pkix.Name, parsed pkix.Name) {
	if parsed.CommonName != "" {
		target.CommonName = parsed.CommonName
	}
	if len(parsed.Organization) > 0 {
		target.Organization = parsed.Organization
	}
	if len(parsed.OrganizationalUnit) > 0 {
		target.OrganizationalUnit = parsed.OrganizationalUnit
	}
	if len(parsed.Country) > 0 {
		target.Country = parsed.Country
	}
	if len(parsed.Province) > 0 {
		target.Province = parsed.Province
	}
	if len(parsed.Locality) > 0 {
		target.Locality = parsed.Locality
	}
	if parsed.SerialNumber != "" {
		target.SerialNumber = parsed.SerialNumber
	}
	if len(parsed.StreetAddress) > 0 {
		target.StreetAddress = parsed.StreetAddress
	}
	if len(parsed.PostalCode) > 0 {
		target.PostalCode = parsed.PostalCode
	}
	if len(parsed.ExtraNames) > 0 {
		target.ExtraNames = parsed.ExtraNames
	}
}

func ProfileFromCert(cert *x509.Certificate) CertProfile {
	if cert.IsCA {
		return ProfileFromCertAs(cert, "ca")
	}
	return ProfileFromCertAs(cert, "cert")
}

func ProfileFromCSR(csr *x509.CertificateRequest) CertProfile {
	return ProfileFromCSRAs(csr, "cert")
}

func ProfileFromCertAs(cert *x509.Certificate, targetType string) CertProfile {
	p := CertProfile{
		Kind:    "certdiag-cert-profile",
		Version: "1",
		Name:    cert.Subject.CommonName,
		Subject: subjectProfileFromName(cert.Subject),
		SANs:    sanProfileFromItems(cert.DNSNames, cert.IPAddresses, cert.EmailAddresses),
		Key:     keyProfileFromPublicKey(cert.PublicKey),
	}

	dur := cert.NotAfter.Sub(cert.NotBefore)
	days := int(dur / (24 * time.Hour))
	if days < 1 {
		days = 1
	}

	sourceIsCA := cert.IsCA
	sameType := (sourceIsCA && targetType == "ca") || (!sourceIsCA && targetType == "cert")

	switch targetType {
	case "cert":
		p.Validity = &ValidityProfile{Days: days}
		ca := false
		p.CA = &ca
		if sameType {
			p.KeyUsage = keyUsageToNames(cert.KeyUsage)
			p.ExtKeyUsage = extKeyUsageToNames(cert.ExtKeyUsage)
		} else {
			p.KeyUsage = []string{"digitalSignature", "keyEncipherment"}
			p.ExtKeyUsage = []string{"serverAuth", "clientAuth"}
		}
	case "ca":
		p.Validity = &ValidityProfile{Days: days}
		ca := true
		p.CA = &ca
		if sourceIsCA {
			pl := pathLengthFromCert(cert)
			p.PathLength = &pl
		} else {
			pl := -1
			p.PathLength = &pl
		}
		if sameType {
			p.KeyUsage = keyUsageToNames(cert.KeyUsage)
			p.ExtKeyUsage = extKeyUsageToNames(cert.ExtKeyUsage)
		} else {
			p.KeyUsage = []string{"certSign", "crlSign"}
			p.ExtKeyUsage = []string{}
		}
	case "csr":
		// CSR target: no validity, no CA, no path_length
		p.KeyUsage = []string{"digitalSignature", "keyEncipherment"}
		p.ExtKeyUsage = []string{"serverAuth", "clientAuth"}
	}

	return p
}

func ProfileFromCSRAs(csr *x509.CertificateRequest, targetType string) CertProfile {
	p := CertProfile{
		Kind:    "certdiag-cert-profile",
		Version: "1",
		Name:    csr.Subject.CommonName,
		Subject: subjectProfileFromName(csr.Subject),
		SANs:    sanProfileFromItems(csr.DNSNames, csr.IPAddresses, csr.EmailAddresses),
		Key:     keyProfileFromPublicKey(csr.PublicKey),
	}

	switch targetType {
	case "cert":
		p.Validity = &ValidityProfile{Days: 365}
		ca := false
		p.CA = &ca
		p.KeyUsage = []string{"digitalSignature", "keyEncipherment"}
		p.ExtKeyUsage = []string{"serverAuth", "clientAuth"}
	case "ca":
		p.Validity = &ValidityProfile{Days: 3650}
		ca := true
		p.CA = &ca
		pl := -1
		p.PathLength = &pl
		p.KeyUsage = []string{"certSign", "crlSign"}
		p.ExtKeyUsage = []string{}
	case "csr":
		// CSR target: no validity, no CA, no path_length
		p.KeyUsage = []string{"digitalSignature", "keyEncipherment"}
		p.ExtKeyUsage = []string{"serverAuth", "clientAuth"}
	}

	return p
}

func pathLengthFromCert(cert *x509.Certificate) int {
	if cert.MaxPathLen > 0 {
		return cert.MaxPathLen
	}
	if cert.MaxPathLen == 0 && cert.MaxPathLenZero {
		return 0
	}
	return -1
}

func keyProfileFromPublicKey(pub crypto.PublicKey) KeyProfile {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return KeyProfile{Algorithm: "rsa", KeySize: k.N.BitLen()}
	case *ecdsa.PublicKey:
		curve := strings.ToLower(strings.ReplaceAll(k.Curve.Params().Name, "-", ""))
		return KeyProfile{Algorithm: "ecdsa", Curve: curve}
	case ed25519.PublicKey:
		return KeyProfile{Algorithm: "ed25519"}
	default:
		return KeyProfile{}
	}
}

func subjectProfileFromName(name pkix.Name) SubjectProfile {
	sp := SubjectProfile{
		CommonName: name.CommonName,
	}
	if len(name.Organization) > 0 {
		sp.Organization = name.Organization[0]
	}
	if len(name.OrganizationalUnit) > 0 {
		sp.OrganizationalUnit = name.OrganizationalUnit[0]
	}
	if len(name.Country) > 0 {
		sp.Country = name.Country[0]
	}
	if len(name.Province) > 0 {
		sp.State = name.Province[0]
	}
	if len(name.Locality) > 0 {
		sp.Locality = name.Locality[0]
	}
	return sp
}

func sanProfileFromItems(dns []string, ips []net.IP, emails []string) SANProfile {
	sp := SANProfile{
		DNS:    dns,
		Emails: emails,
	}
	for _, ip := range ips {
		sp.IPs = append(sp.IPs, ip.String())
	}
	return sp
}

func keyUsageToNames(ku x509.KeyUsage) []string {
	pairs := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "certSign"},
		{x509.KeyUsageCRLSign, "crlSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var names []string
	for _, p := range pairs {
		if ku&p.bit != 0 {
			names = append(names, p.name)
		}
	}
	return names
}

func extKeyUsageToNames(ekus []x509.ExtKeyUsage) []string {
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "ocspSigning",
	}
	var names []string
	for _, eku := range ekus {
		if name, ok := m[eku]; ok {
			names = append(names, name)
		}
	}
	return names
}

func MarshalProfile(p *CertProfile) ([]byte, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return nil, err
	}
	return data, nil
}
