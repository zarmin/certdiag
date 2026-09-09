package certlib

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Name constraints: the mechanism that lets a CA be issued for one organisation
// without becoming a CA for the whole internet.
//
// They live on a CA and restrict every certificate below it. Go's x509.Verify
// enforces them, so certdiag already honours them silently; what was missing
// was the ability to create them, to see them, and to be told which name broke
// one instead of getting "x509: certificate is not authorized to sign".

// NameConstraints is the parsed form of the --permitted-names and
// --excluded-names values.
type NameConstraints struct {
	Critical bool

	PermittedDNS   []string
	ExcludedDNS    []string
	PermittedIP    []*net.IPNet
	ExcludedIP     []*net.IPNet
	PermittedEmail []string
	ExcludedEmail  []string
	PermittedURI   []string
	ExcludedURI    []string
}

// Empty reports whether nothing was constrained.
func (nc NameConstraints) Empty() bool {
	return len(nc.PermittedDNS) == 0 && len(nc.ExcludedDNS) == 0 &&
		len(nc.PermittedIP) == 0 && len(nc.ExcludedIP) == 0 &&
		len(nc.PermittedEmail) == 0 && len(nc.ExcludedEmail) == 0 &&
		len(nc.PermittedURI) == 0 && len(nc.ExcludedURI) == 0
}

// ParseNameConstraints reads the SAN-style syntax: DNS:, IP: (as CIDR), email:
// and URI:, comma separated.
//
// DNS semantics follow Go's, because Go is the verifier certdiag ships with:
// "example.com" matches that host and every subdomain, ".example.com" matches
// subdomains only. Documenting one rule and enforcing another would be worse
// than either.
func ParseNameConstraints(s string) (NameConstraints, error) {
	var nc NameConstraints
	s = strings.TrimSpace(s)
	if s == "" {
		return nc, nil
	}

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.Index(part, ":")
		if idx <= 0 {
			return nc, fmt.Errorf("name constraint %q needs a type prefix (DNS:, IP:, email: or URI:)", part)
		}
		kind := strings.ToLower(part[:idx])
		value := strings.TrimSpace(part[idx+1:])
		if value == "" {
			return nc, fmt.Errorf("name constraint %q has no value", part)
		}

		switch kind {
		case "dns":
			nc.PermittedDNS = append(nc.PermittedDNS, value)
		case "email":
			nc.PermittedEmail = append(nc.PermittedEmail, value)
		case "uri":
			nc.PermittedURI = append(nc.PermittedURI, value)
		case "ip":
			// CIDR only: the RFC's mask form is another way to write the same
			// thing and two syntaxes for one idea is one too many.
			_, ipNet, err := net.ParseCIDR(value)
			if err != nil {
				return nc, fmt.Errorf("IP constraint %q must be CIDR (for example 10.0.0.0/8): %w", value, err)
			}
			nc.PermittedIP = append(nc.PermittedIP, ipNet)
		default:
			return nc, fmt.Errorf("unknown name constraint type %q in %q (use DNS:, IP:, email: or URI:)", kind, part)
		}
	}
	return nc, nil
}

// Excluded turns a parsed set into the excluded side.
func (nc NameConstraints) Excluded() NameConstraints {
	return NameConstraints{
		ExcludedDNS:   nc.PermittedDNS,
		ExcludedIP:    nc.PermittedIP,
		ExcludedEmail: nc.PermittedEmail,
		ExcludedURI:   nc.PermittedURI,
	}
}

// Merge combines a permitted set and an excluded set.
func (nc NameConstraints) Merge(other NameConstraints) NameConstraints {
	nc.ExcludedDNS = append(nc.ExcludedDNS, other.ExcludedDNS...)
	nc.ExcludedIP = append(nc.ExcludedIP, other.ExcludedIP...)
	nc.ExcludedEmail = append(nc.ExcludedEmail, other.ExcludedEmail...)
	nc.ExcludedURI = append(nc.ExcludedURI, other.ExcludedURI...)
	nc.PermittedDNS = append(nc.PermittedDNS, other.PermittedDNS...)
	nc.PermittedIP = append(nc.PermittedIP, other.PermittedIP...)
	nc.PermittedEmail = append(nc.PermittedEmail, other.PermittedEmail...)
	nc.PermittedURI = append(nc.PermittedURI, other.PermittedURI...)
	return nc
}

// ApplyTo writes the constraints into generation options.
func (nc NameConstraints) ApplyTo(opts *CertGenOptions) {
	opts.PermittedDNSDomainsCritical = nc.Critical
	opts.PermittedDNSDomains = nc.PermittedDNS
	opts.ExcludedDNSDomains = nc.ExcludedDNS
	opts.PermittedIPRanges = nc.PermittedIP
	opts.ExcludedIPRanges = nc.ExcludedIP
	opts.PermittedEmailAddresses = nc.PermittedEmail
	opts.ExcludedEmailAddresses = nc.ExcludedEmail
	opts.PermittedURIDomains = nc.PermittedURI
	opts.ExcludedURIDomains = nc.ExcludedURI
}

// CheckNameConstraints reports the names a CA's constraints forbid.
//
// x509.CreateCertificate does not check this, so without it certdiag would
// happily produce a certificate it would itself flag as invalid. The rules
// mirror Go's verifier: excluded wins over permitted, an empty permitted set
// permits everything of that type, and the CN is treated as a DNS name only
// when there are no SANs.
func CheckNameConstraints(ca *x509.Certificate, commonName string, sans SANList) error {
	if ca == nil {
		return nil
	}

	dnsNames := append([]string(nil), sans.DNSNames...)
	if len(dnsNames) == 0 && len(sans.IPAddresses) == 0 && len(sans.EmailAddresses) == 0 &&
		commonName != "" && strings.Contains(commonName, ".") {
		dnsNames = append(dnsNames, commonName)
	}

	for _, name := range dnsNames {
		if err := checkDNSAgainst(ca, name); err != nil {
			return err
		}
	}
	for _, ip := range sans.IPAddresses {
		if err := checkIPAgainst(ca, ip); err != nil {
			return err
		}
	}
	for _, email := range sans.EmailAddresses {
		if err := checkEmailAgainst(ca, email); err != nil {
			return err
		}
	}
	for _, uri := range sans.URIs {
		if err := checkURIAgainst(ca, uri); err != nil {
			return err
		}
	}
	return nil
}

// checkURIAgainst applies URI constraints to the URI's host, as RFC 5280
// 4.2.1.10 and Go's verifier do: a host that is an IP address, or an empty
// host, cannot satisfy a URI constraint at all.
func checkURIAgainst(ca *x509.Certificate, uri *url.URL) error {
	if uri == nil || (len(ca.PermittedURIDomains) == 0 && len(ca.ExcludedURIDomains) == 0) {
		return nil
	}
	host := uri.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return fmt.Errorf("%q has no DNS host to match the CA's URI constraints", uri.String())
	}
	for _, excluded := range ca.ExcludedURIDomains {
		if dnsInSubtree(host, excluded) {
			return fmt.Errorf("%q is excluded by the CA's name constraints (excluded URI:%s)", uri.String(), excluded)
		}
	}
	if len(ca.PermittedURIDomains) == 0 {
		return nil
	}
	for _, permitted := range ca.PermittedURIDomains {
		if dnsInSubtree(host, permitted) {
			return nil
		}
	}
	return fmt.Errorf("%q is outside the CA's permitted URI domains (permitted: %s)",
		uri.String(), strings.Join(ca.PermittedURIDomains, ", "))
}

func checkDNSAgainst(ca *x509.Certificate, name string) error {
	for _, excluded := range ca.ExcludedDNSDomains {
		if dnsInSubtree(name, excluded) {
			return fmt.Errorf("%q is excluded by the CA's name constraints (excluded DNS:%s)", name, excluded)
		}
	}
	if len(ca.PermittedDNSDomains) == 0 {
		return nil
	}
	for _, permitted := range ca.PermittedDNSDomains {
		if dnsInSubtree(name, permitted) {
			return nil
		}
	}
	return fmt.Errorf("%q is outside the CA's permitted names (permitted DNS: %s)",
		name, strings.Join(ca.PermittedDNSDomains, ", "))
}

// dnsInSubtree implements Go's rule: a leading dot restricts to subdomains,
// otherwise the domain itself matches too.
func dnsInSubtree(name, constraint string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	constraint = strings.ToLower(strings.TrimSuffix(constraint, "."))
	if constraint == "" {
		return true
	}
	if strings.HasPrefix(constraint, ".") {
		return strings.HasSuffix(name, constraint)
	}
	return name == constraint || strings.HasSuffix(name, "."+constraint)
}

func checkIPAgainst(ca *x509.Certificate, ip net.IP) error {
	for _, excluded := range ca.ExcludedIPRanges {
		if excluded.Contains(ip) {
			return fmt.Errorf("%s is excluded by the CA's name constraints (excluded IP:%s)", ip, excluded)
		}
	}
	if len(ca.PermittedIPRanges) == 0 {
		return nil
	}
	for _, permitted := range ca.PermittedIPRanges {
		if permitted.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("%s is outside the CA's permitted IP ranges", ip)
}

func checkEmailAgainst(ca *x509.Certificate, email string) error {
	domain := email
	if at := strings.LastIndex(email, "@"); at >= 0 {
		domain = email[at+1:]
	}
	for _, excluded := range ca.ExcludedEmailAddresses {
		if emailInSubtree(email, domain, excluded) {
			return fmt.Errorf("%q is excluded by the CA's name constraints (excluded email:%s)", email, excluded)
		}
	}
	if len(ca.PermittedEmailAddresses) == 0 {
		return nil
	}
	for _, permitted := range ca.PermittedEmailAddresses {
		if emailInSubtree(email, domain, permitted) {
			return nil
		}
	}
	return fmt.Errorf("%q is outside the CA's permitted email addresses (permitted: %s)",
		email, strings.Join(ca.PermittedEmailAddresses, ", "))
}

func emailInSubtree(email, domain, constraint string) bool {
	if strings.Contains(constraint, "@") {
		return strings.EqualFold(email, constraint)
	}
	return dnsInSubtree(domain, constraint)
}

// NameConstraintsFromGenOptions reads constraints back out of generation
// options, which is how a cloned template or a YAML profile carries them.
func NameConstraintsFromGenOptions(opts CertGenOptions) NameConstraints {
	return NameConstraints{
		Critical:       opts.PermittedDNSDomainsCritical,
		PermittedDNS:   opts.PermittedDNSDomains,
		ExcludedDNS:    opts.ExcludedDNSDomains,
		PermittedIP:    opts.PermittedIPRanges,
		ExcludedIP:     opts.ExcludedIPRanges,
		PermittedEmail: opts.PermittedEmailAddresses,
		ExcludedEmail:  opts.ExcludedEmailAddresses,
		PermittedURI:   opts.PermittedURIDomains,
		ExcludedURI:    opts.ExcludedURIDomains,
	}
}
