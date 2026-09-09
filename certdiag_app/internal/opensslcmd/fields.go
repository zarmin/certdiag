package opensslcmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// opensslSubject converts a pkix.Name to an openssl -subj string (slash-style,
// e.g. /C=US/O=Org/CN=foo). Attributes are emitted in Go's ToRDNSequence order
// so the resulting DN matches what certdiag's x509 marshaling produces. It
// returns any notes for attributes with no openssl short name.
func opensslSubject(name pkix.Name) (string, []string) {
	var b strings.Builder
	var notes []string

	add := func(key, val string) {
		b.WriteByte('/')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(escapeSubjectValue(val))
	}

	// Order matches pkix.Name.ToRDNSequence exactly (C, ST, L, street,
	// postalCode, O, OU, CN, serialNumber) so the RDN sequence in the openssl
	// artifact's subject matches certdiag's x509 marshaling.
	for _, v := range name.Country {
		add("C", v)
	}
	for _, v := range name.Province {
		add("ST", v)
	}
	for _, v := range name.Locality {
		add("L", v)
	}
	for _, v := range name.StreetAddress {
		add("street", v)
	}
	for _, v := range name.PostalCode {
		add("postalCode", v)
	}
	for _, v := range name.Organization {
		add("O", v)
	}
	for _, v := range name.OrganizationalUnit {
		add("OU", v)
	}
	if name.CommonName != "" {
		add("CN", name.CommonName)
	}
	if name.SerialNumber != "" {
		add("serialNumber", name.SerialNumber)
	}
	for _, atv := range name.ExtraNames {
		val := fmt.Sprintf("%v", atv.Value)
		short, ok := extraOIDShortName(atv.Type)
		if !ok {
			short = atv.Type.String()
			notes = append(notes, fmt.Sprintf("DN attribute %s has no openssl short name; using its numeric OID", atv.Type.String()))
		}
		add(short, val)
	}

	if b.Len() == 0 {
		return "/", notes
	}
	return b.String(), notes
}

func escapeSubjectValue(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `/`, `\/`)
	return v
}

var extraOIDNames = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "emailAddress"},
	{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "DC"},
	{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, "UID"},
	{asn1.ObjectIdentifier{2, 5, 4, 4}, "SN"},
	{asn1.ObjectIdentifier{2, 5, 4, 42}, "GN"},
	{asn1.ObjectIdentifier{2, 5, 4, 12}, "title"},
	{asn1.ObjectIdentifier{2, 5, 4, 15}, "businessCategory"},
}

func extraOIDShortName(oid asn1.ObjectIdentifier) (string, bool) {
	for _, e := range extraOIDNames {
		if e.oid.Equal(oid) {
			return e.name, true
		}
	}
	return "", false
}

// sanExtension builds an openssl subjectAltName extension value, or "" when
// there are no SANs.
func sanExtension(sans certlib.SANList) string {
	var parts []string
	for _, d := range sans.DNSNames {
		parts = append(parts, "DNS:"+d)
	}
	for _, ip := range sans.IPAddresses {
		parts = append(parts, "IP:"+ip.String())
	}
	for _, e := range sans.EmailAddresses {
		parts = append(parts, "email:"+e)
	}
	for _, u := range sans.URIs {
		parts = append(parts, "URI:"+u.String())
	}
	if len(parts) == 0 {
		return ""
	}
	return "subjectAltName=" + strings.Join(parts, ",")
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsageExtension(ku x509.KeyUsage) string {
	var parts []string
	for _, e := range keyUsageBits {
		if ku&e.bit != 0 {
			parts = append(parts, e.name)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "keyUsage=critical," + strings.Join(parts, ",")
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:             "anyExtendedKeyUsage",
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
}

func extKeyUsageExtension(ekus []x509.ExtKeyUsage) string {
	var parts []string
	for _, e := range ekus {
		if n, ok := extKeyUsageNames[e]; ok {
			parts = append(parts, n)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "extendedKeyUsage=" + strings.Join(parts, ",")
}

func basicConstraintsExtension(isCA bool, pathLen int) string {
	// Go marks basicConstraints critical whenever BasicConstraintsValid is set,
	// which certdiag always does - for leaves too.
	if !isCA {
		return "basicConstraints=critical,CA:FALSE"
	}
	s := "basicConstraints=critical,CA:TRUE"
	if pathLen >= 0 {
		s += fmt.Sprintf(",pathlen:%d", pathLen)
	}
	return s
}

func opensslCurve(internal string) (string, bool) {
	switch strings.ToLower(internal) {
	case "p256":
		return "P-256", true
	case "p384":
		return "P-384", true
	case "p521":
		return "P-521", true
	}
	return internal, false
}
