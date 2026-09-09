package output

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

type OutputOptions struct {
	// Skipped is what the scan passed over; carried into the structured output.
	Skipped []certlib.SkippedFile
	// DetailLevel is the -d count: 0 plain, 1 details, 2 extended (-dd).
	DetailLevel     int
	InsecureDetails bool
	HighlightQuery  string
	RelationIndex   certlib.RelationIndex
	Chains          map[certlib.ItemRef][]certlib.ItemRef
	// ChainsContaining maps any certificate to the chains it belongs to, so an
	// intermediate or a root can show its place too, not only a leaf.
	ChainsContaining map[certlib.ItemRef][][]certlib.ItemRef
	Store            *certlib.CertStore
	CheckResult      *certlib.CheckResult

	// FingerprintFormat controls how fingerprints are rendered for display.
	// The zero value means plain hex. It never affects JSON/YAML.
	FingerprintFormat certlib.FingerprintFormat

	// TrustIndex is set only when trust evaluation was requested. Nil means the
	// trust column and the trust fields are omitted entirely rather than shown
	// as unknown.
	TrustIndex *truststore.TrustIndex
	// StoreTags reports which trust stores hold a certificate. Supplied as a
	// function so this package does not depend on the operations layer.
	StoreTags func(*x509.Certificate) []string

	// StoreVerdicts holds, per remote target, one verdict per trust store the
	// user asked about. Nil unless a store selector was given.
	StoreVerdicts map[string][]certops.RemoteStoreVerdict
}

// Details reports whether the detail block should be rendered (-d or more).
func (o OutputOptions) Details() bool { return o.DetailLevel >= 1 }

// Extended reports whether the extended block should be rendered (-dd or more):
// the PEM body and anything else too bulky for -d.
func (o OutputOptions) Extended() bool { return o.DetailLevel >= 2 }

// TrustEnabled reports whether trust data is available for display.
func (o OutputOptions) TrustEnabled() bool { return o.TrustIndex != nil }

// TrustVerdict returns the display verdict for a certificate, empty when trust
// was not evaluated.
func (o OutputOptions) TrustVerdict(cert *x509.Certificate) string {
	if o.TrustIndex == nil || cert == nil {
		return ""
	}
	detail := o.TrustIndex.Detail(cert)
	display := detail.Verdict.Display()
	if display == "" {
		return ""
	}
	// A path that completes only through a fetched issuer is exactly the trust
	// a client which does not chase AIA does not have, so it never reads as
	// plain TRUSTED.
	if detail.ViaAIA {
		return display + " (via AIA)"
	}
	return display
}

// Fingerprints renders every supported digest of a certificate in the
// configured display format, in canonical algorithm order.
func (o OutputOptions) Fingerprints(cert *x509.Certificate) []FingerprintLine {
	var out []FingerprintLine
	for _, algo := range certlib.FingerprintAlgos {
		out = append(out, FingerprintLine{
			Label: algo.Label(),
			Value: certlib.CertFingerprint(cert, algo, o.FingerprintFormat),
		})
	}
	return out
}

// FingerprintLine is one labelled digest ready for display.
type FingerprintLine struct {
	Label string
	Value string
}

func FormatKeyAlgo(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func FormatPrivateKeyAlgo(key crypto.PrivateKey) string {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PrivateKey:
		return fmt.Sprintf("ECDSA-%s", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func FormatSubject(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return certlib.FormatDNName(cert.Subject)
}

func FormatSubjectDN(cert *x509.Certificate, maxLen int) string {
	dn := certlib.FormatDNName(cert.Subject)
	if maxLen > 0 {
		return truncate(dn, maxLen)
	}
	return dn
}

func FormatIssuer(cert *x509.Certificate) string {
	if certlib.IsSelfSigned(cert) {
		return "Self-signed"
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return certlib.FormatDNName(cert.Issuer)
}

func FormatSANs(cert *x509.Certificate) string {
	return strings.Join(certlib.FormatSANs(cert), ", ")
}

func FormatFileSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func FormatContentType(item *certlib.CertItem, format certlib.FileFormat) string {
	switch item.Type {
	case certlib.ContentCertificate:
		return fmt.Sprintf("%s/cert", format)
	case certlib.ContentPrivateKey:
		return fmt.Sprintf("%s/key", format)
	case certlib.ContentPublicKey:
		return fmt.Sprintf("%s/pubkey", format)
	case certlib.ContentCSR:
		return fmt.Sprintf("%s/csr", format)
	default:
		return string(format)
	}
}
