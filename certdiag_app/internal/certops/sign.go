package certops

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type SignCSROptions struct {
	CSRPath string

	CACertPath     string
	CAKeyPath      string
	CAKeyPasswords []certlib.TaggedPassword

	Days        int
	NotBefore   time.Time
	IsCA        bool
	PathLength  int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	Serial      *big.Int

	CertOutputPath string
	OutputFormat   certlib.FileFormat
	Overwrite      bool
}

type SignCSRResult struct {
	CertBytes   []byte
	CertPath    string
	CertWritten bool

	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	SerialHex string
	IsCA      bool

	// Notes say where the issued certificate departs from what the CSR asked
	// for in its extensionRequest (key usage, extended key usage, basic
	// constraints). The CSR is a request; the signer's options win, but
	// silently issuing something else is the mistake M31 M4 names.
	Notes []string
}

func SignCSR(opts SignCSROptions) (*SignCSRResult, error) {
	csr, err := loadCSR(opts.CSRPath)
	if err != nil {
		return nil, &OperationError{Op: "sign", Message: "load CSR failed", Err: err}
	}

	caCert, err := loadCertificate(opts.CACertPath, opts.CAKeyPasswords)
	if err != nil {
		return nil, &OperationError{Op: "sign", Message: "load CA cert failed", Err: err}
	}

	caKey, err := loadPrivateKey(opts.CAKeyPath, opts.CAKeyPasswords)
	if err != nil {
		return nil, &OperationError{Op: "sign", Message: "load CA key failed", Err: err}
	}

	if !certlib.KeyMatchesCert(caKey, caCert) {
		return nil, &OperationError{Op: "sign", Message: "signer key does not match signer certificate"}
	}

	ku := opts.KeyUsage
	eku := opts.ExtKeyUsage
	if ku == 0 {
		if opts.IsCA {
			ku = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}
	if eku == nil && !opts.IsCA {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	genOpts := certlib.CertGenOptions{
		Days:        opts.Days,
		NotBefore:   opts.NotBefore,
		IsCA:        opts.IsCA,
		PathLength:  opts.PathLength,
		KeyUsage:    ku,
		ExtKeyUsage: eku,
		Serial:      opts.Serial,
	}

	// The same refusal create-cert makes: a CA that says what it may issue for
	// must not be asked to issue something else.
	if err := certlib.CheckNameConstraints(caCert, csr.Subject.CommonName, certlib.SANList{
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}); err != nil {
		return nil, &OperationError{Op: "sign", Message: "refusing to sign: " + err.Error()}
	}

	cert, certDER, err := certlib.SignCSR(csr, caKey, caCert, genOpts)
	if err != nil {
		return nil, &OperationError{Op: "sign", Message: "sign CSR failed", Err: err}
	}
	_ = certDER

	certItem := certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert}
	var certEncoded []byte
	switch opts.OutputFormat {
	case certlib.FormatDER:
		certEncoded, err = certlib.EncodeDER(certItem)
	default:
		certEncoded, err = certlib.EncodePEM([]certlib.CertItem{certItem})
	}
	if err != nil {
		return nil, &OperationError{Op: "sign", Message: "encode certificate failed", Err: err}
	}

	result := &SignCSRResult{
		Notes:     csrRequestNotes(csr, ku, eku, opts.IsCA),
		CertBytes: certEncoded,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		SerialHex: certlib.FormatSerial(cert.SerialNumber),
		IsCA:      cert.IsCA,
	}

	if opts.CertOutputPath != "" {
		if err := certlib.WriteToFile(opts.CertOutputPath, certEncoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "sign", Message: "write cert failed", Err: err}
		}
		result.CertPath = opts.CertOutputPath
		result.CertWritten = true
	}

	return result, nil
}

// csrRequestNotes compares the CSR's requested extensions with what is being
// issued and describes each difference.
func csrRequestNotes(csr *x509.CertificateRequest, ku x509.KeyUsage, eku []x509.ExtKeyUsage, isCA bool) []string {
	req := certlib.CSRRequestedExtensions(csr)
	var notes []string
	if req.HasBasicConstraints && req.IsCA != isCA {
		want, got := "a CA", "a leaf"
		if !req.IsCA {
			want, got = "a leaf", "a CA"
		}
		notes = append(notes, fmt.Sprintf("CSR requests %s certificate, issuing %s", want, got))
	}
	if req.HasKeyUsage && req.KeyUsage != ku {
		notes = append(notes, fmt.Sprintf("CSR requests key usage %s, issuing %s",
			orNone(certlib.FormatKeyUsageInternal(req.KeyUsage)), orNone(certlib.FormatKeyUsageInternal(ku))))
	}
	if req.HasExtKeyUsage && !sameExtKeyUsage(req.ExtKeyUsage, req.UnknownExtKeyUsage, eku) {
		requested := certlib.FormatExtKeyUsageInternal(req.ExtKeyUsage)
		if len(req.UnknownExtKeyUsage) > 0 {
			requested = strings.TrimPrefix(requested+","+strings.Join(req.UnknownExtKeyUsage, ","), ",")
		}
		notes = append(notes, fmt.Sprintf("CSR requests extended key usage %s, issuing %s",
			orNone(requested), orNone(certlib.FormatExtKeyUsageInternal(eku))))
	}
	return notes
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func sameExtKeyUsage(requested []x509.ExtKeyUsage, unknown []string, issued []x509.ExtKeyUsage) bool {
	if len(unknown) > 0 || len(requested) != len(issued) {
		return false
	}
	have := map[x509.ExtKeyUsage]bool{}
	for _, e := range issued {
		have[e] = true
	}
	for _, e := range requested {
		if !have[e] {
			return false
		}
	}
	return true
}
