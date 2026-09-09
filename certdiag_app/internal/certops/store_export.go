package certops

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// ExportCertificate writes a single certificate to path. Format follows the
// file extension, defaulting to PEM.
func ExportCertificate(cert *x509.Certificate, path string, overwrite bool) error {
	if cert == nil {
		return &OperationError{Op: "export", Message: "no certificate selected"}
	}

	item := certlib.CertItem{
		Type:        certlib.ContentCertificate,
		Certificate: cert,
		RawBytes:    cert.Raw,
	}

	format, ok := certlib.FormatFromExtension(filepath.Ext(path))
	if !ok {
		format = certlib.FormatPEM
	}

	var buf bytes.Buffer
	var err error
	switch format {
	case certlib.FormatDER:
		err = certlib.WriteDER(&buf, item)
	case certlib.FormatPKCS7:
		err = certlib.WritePKCS7(&buf, []certlib.CertItem{item})
	default:
		err = certlib.WritePEM(&buf, []certlib.CertItem{item})
	}
	if err != nil {
		return &OperationError{Op: "export", Message: err.Error()}
	}

	if err := certlib.WriteToFile(path, buf.Bytes(), overwrite); err != nil {
		return &OperationError{Op: "export", Message: err.Error()}
	}
	return nil
}

// CertExportName derives a filesystem-safe base name for a certificate.
func CertExportName(cert *x509.Certificate) string {
	if cert == nil {
		return "certificate"
	}
	name := strings.TrimSpace(cert.Subject.CommonName)
	if name == "" && len(cert.Subject.Organization) > 0 {
		name = strings.TrimSpace(cert.Subject.Organization[0])
	}
	if name == "" {
		name = fmt.Sprintf("%x", cert.SerialNumber)
	}
	return stringutil.SanitizeFilename(name)
}

// ReadCertificatesFromFile loads every certificate in a file, for verification
// against a trust store.
func ReadCertificatesFromFile(path string, passwords []certlib.TaggedPassword) ([]*x509.Certificate, error) {
	tagged := append([]certlib.TaggedPassword{}, passwords...)
	tagged = append(tagged, certlib.TaggedPassword{Password: []byte(""), Source: certlib.PasswordSourceNone})

	container, err := certlib.ReadFile(path, tagged)
	if err != nil {
		return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("read %s: %v", path, err)}
	}

	var certs []*x509.Certificate
	for _, item := range container.Items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil {
			certs = append(certs, item.Certificate)
		}
	}
	if len(certs) == 0 {
		return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("no certificates found in %s", path)}
	}
	return certs, nil
}
