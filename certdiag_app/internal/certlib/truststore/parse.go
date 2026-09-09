package truststore

import (
	"bytes"
	"crypto/x509"
)

// parseCertCopy parses a certificate from a copy of buf. x509.ParseCertificate
// retains subslices of its input (cert.Raw, RawTBSCertificate, extension values,
// ...), so when buf points at memory owned by the OS (e.g. a Win32 CERT_CONTEXT
// buffer that is freed/reused on the next enumeration) the parsed certificate
// must not alias it. Cloning first makes the returned cert self-contained.
func parseCertCopy(buf []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(bytes.Clone(buf))
}
