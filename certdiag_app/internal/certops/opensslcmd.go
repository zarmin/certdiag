package certops

import (
	"crypto/x509"
	"path/filepath"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/opensslcmd"
)

// This file bridges the resolved certops option structs to the opensslcmd
// generator so the CLI and the TUI produce identical "equivalent openssl"
// commands from a single source of truth.

func placeholderKeyPath(path string) string {
	if path != "" {
		return path
	}
	return "key.pem"
}

// OpenSSLForGenerateKey returns the openssl command equivalent to a key generation.
func OpenSSLForGenerateKey(opts GenerateKeyOptions) []opensslcmd.Command {
	return []opensslcmd.Command{opensslcmd.KeyGen(
		certlib.KeyGenOptions{Algorithm: opts.Algorithm, KeySize: opts.KeySize, Curve: opts.Curve},
		opts.OutputPath, opts.Format, opts.Encrypt,
	)}
}

// OpenSSLForCreateCSR returns the openssl commands equivalent to a CSR creation.
func OpenSSLForCreateCSR(opts CreateCSROptions) []opensslcmd.Command {
	var cmds []opensslcmd.Command
	keyPath := opts.KeyFilePath
	if opts.WithKey {
		keyPath = placeholderKeyPath(opts.KeyOutputPath)
		cmds = append(cmds, opensslcmd.KeyGen(opts.KeyOptions, keyPath, opts.OutputFormat, opts.EncryptKey))
	}
	cmds = append(cmds, opensslcmd.CSR(opts.Subject, opts.SANs, keyPath, opts.CSROutputPath, opts.OutputFormat))
	return cmds
}

// OpenSSLForCreateCert returns the openssl commands equivalent to a certificate
// creation (self-signed or CA-signed).
func OpenSSLForCreateCert(opts CreateCertOptions) []opensslcmd.Command {
	var cmds []opensslcmd.Command
	keyPath := opts.KeyFilePath
	if opts.WithKey {
		keyPath = placeholderKeyPath(opts.KeyOutputPath)
		cmds = append(cmds, opensslcmd.KeyGen(opts.KeyOptions, keyPath, opts.OutputFormat, opts.EncryptKey))
	}

	// Mirror the KeyUsage/ExtKeyUsage defaults CreateCert applies so the emitted
	// extensions match the certificate certdiag would produce.
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

	if opts.SignerCertPath == "" {
		cmds = append(cmds, opensslcmd.SelfSignedCert(opensslcmd.CertSpec{
			Subject:     opts.Subject,
			SANs:        opts.SANs,
			Days:        opts.Days,
			NotBefore:   opts.NotBefore,
			IsCA:        opts.IsCA,
			PathLength:  opts.PathLength,
			KeyUsage:    ku,
			ExtKeyUsage: eku,
			Serial:      opts.Serial,
			KeyPath:     keyPath,
			OutputPath:  opts.CertOutputPath,
			Format:      opts.OutputFormat,
		}))
		return cmds
	}

	// CA-signed: certdiag signs directly from the key+template; the closest
	// openssl recipe is CSR then x509 -req.
	csrPath := "request.csr"
	csrCmd := opensslcmd.CSR(opts.Subject, opts.SANs, keyPath, csrPath, certlib.FormatPEM)
	csrCmd.Notes = append(csrCmd.Notes, "certdiag signs directly from the key and template; this CSR + x509 -req is the closest openssl recipe")
	cmds = append(cmds, csrCmd)
	cmds = append(cmds, opensslcmd.SignCSR(csrPath, opts.SignerCertPath, opts.SignerKeyPath, opts.CertOutputPath, opts.Days, opts.Serial, opts.OutputFormat,
		&opensslcmd.SignExtSpec{IsCA: opts.IsCA, PathLength: opts.PathLength, KeyUsage: ku, ExtKeyUsage: eku, NotBefore: opts.NotBefore}))
	return cmds
}

// OpenSSLForSignCSR returns the openssl command equivalent to signing a CSR.
func OpenSSLForSignCSR(opts SignCSROptions) []opensslcmd.Command {
	// Mirror the KeyUsage/ExtKeyUsage defaults SignCSR applies so the emitted
	// extensions match the certificate certdiag would produce.
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
	return []opensslcmd.Command{opensslcmd.SignCSR(
		opts.CSRPath, opts.CACertPath, opts.CAKeyPath, opts.CertOutputPath, opts.Days, opts.Serial, opts.OutputFormat,
		&opensslcmd.SignExtSpec{IsCA: opts.IsCA, PathLength: opts.PathLength, KeyUsage: ku, ExtKeyUsage: eku, NotBefore: opts.NotBefore},
	)}
}

// OpenSSLForConvert returns the openssl (or keytool) command(s) equivalent to a
// format conversion.
func OpenSSLForConvert(opts ConvertOptions) []opensslcmd.Command {
	inFmt, ok := certlib.FormatFromExtension(filepath.Ext(opts.InputPath))
	if !ok {
		return []opensslcmd.Command{opensslcmd.Note(
			"cannot show an openssl equivalent: unrecognized input format for " + opts.InputPath)}
	}
	return opensslcmd.Convert(opts.InputPath, inFmt, opts.OutputPath, opts.OutputFormat, opts.Include, opts.LegacyPKCS12)
}
