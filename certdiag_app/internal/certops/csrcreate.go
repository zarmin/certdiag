package certops

import (
	"crypto"
	"crypto/x509/pkix"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type CreateCSROptions struct {
	Subject pkix.Name
	SANs    certlib.SANList

	KeyFilePath      string
	KeyFilePasswords []certlib.TaggedPassword

	WithKey    bool
	KeyOptions certlib.KeyGenOptions

	CSROutputPath string
	KeyOutputPath string
	OutputFormat  certlib.FileFormat
	EncryptKey    bool
	KeyPassword   []byte
	Overwrite     bool
}

type CreateCSRResult struct {
	CSRBytes   []byte
	CSRPath    string
	CSRWritten bool

	KeyBytes   []byte
	KeyPath    string
	KeyWritten bool

	Subject string
	KeyType string
}

func CreateCSR(opts CreateCSROptions) (*CreateCSRResult, error) {
	if opts.KeyFilePath == "" && !opts.WithKey {
		return nil, &OperationError{Op: "csr", Message: "either --key-file or --with-key is required"}
	}
	if opts.KeyFilePath != "" && opts.WithKey {
		return nil, &OperationError{Op: "csr", Message: "cannot use both --key-file and --with-key"}
	}

	var key crypto.PrivateKey
	var err error

	if opts.WithKey {
		key, err = certlib.GenerateKey(opts.KeyOptions)
		if err != nil {
			return nil, &OperationError{Op: "csr", Message: "key generation failed", Err: err}
		}
	} else {
		key, err = loadPrivateKey(opts.KeyFilePath, opts.KeyFilePasswords)
		if err != nil {
			return nil, &OperationError{Op: "csr", Message: "load key failed", Err: err}
		}
	}

	genOpts := certlib.CertGenOptions{
		Subject: opts.Subject,
		SANs:    opts.SANs,
	}

	csr, _, err := certlib.CreateCSR(key, genOpts)
	if err != nil {
		return nil, &OperationError{Op: "csr", Message: "CSR creation failed", Err: err}
	}

	csrItem := certlib.CertItem{Type: certlib.ContentCSR, CSR: csr}
	var csrEncoded []byte
	switch opts.OutputFormat {
	case certlib.FormatDER:
		csrEncoded, err = certlib.EncodeDER(csrItem)
	default:
		csrEncoded, err = certlib.EncodePEM([]certlib.CertItem{csrItem})
	}
	if err != nil {
		return nil, &OperationError{Op: "csr", Message: "encode CSR failed", Err: err}
	}

	result := &CreateCSRResult{
		CSRBytes: csrEncoded,
		Subject:  csr.Subject.String(),
		KeyType:  formatKeyType(key),
	}

	if opts.CSROutputPath != "" {
		if err := certlib.WriteToFile(opts.CSROutputPath, csrEncoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "csr", Message: "write CSR failed", Err: err}
		}
		result.CSRPath = opts.CSROutputPath
		result.CSRWritten = true
	}

	if opts.WithKey {
		var keyEncoded []byte
		if opts.EncryptKey && opts.OutputFormat != certlib.FormatDER {
			keyEncoded, err = encodePEMEncrypted(key, opts.KeyPassword)
		} else {
			keyItem := certlib.CertItem{Type: certlib.ContentPrivateKey, PrivateKey: key}
			switch opts.OutputFormat {
			case certlib.FormatDER:
				keyEncoded, err = certlib.EncodeDER(keyItem)
			default:
				keyEncoded, err = certlib.EncodePEM([]certlib.CertItem{keyItem})
			}
		}
		if err != nil {
			return nil, &OperationError{Op: "csr", Message: "encode key failed", Err: err}
		}

		result.KeyBytes = keyEncoded

		if opts.KeyOutputPath != "" {
			if err := certlib.WriteToFile(opts.KeyOutputPath, keyEncoded, opts.Overwrite); err != nil {
				return nil, &OperationError{Op: "csr", Message: "write key failed", Err: err}
			}
			result.KeyPath = opts.KeyOutputPath
			result.KeyWritten = true
		}
	}

	return result, nil
}
