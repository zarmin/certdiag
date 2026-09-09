package certops

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type CreateCertOptions struct {
	Subject pkix.Name
	SANs    certlib.SANList

	KeyFilePath      string
	KeyFilePasswords []certlib.TaggedPassword

	WithKey    bool
	KeyOptions certlib.KeyGenOptions

	SignerCertPath     string
	SignerKeyPath      string
	SignerKeyPasswords []certlib.TaggedPassword

	Days       int
	NotBefore  time.Time
	IsCA       bool
	PathLength int
	// NameConstraints restricts every certificate issued below this CA. Only
	// meaningful with IsCA.
	NameConstraints certlib.NameConstraints
	KeyUsage        x509.KeyUsage
	ExtKeyUsage     []x509.ExtKeyUsage
	Serial          *big.Int

	CertOutputPath string
	KeyOutputPath  string
	OutputFormat   certlib.FileFormat
	EncryptKey     bool
	KeyPassword    []byte
	Overwrite      bool
}

type CreateCertResult struct {
	CertBytes   []byte
	CertPath    string
	CertWritten bool

	KeyBytes   []byte
	KeyPath    string
	KeyWritten bool

	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialHex    string
	KeyType      string
	IsCA         bool
	IsSelfSigned bool
}

func CreateCert(opts CreateCertOptions) (*CreateCertResult, error) {
	if opts.KeyFilePath == "" && !opts.WithKey {
		return nil, &OperationError{Op: "create-cert", Message: "either --key-file or --with-key is required"}
	}
	if opts.KeyFilePath != "" && opts.WithKey {
		return nil, &OperationError{Op: "create-cert", Message: "cannot use both --key-file and --with-key"}
	}
	if (opts.SignerCertPath == "") != (opts.SignerKeyPath == "") {
		return nil, &OperationError{Op: "create-cert", Message: "both --sign-ca and --sign-key must be specified together"}
	}

	var key crypto.PrivateKey
	var err error

	if opts.WithKey {
		key, err = certlib.GenerateKey(opts.KeyOptions)
		if err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "key generation failed", Err: err}
		}
	} else {
		key, err = loadPrivateKey(opts.KeyFilePath, opts.KeyFilePasswords)
		if err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "load key failed", Err: err}
		}
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
		Subject:     opts.Subject,
		SANs:        opts.SANs,
		Days:        opts.Days,
		NotBefore:   opts.NotBefore,
		IsCA:        opts.IsCA,
		PathLength:  opts.PathLength,
		KeyUsage:    ku,
		ExtKeyUsage: eku,
		Serial:      opts.Serial,
	}
	if opts.IsCA {
		opts.NameConstraints.ApplyTo(&genOpts)
	}

	isSelfSigned := opts.SignerCertPath == ""

	if !isSelfSigned {
		signerCert, err := loadCertificate(opts.SignerCertPath, opts.SignerKeyPasswords)
		if err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "load signer cert failed", Err: err}
		}
		signerKey, err := loadPrivateKey(opts.SignerKeyPath, opts.SignerKeyPasswords)
		if err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "load signer key failed", Err: err}
		}
		if !certlib.KeyMatchesCert(signerKey, signerCert) {
			return nil, &OperationError{Op: "create-cert", Message: "signer key does not match signer certificate"}
		}
		genOpts.SignerCert = signerCert
		genOpts.SignerKey = signerKey

		// A CA that says what it may issue for should not be asked to issue
		// something else. x509.CreateCertificate does not check this, so
		// without it certdiag would produce a certificate it then flags as
		// invalid.
		if err := certlib.CheckNameConstraints(signerCert, opts.Subject.CommonName, opts.SANs); err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "refusing to sign: " + err.Error()}
		}
	}

	var cert *x509.Certificate
	var certDER []byte

	if isSelfSigned {
		cert, certDER, err = certlib.CreateSelfSignedCert(key, genOpts)
	} else {
		cert, certDER, err = certlib.CreateSignedCert(key, genOpts)
	}
	if err != nil {
		return nil, &OperationError{Op: "create-cert", Message: "certificate creation failed", Err: err}
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
		return nil, &OperationError{Op: "create-cert", Message: "encode certificate failed", Err: err}
	}

	result := &CreateCertResult{
		CertBytes:    certEncoded,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialHex:    certlib.FormatSerial(cert.SerialNumber),
		KeyType:      formatKeyType(key),
		IsCA:         cert.IsCA,
		IsSelfSigned: isSelfSigned,
	}

	if opts.CertOutputPath != "" {
		if err := certlib.WriteToFile(opts.CertOutputPath, certEncoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "create-cert", Message: "write cert failed", Err: err}
		}
		result.CertPath = opts.CertOutputPath
		result.CertWritten = true
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
			return nil, &OperationError{Op: "create-cert", Message: "encode key failed", Err: err}
		}

		result.KeyBytes = keyEncoded

		if opts.KeyOutputPath != "" {
			if err := certlib.WriteToFile(opts.KeyOutputPath, keyEncoded, opts.Overwrite); err != nil {
				return nil, &OperationError{Op: "create-cert", Message: "write key failed", Err: err}
			}
			result.KeyPath = opts.KeyOutputPath
			result.KeyWritten = true
		}
	}

	return result, nil
}
