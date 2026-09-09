package certops

import (
	"crypto"
	"crypto/x509"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type RenewOptions struct {
	CertPath      string
	CertPasswords []certlib.TaggedPassword

	KeyFilePath      string
	KeyFilePasswords []certlib.TaggedPassword
	NewKey           bool
	KeyOptions       certlib.KeyGenOptions

	SignerCertPath     string
	SignerKeyPath      string
	SignerKeyPasswords []certlib.TaggedPassword

	AutosignDirs      []string
	AutosignPasswords []certlib.TaggedPassword

	Days int

	CertOutputPath string
	KeyOutputPath  string
	OutputFormat   certlib.FileFormat
	EncryptKey     bool
	KeyPassword    []byte
	Overwrite      bool
}

type RenewResult struct {
	CertBytes []byte
	KeyBytes  []byte
	CertPath  string
	KeyPath   string

	CertWritten bool
	KeyWritten  bool

	Subject      string
	Issuer       string
	SerialHex    string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyType      string
	IsCA         bool
	IsSelfSigned bool
	KeyReused    bool
}

func Renew(opts RenewOptions) (*RenewResult, error) {
	// 1. Read the original certificate
	tagged := append([]certlib.TaggedPassword{}, opts.CertPasswords...)
	tagged = append(tagged, certlib.TaggedPassword{
		Password: []byte(""),
		Source:   certlib.PasswordSourceNone,
	})

	container, err := certlib.ReadFile(opts.CertPath, tagged)
	if err != nil {
		return nil, &OperationError{Op: "renew", Message: "read certificate failed", Err: err}
	}

	var origCert *x509.Certificate
	var bundledKey crypto.PrivateKey
	for _, item := range container.Items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil && origCert == nil {
			origCert = item.Certificate
		}
		if item.Type == certlib.ContentPrivateKey && item.PrivateKey != nil && bundledKey == nil {
			bundledKey = item.PrivateKey
		}
	}
	if origCert == nil {
		return nil, &OperationError{Op: "renew", Message: "no certificate found in input file"}
	}

	// 2. Build template from original cert
	genOpts := certlib.TemplateFromCert(origCert)

	// 3. Override days if specified
	if opts.Days > 0 {
		genOpts.Days = opts.Days
	}

	// 4. Clear serial and NotBefore for fresh values
	genOpts.Serial = nil
	genOpts.NotBefore = time.Time{}

	// 5. Resolve key
	var key crypto.PrivateKey
	keyReused := false

	if opts.NewKey {
		key, err = certlib.GenerateKey(opts.KeyOptions)
		if err != nil {
			return nil, &OperationError{Op: "renew", Message: "key generation failed", Err: err}
		}
	} else if opts.KeyFilePath != "" {
		key, err = loadPrivateKey(opts.KeyFilePath, opts.KeyFilePasswords)
		if err != nil {
			return nil, &OperationError{Op: "renew", Message: "load key file failed", Err: err}
		}
		keyReused = true
	} else if bundledKey != nil {
		key = bundledKey
		keyReused = true
	} else {
		// Try to find key among sibling files
		key, err = findSiblingKey(opts.CertPath, opts.CertPasswords, origCert)
		if err != nil {
			return nil, &OperationError{Op: "renew", Message: "no private key found (use --key-file or --new-key)", Err: err}
		}
		keyReused = true
	}

	// 6. Resolve signer
	wasSelfSigned := isCertSelfSigned(origCert)

	if opts.SignerCertPath != "" && opts.SignerKeyPath != "" {
		signerCert, err := loadCertificate(opts.SignerCertPath, opts.SignerKeyPasswords)
		if err != nil {
			return nil, &OperationError{Op: "renew", Message: "load signer cert failed", Err: err}
		}
		signerKey, err := loadPrivateKey(opts.SignerKeyPath, opts.SignerKeyPasswords)
		if err != nil {
			return nil, &OperationError{Op: "renew", Message: "load signer key failed", Err: err}
		}
		if !certlib.KeyMatchesCert(signerKey, signerCert) {
			return nil, &OperationError{Op: "renew", Message: "signer key does not match signer certificate"}
		}
		genOpts.SignerCert = signerCert
		genOpts.SignerKey = signerKey
	} else if len(opts.AutosignDirs) > 0 {
		caResult, err := FindCA(FindCAOptions{
			SearchDirs: opts.AutosignDirs,
			Passwords:  opts.AutosignPasswords,
		})
		if err == nil {
			genOpts.SignerCert = caResult.CACert
			genOpts.SignerKey = caResult.CAKey
		} else if !wasSelfSigned {
			return nil, &OperationError{Op: "renew", Message: "no CA found for signing (original was not self-signed)", Err: err}
		}
		// If self-signed and no CA found, fall through to self-signed renewal
	} else if !wasSelfSigned {
		return nil, &OperationError{Op: "renew", Message: "original certificate was not self-signed; provide --sign-ca/--sign-key or --autosign"}
	}

	// 7. Create the renewed certificate
	isSelfSigned := genOpts.SignerCert == nil

	var cert *x509.Certificate
	var certDER []byte

	if isSelfSigned {
		cert, certDER, err = certlib.CreateSelfSignedCert(key, genOpts)
	} else {
		cert, certDER, err = certlib.CreateSignedCert(key, genOpts)
	}
	if err != nil {
		return nil, &OperationError{Op: "renew", Message: "certificate creation failed", Err: err}
	}
	_ = certDER

	// 8. Encode and write
	certItem := certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert}
	var certEncoded []byte
	switch opts.OutputFormat {
	case certlib.FormatDER:
		certEncoded, err = certlib.EncodeDER(certItem)
	default:
		certEncoded, err = certlib.EncodePEM([]certlib.CertItem{certItem})
	}
	if err != nil {
		return nil, &OperationError{Op: "renew", Message: "encode certificate failed", Err: err}
	}

	result := &RenewResult{
		CertBytes:    certEncoded,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialHex:    certlib.FormatSerial(cert.SerialNumber),
		KeyType:      formatKeyType(key),
		IsCA:         cert.IsCA,
		IsSelfSigned: isSelfSigned,
		KeyReused:    keyReused,
	}

	if opts.CertOutputPath != "" {
		if err := certlib.WriteToFile(opts.CertOutputPath, certEncoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "renew", Message: "write cert failed", Err: err}
		}
		result.CertPath = opts.CertOutputPath
		result.CertWritten = true
	}

	// Write key if new key was generated or key output is requested
	if opts.NewKey || opts.KeyOutputPath != "" {
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
			return nil, &OperationError{Op: "renew", Message: "encode key failed", Err: err}
		}

		result.KeyBytes = keyEncoded

		if opts.KeyOutputPath != "" {
			if err := certlib.WriteToFile(opts.KeyOutputPath, keyEncoded, opts.Overwrite); err != nil {
				return nil, &OperationError{Op: "renew", Message: "write key failed", Err: err}
			}
			result.KeyPath = opts.KeyOutputPath
			result.KeyWritten = true
		}
	}

	return result, nil
}

func findSiblingKey(certPath string, passwords []certlib.TaggedPassword, cert *x509.Certificate) (crypto.PrivateKey, error) {
	provider := &staticPasswordProvider{passwords: passwords}
	siblings, err := certlib.ScanSiblings([]string{certPath}, certlib.ScanOptions{
		PasswordProvider: provider,
	})
	if err != nil {
		return nil, err
	}

	// Also include the original file's directory items
	store := certlib.NewCertStore()
	for _, c := range siblings.Containers {
		store.AddContainer(c)
	}

	// Add a fake container for the original cert so relations can match
	store.AddContainer(certlib.CertContainer{
		FilePath: certPath,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: cert}},
	})

	relations := certlib.DetectRelations(store)
	for _, rel := range relations {
		if rel.Type != certlib.RelationKeyCert {
			continue
		}
		keyItem := store.SafeItem(rel.Source)
		if keyItem == nil || keyItem.PrivateKey == nil {
			continue
		}
		// Only accept a key whose public part matches the cert being renewed.
		// Without this check, findSiblingKey returned the first key/cert pair in
		// the directory (e.g. a sibling CA's key), silently renewing the cert
		// with the wrong key pair.
		if !certlib.KeyMatchesCert(keyItem.PrivateKey, cert) {
			continue
		}
		return keyItem.PrivateKey, nil
	}

	return nil, &OperationError{Op: "renew", Message: "no matching private key found in sibling files"}
}
