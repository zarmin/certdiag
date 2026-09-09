package certops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type GenerateKeyOptions struct {
	Algorithm  string
	KeySize    int
	Curve      string
	OutputPath string
	Format     certlib.FileFormat
	Encrypt    bool
	Password   []byte
	Overwrite  bool
}

type GenerateKeyResult struct {
	KeyBytes   []byte
	KeyType    string
	OutputPath string
	Written    bool
}

func GenerateKey(opts GenerateKeyOptions) (*GenerateKeyResult, error) {
	key, err := certlib.GenerateKey(certlib.KeyGenOptions{
		Algorithm: opts.Algorithm,
		KeySize:   opts.KeySize,
		Curve:     opts.Curve,
	})
	if err != nil {
		return nil, &OperationError{Op: "generate-key", Message: "key generation failed", Err: err}
	}

	var encoded []byte

	switch opts.Format {
	case certlib.FormatDER:
		if opts.Encrypt {
			return nil, &OperationError{Op: "generate-key", Message: "encrypted DER output is not supported, use PEM format"}
		}
		item := certlib.CertItem{Type: certlib.ContentPrivateKey, PrivateKey: key}
		encoded, err = certlib.EncodeDER(item)
		if err != nil {
			return nil, &OperationError{Op: "generate-key", Message: "DER encoding failed", Err: err}
		}

	default: // PEM
		if opts.Encrypt {
			encoded, err = encodePEMEncrypted(key, opts.Password)
		} else {
			item := certlib.CertItem{Type: certlib.ContentPrivateKey, PrivateKey: key}
			encoded, err = certlib.EncodePEM([]certlib.CertItem{item})
		}
		if err != nil {
			return nil, &OperationError{Op: "generate-key", Message: "PEM encoding failed", Err: err}
		}
	}

	result := &GenerateKeyResult{
		KeyBytes: encoded,
		KeyType:  formatKeyType(key),
	}

	if opts.OutputPath != "" {
		if err := certlib.WriteToFile(opts.OutputPath, encoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "generate-key", Message: "write failed", Err: err}
		}
		result.OutputPath = opts.OutputPath
		result.Written = true
	}

	return result, nil
}

func encodePEMEncrypted(key crypto.PrivateKey, password []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}

	encDer, err := certlib.EncryptPKCS8(der, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt PKCS#8: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encDer,
	}), nil
}

func formatKeyType(key crypto.PrivateKey) string {
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
