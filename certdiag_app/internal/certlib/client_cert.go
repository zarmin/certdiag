package certlib

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

type ClientCertOptions struct {
	CertPath string
	KeyPath  string
	P12Path  string
	JKSPath  string
	Alias    string
	Password []byte
}

func LoadClientCert(opts ClientCertOptions) (tls.Certificate, error) {
	switch {
	case opts.P12Path != "":
		return loadClientCertP12(opts.P12Path, opts.Alias, opts.Password)
	case opts.JKSPath != "":
		return loadClientCertJKS(opts.JKSPath, opts.Alias, opts.Password)
	case opts.CertPath != "" && opts.KeyPath != "":
		return loadClientCertPEM(opts.CertPath, opts.KeyPath, opts.Password)
	case opts.CertPath != "" && opts.KeyPath == "":
		return tls.Certificate{}, fmt.Errorf("--client-cert requires --client-key")
	case opts.CertPath == "" && opts.KeyPath != "":
		return tls.Certificate{}, fmt.Errorf("--client-key requires --client-cert")
	default:
		return tls.Certificate{}, fmt.Errorf("no client certificate source specified")
	}
}

func loadClientCertPEM(certPath, keyPath string, password []byte) (tls.Certificate, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("client certificate not found: %s", certPath)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("client key not found: %s", keyPath)
	}

	// Try loading directly first (works for unencrypted keys)
	cert, err := tls.X509KeyPair(certData, keyData)
	if err == nil {
		return cert, nil
	}

	// If key might be encrypted, try decrypting via certlib PEM reader
	if len(password) > 0 {
		decryptedKey, decErr := decryptPEMKey(keyData, password)
		if decErr == nil {
			cert, err = tls.X509KeyPair(certData, decryptedKey)
			if err == nil {
				return cert, nil
			}
		}
	}

	return tls.Certificate{}, fmt.Errorf("loading client cert+key: %w", err)
}

func decryptPEMKey(keyData, password []byte) ([]byte, error) {
	// Use the internal PEM reader which handles encrypted PKCS#8 keys
	container, err := readPEM("client-key", keyData, [][]byte{password}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	for _, item := range container.Items {
		if item.Type == ContentPrivateKey && item.PrivateKey != nil {
			// Re-encode as unencrypted PKCS8 PEM
			encoded, encErr := EncodePEM([]CertItem{item})
			if encErr != nil {
				return nil, encErr
			}
			return encoded, nil
		}
	}

	return nil, fmt.Errorf("no private key found after decryption")
}

func loadClientCertP12(p12Path, alias string, password []byte) (tls.Certificate, error) {
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	container, err := ReadFile(p12Path, passwords)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse PKCS#12: %s: %w", p12Path, err)
	}

	return extractClientCert(container, alias, p12Path)
}

func loadClientCertJKS(jksPath, alias string, password []byte) (tls.Certificate, error) {
	passwords := []TaggedPassword{{Password: password, Source: PasswordSourceCLI}}
	container, err := ReadFile(jksPath, passwords)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse JKS: %s: %w", jksPath, err)
	}

	return extractClientCert(container, alias, jksPath)
}

func extractClientCert(container *CertContainer, alias, path string) (tls.Certificate, error) {
	var certItem *CertItem
	var keyItem *CertItem

	for i := range container.Items {
		item := &container.Items[i]
		if alias != "" && item.Alias != alias {
			continue
		}
		if item.Type == ContentPrivateKey && item.PrivateKey != nil && keyItem == nil {
			keyItem = item
		}
		if item.Type == ContentCertificate && item.Certificate != nil && certItem == nil {
			certItem = item
		}
	}

	if keyItem == nil {
		return tls.Certificate{}, fmt.Errorf("no private key found in %s", path)
	}

	if certItem == nil {
		return tls.Certificate{}, fmt.Errorf("no certificate found in %s", path)
	}

	// Verify key matches cert
	if err := verifyKeyMatchesCert(keyItem.PrivateKey, certItem.Certificate); err != nil {
		return tls.Certificate{}, fmt.Errorf("client key does not match client certificate: %w", err)
	}

	// Build the wire chain: leaf first, then intermediates so a server that
	// requires the full client chain can verify. Intermediates live on the key
	// entry's Chain (JKS) or as separate cert items (P12). Skip the leaf itself
	// and any self-signed root -- mTLS sends leaf + intermediates, not the root.
	chain := [][]byte{certItem.Certificate.Raw}
	seen := map[string]bool{string(certItem.Certificate.Raw): true}
	addIntermediate := func(der []byte) {
		if len(der) == 0 || seen[string(der)] {
			return
		}
		if c, err := x509.ParseCertificate(der); err == nil && bytes.Equal(c.RawSubject, c.RawIssuer) {
			return
		}
		seen[string(der)] = true
		chain = append(chain, der)
	}
	for _, der := range keyItem.Chain {
		addIntermediate(der)
	}
	for i := range container.Items {
		item := &container.Items[i]
		if alias != "" && item.Alias != alias {
			continue
		}
		if item.Type == ContentCertificate && item.Certificate != nil {
			addIntermediate(item.Certificate.Raw)
		}
	}

	tlsCert := tls.Certificate{
		PrivateKey:  keyItem.PrivateKey,
		Certificate: chain,
		Leaf:        certItem.Certificate,
	}

	return tlsCert, nil
}

// KeyMatchesCert reports whether the private key's public part matches the
// certificate's public key.
func KeyMatchesCert(key any, cert *x509.Certificate) bool {
	return verifyKeyMatchesCert(key, cert) == nil
}

func verifyKeyMatchesCert(key any, cert *x509.Certificate) error {
	// Extract public key from private key using crypto.Signer interface
	signer, ok := key.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not implement crypto.Signer")
	}

	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshaling private key's public key: %w", err)
	}

	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling certificate's public key: %w", err)
	}

	if !bytes.Equal(keyPub, certPub) {
		return fmt.Errorf("public keys do not match")
	}
	return nil
}
