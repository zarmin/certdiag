package certlib

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/smallstep/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// WritePEM writes items as PEM blocks to w.
// expandKeyChains inserts the issuer certs carried on a private key's Chain
// field (populated when reading a JKS PrivateKeyEntry) as standalone certificate
// items, so writers/converters emit the full chain instead of just the leaf.
// Certs already present in items (by raw DER) are not duplicated. Inserted items
// get no alias so JKS writing auto-generates non-colliding aliases.
// ExpandKeyChains is the exported form of expandKeyChains, for callers that must
// materialize a key's carried issuer chain into standalone certificate items
// before format-specific filtering (e.g. the conversion matrix, which drops key
// items for cert-only formats before the writers run).
func ExpandKeyChains(items []CertItem) []CertItem {
	return expandKeyChains(items)
}

func expandKeyChains(items []CertItem) []CertItem {
	seen := make(map[string]bool)
	for _, it := range items {
		if it.Type == ContentCertificate && it.Certificate != nil {
			seen[string(it.Certificate.Raw)] = true
		}
	}
	var out []CertItem
	for _, it := range items {
		out = append(out, it)
		if it.Type != ContentPrivateKey || len(it.Chain) == 0 {
			continue
		}
		for _, der := range it.Chain {
			if seen[string(der)] {
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil || cert == nil {
				continue
			}
			seen[string(der)] = true
			out = append(out, CertItem{Type: ContentCertificate, Certificate: cert, RawBytes: der})
		}
	}
	return out
}

func WritePEM(w io.Writer, items []CertItem) error {
	items = expandKeyChains(items)
	for _, item := range items {
		switch item.Type {
		case ContentCertificate:
			if item.Certificate == nil {
				return fmt.Errorf("certificate item has nil certificate")
			}
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: item.Certificate.Raw,
			}
			if err := pem.Encode(w, block); err != nil {
				return fmt.Errorf("encode PEM certificate: %w", err)
			}

		case ContentPrivateKey:
			if item.PrivateKey == nil {
				return fmt.Errorf("private key item has nil key")
			}
			der, err := x509.MarshalPKCS8PrivateKey(item.PrivateKey)
			if err != nil {
				return fmt.Errorf("marshal private key: %w", err)
			}
			block := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			}
			if err := pem.Encode(w, block); err != nil {
				return fmt.Errorf("encode PEM private key: %w", err)
			}

		case ContentPublicKey:
			if item.PublicKey == nil {
				return fmt.Errorf("public key item has nil key")
			}
			der, err := x509.MarshalPKIXPublicKey(item.PublicKey)
			if err != nil {
				return fmt.Errorf("marshal public key: %w", err)
			}
			block := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: der,
			}
			if err := pem.Encode(w, block); err != nil {
				return fmt.Errorf("encode PEM public key: %w", err)
			}

		case ContentCSR:
			if item.CSR == nil {
				return fmt.Errorf("CSR item has nil CSR")
			}
			block := &pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: item.CSR.Raw,
			}
			if err := pem.Encode(w, block); err != nil {
				return fmt.Errorf("encode PEM CSR: %w", err)
			}

		default:
			return fmt.Errorf("unsupported content type for PEM encoding: %s", item.Type)
		}
	}
	return nil
}

// WriteDER writes a single item as DER bytes to w.
func WriteDER(w io.Writer, item CertItem) error {
	switch item.Type {
	case ContentCertificate:
		if item.Certificate == nil {
			return fmt.Errorf("certificate item has nil certificate")
		}
		_, err := w.Write(item.Certificate.Raw)
		return err

	case ContentPrivateKey:
		if item.PrivateKey == nil {
			return fmt.Errorf("private key item has nil key")
		}
		der, err := x509.MarshalPKCS8PrivateKey(item.PrivateKey)
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}
		_, err = w.Write(der)
		return err

	case ContentPublicKey:
		if item.PublicKey == nil {
			return fmt.Errorf("public key item has nil key")
		}
		der, err := x509.MarshalPKIXPublicKey(item.PublicKey)
		if err != nil {
			return fmt.Errorf("marshal public key: %w", err)
		}
		_, err = w.Write(der)
		return err

	case ContentCSR:
		if item.CSR == nil {
			return fmt.Errorf("CSR item has nil CSR")
		}
		_, err := w.Write(item.CSR.Raw)
		return err

	default:
		return fmt.Errorf("unsupported content type for DER encoding: %s", item.Type)
	}
}

// WritePKCS12 writes items as a PKCS#12 archive to w.
// If items contain a private key, it creates a key+cert bundle.
// If items contain only certificates, it creates a trust store.
func WritePKCS12(w io.Writer, items []CertItem, password []byte, legacy bool) error {
	items = expandKeyChains(items)
	var privKey crypto.PrivateKey
	var leafCert *x509.Certificate
	var caCerts []*x509.Certificate
	var allCerts []*x509.Certificate

	for _, item := range items {
		switch item.Type {
		case ContentPrivateKey:
			if privKey != nil {
				return fmt.Errorf("PKCS#12 supports only one private key")
			}
			privKey = item.PrivateKey
		case ContentCertificate:
			allCerts = append(allCerts, item.Certificate)
		}
	}

	if privKey != nil {
		if len(allCerts) == 0 {
			return fmt.Errorf("PKCS#12 with private key requires at least one certificate")
		}
		// Pair the key with the certificate whose public key actually matches it,
		// not blindly allCerts[0]. After expandKeyChains (and bundle's keys-first
		// ordering) a JKS-sourced key can be followed by its issuer certs, so the
		// first cert may be an intermediate; using it as the leaf would produce a
		// key/cert-mismatched archive. Fall back to allCerts[0] when nothing
		// matches (e.g. the real leaf is absent) to preserve prior behavior.
		leafIdx := 0
		for i, c := range allCerts {
			if KeyMatchesCert(privKey, c) {
				leafIdx = i
				break
			}
		}
		leafCert = allCerts[leafIdx]
		for i, c := range allCerts {
			if i != leafIdx {
				caCerts = append(caCerts, c)
			}
		}

		var encoder *gopkcs12.Encoder
		if password == nil {
			encoder = gopkcs12.Passwordless
		} else if legacy {
			encoder = gopkcs12.Legacy
		} else {
			encoder = gopkcs12.Modern2023
		}
		data, err := encoder.Encode(privKey, leafCert, caCerts, string(password))
		if err != nil {
			return fmt.Errorf("encode PKCS#12: %w", err)
		}
		_, err = w.Write(data)
		return err
	}

	// Certificates only: create trust store
	if len(allCerts) == 0 {
		return fmt.Errorf("no certificates or keys to encode as PKCS#12")
	}

	var encoder *gopkcs12.Encoder
	if password == nil {
		encoder = gopkcs12.Passwordless
	} else if legacy {
		encoder = gopkcs12.Legacy
	} else {
		encoder = gopkcs12.Modern2023
	}
	data, err := encoder.EncodeTrustStore(allCerts, string(password))
	if err != nil {
		return fmt.Errorf("encode PKCS#12 trust store: %w", err)
	}
	_, err = w.Write(data)
	return err
}

// WritePKCS7 writes certificates as a degenerate PKCS#7 SignedData structure to w.
// Private keys are ignored (PKCS#7 degenerate only holds certificates).
func WritePKCS7(w io.Writer, items []CertItem) error {
	// Expand any issuer certs carried on a JKS-sourced key's Chain field into
	// standalone cert items, matching WritePEM/WritePKCS12/WriteJKS, so a
	// JKS->PKCS#7 conversion preserves intermediates instead of emitting only
	// the leaf entry's certificate.
	items = expandKeyChains(items)
	var certs []*x509.Certificate
	for _, item := range items {
		if item.Type == ContentCertificate && item.Certificate != nil {
			certs = append(certs, item.Certificate)
		}
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificates to encode as PKCS#7")
	}

	if len(certs) == 1 {
		data, err := pkcs7.DegenerateCertificate(certs[0].Raw)
		if err != nil {
			return fmt.Errorf("encode PKCS#7: %w", err)
		}
		_, err = w.Write(data)
		return err
	}

	// Multiple certs: use SignedData with no signers
	sd, err := pkcs7.NewSignedData(nil)
	if err != nil {
		return fmt.Errorf("create PKCS#7 signed data: %w", err)
	}
	for _, cert := range certs {
		sd.AddCertificate(cert)
	}
	data, err := sd.Finish()
	if err != nil {
		return fmt.Errorf("finish PKCS#7: %w", err)
	}
	_, err = w.Write(data)
	return err
}

// NonASCIIJKSPasswordWarning is emitted when a JKS is written or read with a
// password containing non-ASCII bytes. certdiag passes such passwords to
// keystore-go as raw UTF-8, which encodes differently from Java keytool's
// UTF-16BE, so the store still works within certdiag but will not interoperate
// with keytool.
const NonASCIIJKSPasswordWarning = "JKS password contains non-ASCII characters; it may not interoperate with Java keytool (which uses UTF-16BE). Use an ASCII password for keytool compatibility."

func passwordHasNonASCII(password []byte) bool {
	for _, b := range password {
		if b > 0x7F {
			return true
		}
	}
	return false
}

// JKSPasswordWarning returns NonASCIIJKSPasswordWarning if password contains
// non-ASCII bytes, or "" for an ASCII (keytool-compatible) password.
func JKSPasswordWarning(password []byte) string {
	if passwordHasNonASCII(password) {
		return NonASCIIJKSPasswordWarning
	}
	return ""
}

// WriteJKS writes items as a JKS (Java KeyStore) to w.
// aliases maps item index to alias name; missing entries get auto-generated aliases.
func WriteJKS(w io.Writer, items []CertItem, password []byte, aliases map[int]string) error {
	ks := keystore.New()
	entryNum := 0

	// Build key-to-cert chain mapping: for each private key, find its matching
	// leaf cert (by public key) and build the issuer chain from that leaf.
	// Certs that are part of a key's chain are NOT added as separate TrustedCertificateEntries.
	chainCertIdxs := make(map[int]bool)   // cert indices consumed by key chains
	keyLeafCertIdxs := make(map[int]bool) // cert indices that are a key's own leaf
	type keyChainInfo struct {
		chain   []keystore.Certificate
		certIdx int // index of the matching leaf cert (-1 if none)
	}
	keyChains := make(map[int]*keyChainInfo) // key item index -> chain info

	for i, item := range items {
		if item.Type != ContentPrivateKey || item.PrivateKey == nil {
			continue
		}
		info := &keyChainInfo{certIdx: -1}
		keyChains[i] = info

		pk, ok := item.PrivateKey.(crypto.Signer)
		if !ok {
			continue
		}
		keyPub, err := x509.MarshalPKIXPublicKey(pk.Public())
		if err != nil {
			continue
		}

		// Find the leaf cert matching this key
		leafIdx := -1
		for j, other := range items {
			if other.Type != ContentCertificate || other.Certificate == nil {
				continue
			}
			certPub, err := x509.MarshalPKIXPublicKey(other.Certificate.PublicKey)
			if err != nil {
				continue
			}
			if bytes.Equal(keyPub, certPub) {
				leafIdx = j
				break
			}
		}
		if leafIdx < 0 {
			continue
		}
		info.certIdx = leafIdx
		keyLeafCertIdxs[leafIdx] = true

		// Build the issuer chain starting from the leaf
		chain := []keystore.Certificate{{
			Type:    "X.509",
			Content: items[leafIdx].Certificate.Raw,
		}}
		chainCertIdxs[leafIdx] = true

		// Walk up the issuer chain
		current := items[leafIdx].Certificate
		for {
			found := false
			for j, other := range items {
				if chainCertIdxs[j] || other.Type != ContentCertificate || other.Certificate == nil {
					continue
				}
				if current.Issuer.String() == other.Certificate.Subject.String() {
					if err := current.CheckSignatureFrom(other.Certificate); err == nil {
						chain = append(chain, keystore.Certificate{
							Type:    "X.509",
							Content: other.Certificate.Raw,
						})
						chainCertIdxs[j] = true
						current = other.Certificate
						found = true
						break
					}
				}
			}
			if !found {
				break
			}
		}
		// Append any issuer certs carried on the key's Chain field (from a JKS
		// read) that the issuer-walk didn't already include, so intermediates are
		// preserved on re-encode instead of being truncated to the leaf.
		inChain := make(map[string]bool, len(chain))
		for _, c := range chain {
			inChain[string(c.Content)] = true
		}
		for _, der := range item.Chain {
			if inChain[string(der)] {
				continue
			}
			inChain[string(der)] = true
			chain = append(chain, keystore.Certificate{Type: "X.509", Content: der})
		}
		info.chain = chain
	}

	// Now emit entries
	for i, item := range items {
		alias := aliases[i]
		if alias == "" && item.Alias != "" {
			alias = item.Alias
		}
		if alias == "" {
			entryNum++
			alias = fmt.Sprintf("entry-%d", entryNum)
		}

		switch item.Type {
		case ContentPrivateKey:
			if item.PrivateKey == nil {
				continue
			}
			pkcs8, err := x509.MarshalPKCS8PrivateKey(item.PrivateKey)
			if err != nil {
				return fmt.Errorf("marshal private key for JKS: %w", err)
			}

			info := keyChains[i]
			var chain []keystore.Certificate
			if info != nil {
				chain = info.chain
			}

			// Use the matching cert's alias for the PrivateKeyEntry
			keyAlias := alias
			if info != nil && info.certIdx >= 0 {
				if ca := aliases[info.certIdx]; ca != "" {
					keyAlias = ca
				} else if items[info.certIdx].Alias != "" {
					keyAlias = items[info.certIdx].Alias
				}
			}

			entryPass := password
			if item.EntryPassword != nil {
				entryPass = item.EntryPassword
			}
			err = ks.SetPrivateKeyEntry(keyAlias, keystore.PrivateKeyEntry{
				PrivateKey:       pkcs8,
				CertificateChain: chain,
			}, entryPass)
			if err != nil {
				return fmt.Errorf("set JKS private key entry %q: %w", keyAlias, err)
			}

		case ContentCertificate:
			if item.Certificate == nil {
				continue
			}
			// Skip the leaf cert (directly matched to a key) — it's already in the PrivateKeyEntry.
			// A key's own leaf cert shares the key's alias, so emitting it as a trusted entry
			// would overwrite the PrivateKeyEntry and drop the key (even when self-signed).
			// Self-signed issuer certs (roots) in the chain still get their own TrustedCertificateEntry.
			if chainCertIdxs[i] && (keyLeafCertIdxs[i] || item.Certificate.Subject.String() != item.Certificate.Issuer.String()) {
				continue
			}
			err := ks.SetTrustedCertificateEntry(alias, keystore.TrustedCertificateEntry{
				Certificate: keystore.Certificate{
					Type:    "X.509",
					Content: item.Certificate.Raw,
				},
			})
			if err != nil {
				return fmt.Errorf("set JKS trusted cert entry %q: %w", alias, err)
			}
		}
	}

	return ks.Store(w, password)
}

// --- Convenience wrappers ([]byte return) ---

func EncodePEM(items []CertItem) ([]byte, error) {
	var buf bytes.Buffer
	if err := WritePEM(&buf, items); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func EncodeDER(item CertItem) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteDER(&buf, item); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func EncodePKCS12(items []CertItem, password []byte, legacy bool) ([]byte, error) {
	var buf bytes.Buffer
	if err := WritePKCS12(&buf, items, password, legacy); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func EncodePKCS7(items []CertItem) ([]byte, error) {
	var buf bytes.Buffer
	if err := WritePKCS7(&buf, items); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func EncodeJKS(items []CertItem, password []byte, aliases map[int]string) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteJKS(&buf, items, password, aliases); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteToFile writes data to a file atomically.
func WriteToFile(path string, data []byte, overwrite bool) error {
	var existingMode os.FileMode
	haveExistingMode := false
	if info, err := os.Stat(path); err == nil {
		if !overwrite {
			return fmt.Errorf("%w: %s (use --no-confirm to replace)", ErrFileExists, path)
		}
		if info.Mode().Perm()&0200 == 0 {
			return fmt.Errorf("file is read-only: %s", path)
		}
		existingMode = info.Mode().Perm()
		haveExistingMode = true
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".certdiag-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if haveExistingMode {
		if err := os.Chmod(tmpPath, existingMode); err != nil {
			return fmt.Errorf("chmod temp file: %w", err)
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}
