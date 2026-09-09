package certlib

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/smallstep/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

var ErrUnknownFormat = errors.New("unknown or unsupported file format")
var ErrPasswordRequired = errors.New("password required but not provided")
var ErrInvalidPassword = errors.New("invalid password")
var ErrFileExists = errors.New("file already exists")

func rawPasswords(tagged []TaggedPassword) [][]byte {
	raw := make([][]byte, len(tagged))
	for i, t := range tagged {
		raw[i] = t.Password
	}
	return raw
}

// passwordsWithEmpty appends an empty password ("") to the list if not already present.
// This ensures files with no password or empty password can be opened as a fallback,
// without requiring the user to explicitly provide an empty password.
func passwordsWithEmpty(passwords [][]byte) [][]byte {
	for _, p := range passwords {
		if len(p) == 0 {
			return passwords
		}
	}
	return append(passwords, []byte(""))
}

func findSources(tagged []TaggedPassword, pw []byte) []PasswordSource {
	var sources []PasswordSource
	seen := make(map[PasswordSource]bool)
	for _, t := range tagged {
		if bytes.Equal(t.Password, pw) && !seen[t.Source] {
			sources = append(sources, t.Source)
			seen[t.Source] = true
		}
	}
	return sources
}

// ReadFile reads a file the caller named explicitly.
//
// The extension is treated as a hint rather than a guarantee: ".crt" and ".cer"
// routinely carry DER as well as PEM, so when the extension-implied parse fails
// the format is re-detected from the content. Directory scanning deliberately
// does NOT do this -- there the extension is the filter that stops a scan from
// parsing every file in a tree, which is what --file-signature-scan opts into.
func ReadFile(path string, passwords []TaggedPassword) (*CertContainer, error) {
	return readNamedFile(path, passwords, nil)
}

func readNamedFile(path string, passwords []TaggedPassword, progress *ScanProgress) (*CertContainer, error) {
	container, err := readFileCore(path, passwords, progress)
	if err == nil {
		return container, nil
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, err
	}
	// Only a fallback that actually yields items wins, so a locked keystore or
	// a wrong password still reports its own error rather than being masked by
	// a speculative reparse.
	if c, sigErr := readFileBySignatureCore(path, data, passwords, progress); sigErr == nil && len(c.Items) > 0 {
		return c, nil
	}
	if isJCEKS(data) {
		return nil, ErrJCEKSUnsupported
	}
	return nil, err
}

// ErrJCEKSUnsupported names the one keystore format certdiag recognises but
// does not read (M31 decision D4): the fix is a keytool conversion, and the
// message must say so instead of "unknown format".
var ErrJCEKSUnsupported = errors.New("JCEKS keystores are not supported; convert with: keytool -importkeystore -srcstoretype JCEKS -deststoretype JKS")

// isJCEKS checks the JCEKS magic (0xCECECECE; JKS is 0xFEEDFEED).
func isJCEKS(data []byte) bool {
	return len(data) >= 4 && data[0] == 0xCE && data[1] == 0xCE && data[2] == 0xCE && data[3] == 0xCE
}

// utf8BOM is what Windows editors prepend to a text file; a PEM that starts
// with it is still a PEM.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func readFileCore(path string, passwords []TaggedPassword, progress *ScanProgress) (*CertContainer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, utf8BOM)

	raw := rawPasswords(passwords)
	ext := filepath.Ext(path)

	var container *CertContainer
	format, ok := FormatFromExtension(ext)
	if !ok {
		if isPEM(data) {
			container, err = readPEM(path, data, raw, progress)
		} else {
			// Not an early return: ".csr" is a certificate extension with no
			// entry in FormatFromExtension, so it must still reach the
			// content-detection fallback below.
			err = ErrUnknownFormat
		}
	} else {
		switch format {
		case FormatPEM:
			container, err = readPEM(path, data, raw, progress)
		case FormatDER:
			container, err = readDER(path, data)
		case FormatPKCS12:
			container, err = readPKCS12(path, data, raw, progress)
		case FormatJKS:
			container, err = readJKS(path, data, raw, progress)
		case FormatPKCS7:
			container, err = readPKCS7(path, data)
		}
	}

	// For a file that already carries a certificate extension, that extension
	// is only a hint about which parser to try first: ".crt" and ".cer"
	// routinely hold DER rather than PEM, and a DER CSR named ".csr" is just as
	// common. Re-detect from the content rather than rejecting a file we can
	// read perfectly well.
	//
	// Extensions outside that set stay strict. The recursive directory walk has
	// no filter of its own and relies on this reader refusing unrelated files;
	// sniffing everything would silently make --file-signature-scan a no-op and
	// parse every file in a scanned tree.
	if err != nil && certExtensions[strings.ToLower(ext)] {
		if c, sigErr := readFileBySignatureCore(path, data, passwords, progress); sigErr == nil && len(c.Items) > 0 {
			return c, nil
		}
	}

	if err != nil {
		return nil, err
	}
	container.UnlockSources = findSources(passwords, container.Password)
	return container, nil
}

func isPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil
}

func readPEM(path string, data []byte, passwords [][]byte, progress *ScanProgress) (*CertContainer, error) {
	container := &CertContainer{
		FilePath: path,
		Format:   FormatPEM,
		RawData:  data,
		Items:    make([]CertItem, 0),
	}

	remaining := data
	var ignored []string
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		item := CertItem{RawBytes: block.Bytes}

		switch block.Type {
		default:
			// A CRL, a trusted-certificate wrapper or an OpenSSH key is not
			// silently nothing: it is named when the file yields no item.
			ignored = append(ignored, block.Type)
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				item.Type = ContentCertificate
				item.Certificate = cert
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}

		case "PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
				decryptLegacyPEMKey(container, item, block, passwordsWithEmpty(passwords), progress,
					func(der []byte) (crypto.PrivateKey, error) { return x509.ParsePKCS8PrivateKey(der) })
				break
			}
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				item.Type = ContentPrivateKey
				item.PrivateKey = key
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}

		case "RSA PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
				decryptLegacyPEMKey(container, item, block, passwordsWithEmpty(passwords), progress,
					func(der []byte) (crypto.PrivateKey, error) { return x509.ParsePKCS1PrivateKey(der) })
				break
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				item.Type = ContentPrivateKey
				item.PrivateKey = key
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}

		case "EC PRIVATE KEY":
			if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
				decryptLegacyPEMKey(container, item, block, passwordsWithEmpty(passwords), progress,
					func(der []byte) (crypto.PrivateKey, error) { return x509.ParseECPrivateKey(der) })
				break
			}
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err == nil {
				item.Type = ContentPrivateKey
				item.PrivateKey = key
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}

		case "ENCRYPTED PRIVATE KEY":
			item.Type = ContentPrivateKey
			item.Encrypted = true
			decrypted := false
			for _, pass := range passwordsWithEmpty(passwords) {
				if progress != nil {
					progress.PasswordChecks.Add(1)
				}
				plain, err := DecryptPKCS8(block.Bytes, pass)
				if err == nil {
					if parsed, parseErr := x509.ParsePKCS8PrivateKey(plain); parseErr == nil {
						item.RawBytes = plain
						item.PrivateKey = parsed
						container.Password = pass
						decrypted = true
						break
					}
				}
			}
			if !decrypted {
				for _, pass := range passwordsWithEmpty(passwords) {
					if progress != nil {
						progress.PasswordChecks.Add(1)
					}
					key, err := x509.DecryptPEMBlock(block, pass) //nolint:staticcheck
					if err == nil {
						if parsed, parseErr := x509.ParsePKCS8PrivateKey(key); parseErr == nil {
							item.RawBytes = key
							item.PrivateKey = parsed
							container.Password = pass
							decrypted = true
							break
						}
					}
				}
			}
			if !decrypted {
				container.ParseErrors = append(container.ParseErrors, "failed to decrypt private key (wrong password or unsupported encryption)")
			}
			container.Items = append(container.Items, item)

		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err == nil {
				item.Type = ContentCSR
				item.CSR = csr
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}

		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				item.Type = ContentPublicKey
				item.PublicKey = key
				container.Items = append(container.Items, item)
			} else {
				container.ParseErrors = append(container.ParseErrors, err.Error())
			}
		}

		remaining = rest
	}

	if len(container.Items) == 0 && len(container.ParseErrors) == 0 {
		if len(ignored) > 0 {
			return nil, fmt.Errorf("no certificates, keys or requests (PEM holds only: %s)", strings.Join(uniqueStrings(ignored), ", "))
		}
		return nil, ErrUnknownFormat
	}

	return container, nil
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func decryptLegacyPEMKey(container *CertContainer, item CertItem, block *pem.Block, passwords [][]byte, progress *ScanProgress, parse func([]byte) (crypto.PrivateKey, error)) {
	item.Type = ContentPrivateKey
	item.Encrypted = true
	for _, pass := range passwords {
		if progress != nil {
			progress.PasswordChecks.Add(1)
		}
		der, err := x509.DecryptPEMBlock(block, pass) //nolint:staticcheck
		if err != nil {
			continue
		}
		if key, parseErr := parse(der); parseErr == nil {
			item.RawBytes = der
			item.PrivateKey = key
			container.Password = pass
			container.Items = append(container.Items, item)
			return
		}
	}
	container.ParseErrors = append(container.ParseErrors, "failed to decrypt private key (wrong password or unsupported encryption)")
	container.Items = append(container.Items, item)
}

func readDER(path string, data []byte) (*CertContainer, error) {
	container := &CertContainer{
		FilePath: path,
		Format:   FormatDER,
		RawData:  data,
		Items:    make([]CertItem, 0),
	}

	if cert, err := x509.ParseCertificate(data); err == nil {
		container.Items = append(container.Items, CertItem{
			Type:        ContentCertificate,
			RawBytes:    data,
			Certificate: cert,
		})
		return container, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		container.Items = append(container.Items, CertItem{
			Type:       ContentPrivateKey,
			RawBytes:   data,
			PrivateKey: key,
		})
		return container, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		container.Items = append(container.Items, CertItem{
			Type:       ContentPrivateKey,
			RawBytes:   data,
			PrivateKey: key,
		})
		return container, nil
	}

	if key, err := x509.ParseECPrivateKey(data); err == nil {
		container.Items = append(container.Items, CertItem{
			Type:       ContentPrivateKey,
			RawBytes:   data,
			PrivateKey: key,
		})
		return container, nil
	}

	if csr, err := x509.ParseCertificateRequest(data); err == nil {
		container.Items = append(container.Items, CertItem{
			Type:     ContentCSR,
			RawBytes: data,
			CSR:      csr,
		})
		return container, nil
	}

	return nil, ErrUnknownFormat
}

func readPKCS12(path string, data []byte, passwords [][]byte, progress *ScanProgress) (*CertContainer, error) {
	container := &CertContainer{
		FilePath: path,
		Format:   FormatPKCS12,
		RawData:  data,
		Items:    make([]CertItem, 0),
	}

	tryPassword := func(pass []byte) bool {
		pw := string(pass)

		// Try DecodeChain first (single key + cert bundle, most common)
		privKey, leafCert, caCerts, err := pkcs12.DecodeChain(data, pw)
		if err == nil {
			container.Password = pass
			if leafCert != nil {
				container.Items = append(container.Items, CertItem{
					Type:        ContentCertificate,
					Certificate: leafCert,
					RawBytes:    leafCert.Raw,
				})
			}
			for _, ca := range caCerts {
				container.Items = append(container.Items, CertItem{
					Type:        ContentCertificate,
					Certificate: ca,
					RawBytes:    ca.Raw,
				})
			}
			if privKey != nil {
				container.Items = append(container.Items, CertItem{
					Type:       ContentPrivateKey,
					PrivateKey: privKey,
				})
			}
			applyPKCS12FriendlyNames(container, data, pw)
			return true
		}

		// Multi-key path: ToPEM extracts all safe bags without single-key constraint
		pemBlocks, pemErr := pkcs12.ToPEM(data, pw)
		if pemErr == nil && len(pemBlocks) > 0 {
			for _, block := range pemBlocks {
				item := parsePKCS12PEMBlock(block)
				if item != nil {
					item.Alias = block.Headers[pkcs12FriendlyNameHeader]
					container.Items = append(container.Items, *item)
				}
			}
			if len(container.Items) > 0 {
				container.Password = pass
				return true
			}
		}

		// Fall back to DecodeTrustStore (cert-only P12)
		certs, err := pkcs12.DecodeTrustStore(data, pw)
		if err == nil {
			container.Password = pass
			for _, cert := range certs {
				container.Items = append(container.Items, CertItem{
					Type:        ContentCertificate,
					Certificate: cert,
					RawBytes:    cert.Raw,
				})
			}
			return true
		}

		return false
	}

	for _, pass := range passwordsWithEmpty(passwords) {
		if progress != nil {
			progress.PasswordChecks.Add(1)
		}
		if tryPassword(pass) {
			return container, nil
		}
	}

	container.ParseErrors = append(container.ParseErrors, "password required to read contents")
	return container, nil
}

const pkcs12WrongPasswordProbe = "\x00certdiag-locked-probe\x00"

func isEncryptedPKCS12(data []byte) bool {
	_, _, _, err := pkcs12.DecodeChain(data, pkcs12WrongPasswordProbe)
	return errors.Is(err, pkcs12.ErrIncorrectPassword)
}

func readJKS(path string, data []byte, passwords [][]byte, progress *ScanProgress) (*CertContainer, error) {
	return readKeyStore(path, data, passwords, FormatJKS, progress)
}

func readKeyStore(path string, data []byte, passwords [][]byte, format FileFormat, progress *ScanProgress) (*CertContainer, error) {
	container := &CertContainer{
		FilePath: path,
		Format:   format,
		RawData:  data,
		Items:    make([]CertItem, 0),
	}

	allPasswords := passwordsWithEmpty(passwords)

	for _, pass := range allPasswords {
		if progress != nil {
			progress.PasswordChecks.Add(1)
		}
		ks := keystore.New()
		err := ks.Load(bytes.NewReader(data), pass)
		if err != nil {
			continue
		}

		container.Password = pass
		for _, alias := range ks.Aliases() {
			if ks.IsPrivateKeyEntry(alias) {
				readKeyStorePrivateEntry(container, &ks, alias, allPasswords, progress)
			} else if ks.IsTrustedCertificateEntry(alias) {
				entry, err := ks.GetTrustedCertificateEntry(alias)
				if err == nil {
					cert, certErr := x509.ParseCertificate(entry.Certificate.Content)
					if cert != nil {
						container.Items = append(container.Items, CertItem{
							Type:        ContentCertificate,
							Alias:       alias,
							Certificate: cert,
							RawBytes:    entry.Certificate.Content,
						})
					} else {
						container.Items = append(container.Items, CertItem{
							Type:  ContentCertificate,
							Alias: alias,
						})
						container.ParseErrors = append(container.ParseErrors,
							fmt.Sprintf("malformed certificate in entry %q: %v", alias, certErr))
					}
				}
			}
		}
		return container, nil
	}

	container.ParseErrors = append(container.ParseErrors, "password required to read contents")
	return container, nil
}

func readKeyStorePrivateEntry(container *CertContainer, ks *keystore.KeyStore, alias string, passwords [][]byte, progress *ScanProgress) {
	// Try store password first, then all other candidates
	tryOrder := make([][]byte, 0, len(passwords))
	tryOrder = append(tryOrder, container.Password)
	for _, p := range passwords {
		if !bytes.Equal(p, container.Password) {
			tryOrder = append(tryOrder, p)
		}
	}

	for _, pass := range tryOrder {
		if progress != nil {
			progress.PasswordChecks.Add(1)
		}
		entry, err := ks.GetPrivateKeyEntry(alias, pass)
		if err != nil {
			continue
		}

		item := CertItem{
			Type:          ContentPrivateKey,
			Alias:         alias,
			EntryPassword: pass,
		}
		if len(entry.PrivateKey) > 0 {
			pk, pkErr := x509.ParsePKCS8PrivateKey(entry.PrivateKey)
			if pkErr != nil {
				container.ParseErrors = append(container.ParseErrors,
					fmt.Sprintf("entry %q: private key is not PKCS#8: %v", alias, pkErr))
			} else {
				item.PrivateKey = pk
			}
		}
		// Carry the issuer chain (everything after the leaf) on the key item so
		// intermediates are not lost on read; they are re-emitted on write and
		// in JKS->PEM/P12 conversions.
		if len(entry.CertificateChain) > 1 {
			for _, cc := range entry.CertificateChain[1:] {
				der := make([]byte, len(cc.Content))
				copy(der, cc.Content)
				item.Chain = append(item.Chain, der)
			}
		}
		if len(entry.CertificateChain) > 0 {
			cert, certErr := x509.ParseCertificate(entry.CertificateChain[0].Content)
			if cert != nil {
				container.Items = append(container.Items, CertItem{
					Type:        ContentCertificate,
					Alias:       alias,
					Certificate: cert,
					RawBytes:    entry.CertificateChain[0].Content,
				})
			} else {
				container.Items = append(container.Items, CertItem{
					Type:  ContentCertificate,
					Alias: alias,
				})
				container.ParseErrors = append(container.ParseErrors,
					fmt.Sprintf("malformed certificate in entry %q: %v", alias, certErr))
			}
		}
		container.Items = append(container.Items, item)
		return
	}

	// No password worked -- add placeholder cert + locked key to preserve entry structure
	container.Items = append(container.Items, CertItem{
		Type:  ContentCertificate,
		Alias: alias,
	})
	container.Items = append(container.Items, CertItem{
		Type:      ContentPrivateKey,
		Alias:     alias,
		Encrypted: true,
	})
}

func readPKCS7(path string, data []byte) (*CertContainer, error) {
	container := &CertContainer{
		FilePath: path,
		Format:   FormatPKCS7,
		RawData:  data,
		Items:    make([]CertItem, 0),
	}

	parseData := data
	if block, _ := pem.Decode(data); block != nil {
		parseData = block.Bytes
	}

	p7, err := pkcs7.Parse(parseData)
	if err != nil {
		return nil, err
	}

	for _, cert := range p7.Certificates {
		container.Items = append(container.Items, CertItem{
			Type:        ContentCertificate,
			Certificate: cert,
			RawBytes:    cert.Raw,
		})
	}

	if len(container.Items) == 0 {
		return nil, ErrUnknownFormat
	}

	return container, nil
}

// parsePKCS12PEMBlock converts a pem.Block from pkcs12.ToPEM() into a CertItem.
// ToPEM labels all private keys as "PRIVATE KEY" but encodes RSA keys as PKCS#1
// and EC keys as SEC1, so we must try all three key formats.
// pkcs12FriendlyNameHeader is the PEM header go-pkcs12 uses for the
// friendlyName attribute of a safe bag.
const pkcs12FriendlyNameHeader = "friendlyName"

// applyPKCS12FriendlyNames names the items after the archive's friendlyName
// attributes, so `extract --alias` works on PKCS#12 the way it does on JKS
// (M31 WP12). DecodeChain drops the attributes; a second pass through ToPEM
// recovers them.
func applyPKCS12FriendlyNames(container *CertContainer, data []byte, pw string) {
	blocks, err := pkcs12.ToPEM(data, pw)
	if err != nil {
		return
	}
	certNames := map[string]string{}
	keyName := ""
	for _, b := range blocks {
		name := b.Headers[pkcs12FriendlyNameHeader]
		if name == "" {
			continue
		}
		switch b.Type {
		case "CERTIFICATE":
			certNames[string(b.Bytes)] = name
		case "PRIVATE KEY":
			if keyName == "" {
				keyName = name
			}
		}
	}
	for i := range container.Items {
		it := &container.Items[i]
		switch it.Type {
		case ContentCertificate:
			if it.Certificate != nil {
				it.Alias = certNames[string(it.Certificate.Raw)]
			}
		case ContentPrivateKey:
			it.Alias = keyName
		}
	}
}

func parsePKCS12PEMBlock(block *pem.Block) *CertItem {
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return &CertItem{
			Type:        ContentCertificate,
			Certificate: cert,
			RawBytes:    block.Bytes,
		}
	case "PRIVATE KEY":
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return &CertItem{Type: ContentPrivateKey, PrivateKey: key, RawBytes: block.Bytes}
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return &CertItem{Type: ContentPrivateKey, PrivateKey: key, RawBytes: block.Bytes}
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return &CertItem{Type: ContentPrivateKey, PrivateKey: key, RawBytes: block.Bytes}
		}
		return nil
	}
	return nil
}
