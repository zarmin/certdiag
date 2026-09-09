package certops

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type ReencryptOptions struct {
	InputPath     string
	OldPasswords  []certlib.TaggedPassword
	NewPassword   []byte
	OutputPath    string
	Overwrite     bool
	LegacyPKCS12  bool
	EntryAlias    string // if set, change only this entry's password
	StorePassword []byte // explicit store password (for entry-level changes)
}

type ReencryptResult struct {
	OutputPath     string
	Format         certlib.FileFormat
	ItemCount      int
	SkippedEntries int // entries with different passwords that were not changed
	Warnings       []string
}

func Reencrypt(opts ReencryptOptions) (*ReencryptResult, error) {
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = opts.InputPath
	}

	tagged := withEmptyPasswordFallback(opts.OldPasswords)

	container, err := readAndValidate(opts.InputPath, tagged)
	if err != nil {
		return nil, &OperationError{Op: "reencrypt", Message: err.Error()}
	}

	format := container.Format

	// Entry-level password change (JKS only)
	if opts.EntryAlias != "" {
		if format != certlib.FormatJKS {
			return nil, &OperationError{Op: "reencrypt",
				Message: fmt.Sprintf("--entry is only supported for JKS format, got %s", format)}
		}
		return reencryptEntry(container, opts, outputPath)
	}

	var encoded []byte

	switch format {
	case certlib.FormatPKCS12:
		encoded, err = certlib.EncodePKCS12(container.Items, opts.NewPassword, opts.LegacyPKCS12)
		if err != nil {
			return nil, &OperationError{Op: "reencrypt", Message: "re-encode PKCS#12 failed", Err: err}
		}

	case certlib.FormatJKS:
		if locked := lockedKeyEntries(container); len(locked) > 0 {
			// Do not suggest --entry here: reencryptEntry re-encodes the whole
			// keystore too, so it also drops any locked entry. Supplying every
			// entry's password is the only safe way to rewrite the store.
			return nil, &OperationError{Op: "reencrypt", Message: fmt.Sprintf(
				"refusing to rewrite %s: %d key entr%s could not be unlocked and would be lost (%s); "+
					"supply the correct password(s) for all entries and retry",
				opts.InputPath, len(locked), plural(len(locked), "y", "ies"), strings.Join(locked, ", "))}
		}
		skipped := updateKeyStoreEntryPasswords(container, opts.NewPassword)
		aliases := extractAliases(container.Items)
		encoded, err = certlib.EncodeJKS(container.Items, opts.NewPassword, aliases)
		if err != nil {
			return nil, &OperationError{Op: "reencrypt", Message: fmt.Sprintf("re-encode %s failed", format), Err: err}
		}
		return writeResult(outputPath, opts, encoded, container, skipped)

	case certlib.FormatPEM:
		if len(privateKeyItems(container.Items)) == 0 {
			return nil, &OperationError{Op: "reencrypt",
				Message: fmt.Sprintf("%s contains no private key; nothing to re-encrypt", opts.InputPath)}
		}
		encoded, err = reencryptPEMKeys(container, opts.NewPassword)
		if err != nil {
			return nil, &OperationError{Op: "reencrypt", Message: "re-encode PEM failed", Err: err}
		}

	default:
		return nil, &OperationError{Op: "reencrypt", Message: fmt.Sprintf("format %q does not support password changing", format)}
	}

	return writeResult(outputPath, opts, encoded, container, 0)
}

// updateKeyStoreEntryPasswords updates entry passwords for JKS store-level password change.
// Entries matching the old store password get the new password. Others are left unchanged.
// Returns the count of entries that were not changed (different password).
func updateKeyStoreEntryPasswords(container *certlib.CertContainer, newPassword []byte) int {
	skipped := 0
	for i := range container.Items {
		item := &container.Items[i]
		if item.Type != certlib.ContentPrivateKey || item.EntryPassword == nil {
			continue
		}
		if bytes.Equal(item.EntryPassword, container.Password) {
			item.EntryPassword = newPassword
		} else {
			skipped++
		}
	}
	return skipped
}

// lockedKeyEntries returns the aliases of private-key entries that could not be
// unlocked (read as nil-key placeholders). Re-encoding a JKS while these are
// present would silently drop them, so callers must refuse.
func lockedKeyEntries(container *certlib.CertContainer) []string {
	return lockedKeyItemAliases(container.Items)
}

// lockedKeyItemAliases returns the aliases of nil-key private-key placeholders
// among items. Shared by reencrypt and convert, which both silently drop such
// entries on re-encode without this check.
func lockedKeyItemAliases(items []certlib.CertItem) []string {
	var locked []string
	for i := range items {
		item := &items[i]
		// A private-key item with no parsed key is a nil-key placeholder that
		// EncodeJKS silently drops: either no supplied password unlocked it
		// (Encrypted), or it decrypted but the key bytes could not be parsed
		// (e.g. an algorithm Go cannot load, such as DSA - Encrypted stays false).
		// Both are data loss, so guard on PrivateKey == nil alone.
		if item.Type == certlib.ContentPrivateKey && item.PrivateKey == nil {
			alias := item.Alias
			if alias == "" {
				alias = fmt.Sprintf("#%d", i)
			}
			locked = append(locked, alias)
		}
	}
	return locked
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

func reencryptEntry(container *certlib.CertContainer, opts ReencryptOptions, outputPath string) (*ReencryptResult, error) {
	if locked := lockedKeyEntries(container); len(locked) > 0 {
		return nil, &OperationError{Op: "reencrypt", Message: fmt.Sprintf(
			"refusing to rewrite %s: %d key entr%s could not be unlocked and would be lost (%s)",
			opts.InputPath, len(locked), plural(len(locked), "y", "ies"), strings.Join(locked, ", "))}
	}
	found := false
	for i := range container.Items {
		item := &container.Items[i]
		if item.Type == certlib.ContentPrivateKey && item.Alias == opts.EntryAlias {
			item.EntryPassword = opts.NewPassword
			found = true
			break
		}
	}
	if !found {
		return nil, &OperationError{Op: "reencrypt",
			Message: fmt.Sprintf("no private key entry with alias %q found", opts.EntryAlias)}
	}

	// Use the original store password for re-encoding
	storePassword := opts.StorePassword
	if storePassword == nil {
		storePassword = container.Password
	}

	aliases := extractAliases(container.Items)
	var encoded []byte
	var err error
	encoded, err = certlib.EncodeJKS(container.Items, storePassword, aliases)
	if err != nil {
		return nil, &OperationError{Op: "reencrypt",
			Message: fmt.Sprintf("re-encode %s failed", container.Format), Err: err}
	}

	return writeResult(outputPath, opts, encoded, container, 0)
}

func writeResult(outputPath string, opts ReencryptOptions, encoded []byte, container *certlib.CertContainer, skipped int) (*ReencryptResult, error) {
	overwrite := opts.Overwrite
	if outputPath == opts.InputPath {
		overwrite = true
	}

	if err := certlib.WriteToFile(outputPath, encoded, overwrite); err != nil {
		return nil, &OperationError{Op: "reencrypt", Message: "write failed", Err: err}
	}

	var warnings []string
	if container.Format == certlib.FormatJKS {
		if w := certlib.JKSPasswordWarning(opts.NewPassword); w != "" {
			warnings = append(warnings, w)
		}
	}

	return &ReencryptResult{
		OutputPath:     outputPath,
		Format:         container.Format,
		ItemCount:      len(container.Items),
		SkippedEntries: skipped,
		Warnings:       warnings,
	}, nil
}

func extractAliases(items []certlib.CertItem) map[int]string {
	aliases := make(map[int]string)
	for i, item := range items {
		if item.Alias != "" {
			aliases[i] = item.Alias
		}
	}
	return aliases
}

func reencryptPEMKeys(container *certlib.CertContainer, newPassword []byte) ([]byte, error) {
	keyItems := privateKeyItems(container.Items)
	ki := 0

	var allBytes []byte
	remaining := container.RawData
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if isPEMPrivateKeyBlock(block.Type) {
			var item certlib.CertItem
			if ki < len(keyItems) {
				item = keyItems[ki]
				ki++
			}
			enc, err := reencodePEMKey(item, newPassword)
			if err != nil {
				return nil, err
			}
			allBytes = append(allBytes, enc...)
		} else {
			allBytes = append(allBytes, pem.EncodeToMemory(block)...)
		}
		remaining = rest
	}

	return allBytes, nil
}

func reencodePEMKey(item certlib.CertItem, newPassword []byte) ([]byte, error) {
	if item.PrivateKey == nil {
		if item.Encrypted {
			return nil, fmt.Errorf("could not decrypt private key (wrong password or unsupported encryption)")
		}
		return nil, fmt.Errorf("private key could not be parsed")
	}
	if len(newPassword) > 0 {
		enc, err := encodePEMEncrypted(item.PrivateKey, newPassword)
		if err != nil {
			return nil, fmt.Errorf("encrypt key: %w", err)
		}
		return enc, nil
	}
	enc, err := certlib.EncodePEM([]certlib.CertItem{item})
	if err != nil {
		return nil, fmt.Errorf("encode PEM item: %w", err)
	}
	return enc, nil
}

func privateKeyItems(items []certlib.CertItem) []certlib.CertItem {
	var keys []certlib.CertItem
	for _, item := range items {
		if item.Type == certlib.ContentPrivateKey {
			keys = append(keys, item)
		}
	}
	return keys
}

func isPEMPrivateKeyBlock(blockType string) bool {
	switch blockType {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	}
	return false
}
