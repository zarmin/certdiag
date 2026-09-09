package certops

import (
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type ConvertOptions struct {
	InputPath      string
	InputPasswords []certlib.TaggedPassword
	OutputPath     string
	OutputFormat   certlib.FileFormat
	OutputPassword []byte
	Alias          string
	Aliases        map[int]string
	Include        string // "certs", "keys", "all"
	Overwrite      bool
	LegacyPKCS12   bool
}

type ConvertResult struct {
	InputFormat  string
	OutputFormat string
	ItemCount    int
	OutputPath   string
	Warnings     []string
}

func Convert(opts ConvertOptions) (*ConvertResult, error) {
	if opts.Include == "" {
		opts.Include = "all"
	}

	tagged := withEmptyPasswordFallback(opts.InputPasswords)

	container, err := readAndValidate(opts.InputPath, tagged)
	if err != nil {
		return nil, &OperationError{Op: "convert", Message: err.Error()}
	}

	items := filterItems(container.Items, opts.Include)
	if len(items) == 0 {
		return nil, &OperationError{Op: "convert", Message: fmt.Sprintf("no items matching filter %q", opts.Include)}
	}

	if opts.OutputFormat == certlib.FormatDER && len(items) > 1 {
		return nil, &OperationError{Op: "convert", Message: fmt.Sprintf("DER format supports only one item, input contains %d", len(items))}
	}

	result := &ConvertResult{
		InputFormat:  string(container.Format),
		OutputFormat: string(opts.OutputFormat),
		OutputPath:   opts.OutputPath,
	}

	// Apply conversion matrix: collect warnings and adjust items
	items, result.Warnings = applyConversionMatrix(items, container.Format, opts.OutputFormat)
	result.ItemCount = len(items)

	if opts.OutputFormat == certlib.FormatJKS {
		if w := certlib.JKSPasswordWarning(opts.OutputPassword); w != "" {
			result.Warnings = append(result.Warnings, w)
		}
	}

	// A locked/unparseable key entry (nil-key placeholder) that survives the
	// matrix into a key-preserving output format would be silently dropped by
	// EncodeJKS/EncodePKCS12. Refuse rather than lose keys, matching reencrypt.
	// (Formats that drop keys, e.g. PKCS#7, remove the placeholder in the matrix
	// above, so this only fires when the key would actually have been encoded.)
	if locked := lockedKeyItemAliases(items); len(locked) > 0 {
		return nil, &OperationError{Op: "convert", Message: fmt.Sprintf(
			"refusing to convert %s: %d key entr%s could not be unlocked and would be lost (%s); supply the correct password(s)",
			opts.InputPath, len(locked), plural(len(locked), "y", "ies"), strings.Join(locked, ", "))}
	}

	encoded, err := encodeItems(items, opts)
	if err != nil {
		return nil, &OperationError{Op: "convert", Message: "encoding failed", Err: err}
	}

	if err := certlib.WriteToFile(opts.OutputPath, encoded, opts.Overwrite); err != nil {
		return nil, &OperationError{Op: "convert", Message: "write failed", Err: err}
	}

	return result, nil
}

func filterItems(items []certlib.CertItem, include string) []certlib.CertItem {
	switch strings.ToLower(include) {
	case "certs":
		var filtered []certlib.CertItem
		for _, item := range items {
			if item.Type == certlib.ContentCertificate {
				filtered = append(filtered, item)
			}
		}
		return filtered
	case "keys":
		var filtered []certlib.CertItem
		for _, item := range items {
			if item.Type == certlib.ContentPrivateKey || item.Type == certlib.ContentPublicKey {
				filtered = append(filtered, item)
			}
		}
		return filtered
	default:
		return items
	}
}

func applyConversionMatrix(items []certlib.CertItem, srcFmt, dstFmt certlib.FileFormat) ([]certlib.CertItem, []string) {
	var warnings []string

	// Materialize any issuer certs carried on a JKS-sourced key's Chain into
	// standalone cert items before format-specific filtering. Otherwise the
	// cert-only branches below (e.g. PKCS#7) drop the key together with its
	// chain, losing intermediates that the target format could hold.
	items = certlib.ExpandKeyChains(items)

	switch dstFmt {
	case certlib.FormatPKCS7:
		// PKCS#7 degenerate can only hold certificates
		var filtered []certlib.CertItem
		dropped := 0
		for _, item := range items {
			if item.Type == certlib.ContentCertificate {
				filtered = append(filtered, item)
			} else {
				dropped++
			}
		}
		if dropped > 0 {
			warnings = append(warnings, fmt.Sprintf("dropped %d non-certificate item(s) (PKCS#7 only holds certificates)", dropped))
		}
		items = filtered

	case certlib.FormatDER:
		// DER is single-item only — caller should pre-check; this is a safety net
		if len(items) > 1 {
			warnings = append(warnings, fmt.Sprintf("DER format supports only one item, keeping first of %d", len(items)))
			items = items[:1]
		}

	case certlib.FormatPKCS12:
		if srcFmt == certlib.FormatPKCS7 {
			hasKey := false
			for _, item := range items {
				if item.Type == certlib.ContentPrivateKey {
					hasKey = true
					break
				}
			}
			if !hasKey {
				warnings = append(warnings, "PKCS#7 source has no private keys; creating trust store only")
			}
		}

	case certlib.FormatJKS:
		if srcFmt == certlib.FormatPKCS7 {
			warnings = append(warnings, "PKCS#7 source has no private keys; creating trusted certificate entries only")
		}
	}

	return items, warnings
}

func encodeItems(items []certlib.CertItem, opts ConvertOptions) ([]byte, error) {
	switch opts.OutputFormat {
	case certlib.FormatPEM:
		return certlib.EncodePEM(items)

	case certlib.FormatDER:
		if len(items) == 0 {
			return nil, fmt.Errorf("no items to encode")
		}
		return certlib.EncodeDER(items[0])

	case certlib.FormatPKCS12:
		return certlib.EncodePKCS12(items, opts.OutputPassword, opts.LegacyPKCS12)

	case certlib.FormatPKCS7:
		return certlib.EncodePKCS7(items)

	case certlib.FormatJKS:
		aliases := opts.Aliases
		if aliases == nil {
			aliases = make(map[int]string)
			if opts.Alias != "" {
				aliases[0] = opts.Alias
			}
		}
		return certlib.EncodeJKS(items, opts.OutputPassword, aliases)

	default:
		return nil, fmt.Errorf("unsupported output format: %s", opts.OutputFormat)
	}
}
