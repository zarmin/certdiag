package certops

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
)

type ExtractOptions struct {
	InputPath      string
	InputPasswords []certlib.TaggedPassword
	OutputDir      string
	OutputFile     string // direct output path for single-item extraction
	OutputFormat   certlib.FileFormat
	OutputPassword []byte // for p12/jks container output
	Index          int    // 1-based, 0 = all
	Alias          string
	TypeFilter     string // "certs", "keys", "all"
	NamingPattern  string
	Overwrite      bool
}

type ExtractResult struct {
	ExtractedFiles []ExtractedFile
	TotalItems     int
}

type ExtractedFile struct {
	Path    string
	Type    string
	Subject string
}

func Extract(opts ExtractOptions) (*ExtractResult, error) {
	if opts.OutputDir == "" {
		opts.OutputDir = "."
	}
	if opts.OutputFormat == "" {
		opts.OutputFormat = certlib.FormatPEM
	}
	if opts.NamingPattern == "" {
		opts.NamingPattern = "{filename}-{index}-{type}"
	}
	if opts.TypeFilter == "" {
		opts.TypeFilter = "all"
	}

	tagged := withEmptyPasswordFallback(opts.InputPasswords)

	container, err := readAndValidate(opts.InputPath, tagged)
	if err != nil {
		return nil, &OperationError{Op: "extract", Message: err.Error()}
	}

	// Build candidate list with original 1-based indices
	type candidate struct {
		item  certlib.CertItem
		index int // 1-based
	}
	var candidates []candidate
	for i, item := range container.Items {
		candidates = append(candidates, candidate{item: item, index: i + 1})
	}

	// Filter by type
	if opts.TypeFilter != "all" {
		var filtered []candidate
		for _, c := range candidates {
			if matchesTypeFilter(c.item, opts.TypeFilter) {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	// Filter by index
	if opts.Index > 0 {
		var filtered []candidate
		for _, c := range candidates {
			if c.index == opts.Index {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	// Filter by alias
	if opts.Alias != "" {
		var filtered []candidate
		for _, c := range candidates {
			if strings.EqualFold(c.item.Alias, opts.Alias) {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	if len(candidates) == 0 {
		return nil, &OperationError{Op: "extract", Message: "no items match the specified filters"}
	}

	if opts.OutputFile != "" && len(candidates) > 1 {
		return nil, &OperationError{Op: "extract", Message: fmt.Sprintf(
			"--output-file targets a single file but %d items match; narrow with --index/--alias/--type or use an output directory", len(candidates))}
	}

	baseName := fileBaseName(opts.InputPath)
	ext := formatExtension(opts.OutputFormat)

	result := &ExtractResult{
		TotalItems: len(container.Items),
	}

	for _, c := range candidates {
		var outPath string
		if opts.OutputFile != "" {
			outPath = opts.OutputFile
		} else {
			filename := resolveNamingPattern(opts.NamingPattern, baseName, c.index, c.item, ext)
			outPath = filepath.Join(opts.OutputDir, filename)
		}

		encoded, err := encodeSingleItem(c.item, opts)
		if err != nil {
			return nil, &OperationError{Op: "extract", Message: fmt.Sprintf("encode item %d failed", c.index), Err: err}
		}

		if err := certlib.WriteToFile(outPath, encoded, opts.Overwrite); err != nil {
			return nil, &OperationError{Op: "extract", Message: fmt.Sprintf("write item %d failed", c.index), Err: err}
		}

		result.ExtractedFiles = append(result.ExtractedFiles, ExtractedFile{
			Path:    outPath,
			Type:    string(c.item.Type),
			Subject: itemSubject(c.item),
		})
	}

	return result, nil
}

func matchesTypeFilter(item certlib.CertItem, filter string) bool {
	switch strings.ToLower(filter) {
	case "certs":
		return item.Type == certlib.ContentCertificate
	case "keys":
		return item.Type == certlib.ContentPrivateKey || item.Type == certlib.ContentPublicKey
	default:
		return true
	}
}

func fileBaseName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

func formatExtension(format certlib.FileFormat) string {
	switch format {
	case certlib.FormatPEM:
		return "pem"
	case certlib.FormatDER:
		return "der"
	case certlib.FormatPKCS12:
		return "p12"
	case certlib.FormatPKCS7:
		return "p7b"
	case certlib.FormatJKS:
		return "jks"
	default:
		return "bin"
	}
}

func itemTypeName(item certlib.CertItem) string {
	switch item.Type {
	case certlib.ContentCertificate:
		return "cert"
	case certlib.ContentPrivateKey:
		return "key"
	case certlib.ContentPublicKey:
		return "pubkey"
	case certlib.ContentCSR:
		return "csr"
	default:
		return "unknown"
	}
}

func itemSubject(item certlib.CertItem) string {
	if item.Certificate != nil && item.Certificate.Subject.CommonName != "" {
		return item.Certificate.Subject.CommonName
	}
	if item.CSR != nil && item.CSR.Subject.CommonName != "" {
		return item.CSR.Subject.CommonName
	}
	return "unknown"
}

func resolveNamingPattern(pattern, baseName string, index int, item certlib.CertItem, ext string) string {
	aliasVal := item.Alias
	if aliasVal == "" {
		aliasVal = "noalias"
	}

	subjectVal := stringutil.SanitizeFilename(itemSubject(item))

	result := pattern
	result = strings.ReplaceAll(result, "{filename}", baseName)
	result = strings.ReplaceAll(result, "{index}", fmt.Sprintf("%d", index))
	result = strings.ReplaceAll(result, "{type}", itemTypeName(item))
	result = strings.ReplaceAll(result, "{alias}", stringutil.SanitizeFilename(aliasVal))
	result = strings.ReplaceAll(result, "{subject}", subjectVal)
	result = strings.ReplaceAll(result, "{format}", ext)

	if !strings.HasSuffix(result, "."+ext) {
		result = result + "." + ext
	}

	return result
}

func encodeSingleItem(item certlib.CertItem, opts ExtractOptions) ([]byte, error) {
	// Extraction is item-level. A JKS-sourced key item carries its issuer certs
	// on the Chain field for whole-container conversions, but a single-item
	// extract must stay item-only: WritePEM would otherwise expand that chain and
	// a "keys" extract would gain intermediate/root CERTIFICATE blocks. Drop the
	// chain on this local copy so the output contains only the extracted item.
	item.Chain = nil
	switch opts.OutputFormat {
	case certlib.FormatPEM:
		return certlib.EncodePEM([]certlib.CertItem{item})
	case certlib.FormatDER:
		return certlib.EncodeDER(item)
	case certlib.FormatPKCS12:
		return certlib.EncodePKCS12([]certlib.CertItem{item}, opts.OutputPassword, false)
	case certlib.FormatPKCS7:
		return certlib.EncodePKCS7([]certlib.CertItem{item})
	case certlib.FormatJKS:
		aliases := map[int]string{}
		if item.Alias != "" {
			aliases[0] = item.Alias
		}
		return certlib.EncodeJKS([]certlib.CertItem{item}, opts.OutputPassword, aliases)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", opts.OutputFormat)
	}
}
