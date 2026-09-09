package cmdutil

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// ResolveOutputFormat resolves the output file format from an explicit flag value,
// config default, and/or output file extension.
func ResolveOutputFormat(explicit string, configDefault string, outputPath string) (certlib.FileFormat, error) {
	if explicit != "" {
		return parseFormat(explicit)
	}
	if outputPath != "" {
		if f, ok := certlib.FormatFromExtension(filepath.Ext(outputPath)); ok {
			return f, nil
		}
	}
	if configDefault != "" {
		return parseFormat(configDefault)
	}
	return certlib.FormatPEM, nil
}

func parseFormat(s string) (certlib.FileFormat, error) {
	switch strings.ToLower(s) {
	case "pem":
		return certlib.FormatPEM, nil
	case "der":
		return certlib.FormatDER, nil
	case "pkcs12", "p12":
		return certlib.FormatPKCS12, nil
	case "p7b", "pkcs7":
		return certlib.FormatPKCS7, nil
	case "jks":
		return certlib.FormatJKS, nil
	default:
		return "", fmt.Errorf("unsupported output format: %q", s)
	}
}
