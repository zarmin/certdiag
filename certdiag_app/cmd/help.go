package cmd

import (
	"github.com/fatih/color"
)

func GetLongDescription() string {
	return `A tool to inspect and analyze X.509 certificates, keys, and keystores.

Supports various certificate formats including PEM, DER, PKCS#12, and Java KeyStore (JKS).
Can scan individual files or directories recursively to find and analyze certificates.`
}

func GetColorsHelp() string {
	expired := color.New(color.FgRed, color.Bold)
	expiringUrgent := color.New(color.FgHiRed)
	expiringWarning := color.New(color.FgYellow)
	expiringOK := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	errorColor := color.New(color.FgRed, color.Bold)
	warningColor := color.New(color.FgYellow)
	caColor := color.New(color.FgGreen, color.Bold)

	return `COLORS:
  Expiry dates are colored based on validity status:
    ` + expired.Sprint("Red (bold)") + `    - Expired or not yet valid
    ` + expiringUrgent.Sprint("Bright Red") + `  - Expiring within 7 days
    ` + expiringWarning.Sprint("Yellow") + `      - Expiring within 30 days
    ` + expiringOK.Sprint("Green") + `       - Valid for 30-90 days
    Default       - Valid for more than 90 days

  File types are colored by content:
    ` + blue.Sprint("Blue") + `          - Cert bundles with private keys
    ` + cyan.Sprint("Cyan") + `          - Key-only files
    ` + magenta.Sprint("Magenta") + `       - Certificate signing requests
    Default       - Certificate-only files

  Status indicators:
    ` + errorColor.Sprint("Red (bold)") + `    - Errors
    ` + warningColor.Sprint("Yellow") + `        - Warnings and self-signed certificates
    ` + caColor.Sprint("Green (bold)") + `  - CA certificates

  Colors are automatically disabled when output is piped or NO_COLOR is set.`
}
