package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/pkg/oscountry"
)

var (
	templatesFrom     string
	templatesPassword string
)

var templatesCmd = &cobra.Command{
	Use:   "templates [type]",
	Short: "Print certificate profile templates",
	Long: `Print a YAML certificate profile template to stdout.

Supported types:
  cert  - Standard leaf certificate profile
  ca    - Certificate Authority profile
  csr   - Certificate Signing Request profile

Use --from to generate a pre-filled template from an existing certificate or CSR:
  certdiag templates cert --from server.crt > server-profile.yaml
  certdiag templates csr --from existing.crt > csr-profile.yaml

Cross-type extraction is supported (e.g., CSR profile from a CA cert).
When extracting across types, KU/EKU use target-type defaults.

The output can be saved to a file and customized, then used with
--template-profile when creating certificates or CSRs.

Examples:
  certdiag templates cert > my-server.yaml
  certdiag templates ca > my-ca.yaml
  certdiag templates csr > my-csr.yaml
  certdiag templates cert --from existing.crt > clone-profile.yaml
  certdiag templates csr --from ca.crt > csr-from-ca.yaml
  certdiag create-cert --with-key --template-profile my-server.yaml -o server.crt --key-output server.key`,
	Args: cobra.RangeArgs(0, 1),
	Run:  runTemplates,
}

func init() {
	rootCmd.AddCommand(templatesCmd)
	templatesCmd.Flags().StringVar(&templatesFrom, "from", "", "generate template from an existing certificate or CSR file")
	templatesCmd.Flags().StringVarP(&templatesPassword, "password", "p", "", "Password for an encrypted --from file")
	registerPasswordFileFlag(templatesCmd)
}

func runTemplates(cmd *cobra.Command, args []string) {
	if templatesFrom != "" {
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: --from requires a type argument (cert, ca, csr)")
			os.Exit(1)
		}
		targetType := args[0]
		switch targetType {
		case "cert", "ca", "csr":
			runTemplatesFrom(cmd, targetType, templatesFrom)
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown template type %q (valid: cert, ca, csr)\n", targetType)
			os.Exit(1)
		}
		return
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: requires a type argument (cert, ca, csr) or --from flag")
		os.Exit(1)
	}

	td := loadTemplateDefaults()

	switch args[0] {
	case "cert":
		fmt.Fprintf(os.Stdout, certProfileTemplate,
			td.organization, td.organizationalUnit, td.country, td.state, td.locality,
			td.certAlgorithm, td.certKeySize, td.certCurve, td.certDays)
	case "ca":
		fmt.Fprintf(os.Stdout, caProfileTemplate,
			td.organization, td.organizationalUnit, td.country, td.state, td.locality,
			td.caAlgorithm, td.caKeySize, td.caCurve, td.caDays)
	case "csr":
		fmt.Fprintf(os.Stdout, csrProfileTemplate,
			td.organization, td.organizationalUnit, td.country, td.state, td.locality,
			td.certAlgorithm, td.certKeySize, td.certCurve)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown template type %q (valid: cert, ca, csr)\n", args[0])
		os.Exit(1)
	}
}

func runTemplatesFrom(cmd *cobra.Command, targetType, path string) {
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", []string{templatesPassword}, 1)
	container, err := certlib.ReadFile(path, pm.PasswordsForFile(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", path, err)
		os.Exit(1)
	}

	var profile certlib.CertProfile
	found := false
	for _, item := range container.Items {
		switch item.Type {
		case certlib.ContentCertificate:
			profile = certlib.ProfileFromCertAs(item.Certificate, targetType)
			found = true
		case certlib.ContentCSR:
			profile = certlib.ProfileFromCSRAs(item.CSR, targetType)
			found = true
		}
		if found {
			break
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Error: no certificate or CSR found in %s\n", path)
		os.Exit(1)
	}

	data, err := certlib.MarshalProfile(&profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling profile: %v\n", err)
		os.Exit(1)
	}

	useCmd := "create-cert"
	if targetType == "csr" {
		useCmd = "create-csr"
	}
	header := fmt.Sprintf("# certdiag certificate profile (generated from %s)\n"+
		"# Edit values, then use:\n"+
		"#   certdiag %s --with-key --template-profile <this-file> -o output --key-output key\n\n",
		filepath.Base(path), useCmd)
	fmt.Fprint(os.Stdout, header)
	fmt.Fprint(os.Stdout, string(data))
}

type templateDefaults struct {
	organization       string
	organizationalUnit string
	country            string
	state              string
	locality           string
	certAlgorithm      string
	certKeySize        int
	certCurve          string
	certDays           int
	caAlgorithm        string
	caKeySize          int
	caCurve            string
	caDays             int
}

func loadTemplateDefaults() templateDefaults {
	td := templateDefaults{
		certAlgorithm: "ecdsa",
		certCurve:     "p256",
		certKeySize:   2048,
		certDays:      365,
		caAlgorithm:   "ecdsa",
		caCurve:       "p384",
		caKeySize:     4096,
		caDays:        3650,
	}

	// Detect country from OS locale/timezone
	td.country = oscountry.GuessCountry()

	// Load config for additional defaults
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	if cfg == nil {
		return td
	}

	subj := cfg.Defaults.Subject
	if subj.Organization != nil && *subj.Organization != "" {
		td.organization = *subj.Organization
	}
	if subj.OrganizationalUnit != "" {
		td.organizationalUnit = subj.OrganizationalUnit
	}
	if subj.Country != "" {
		td.country = subj.Country
	}
	if subj.State != "" {
		td.state = subj.State
	}
	if subj.Locality != "" {
		td.locality = subj.Locality
	}

	keyDef := cfg.GetKeyDefaults()
	td.certAlgorithm = keyDef.Algorithm
	td.certCurve = keyDef.Curve
	td.certKeySize = keyDef.KeySize
	td.caAlgorithm = keyDef.Algorithm
	td.caCurve = keyDef.Curve
	td.caKeySize = keyDef.KeySize

	certDef := cfg.GetCertDefaults()
	td.certDays = certDef.Days
	td.caDays = certDef.CADays

	return td
}

const certProfileTemplate = `# certdiag certificate profile
# Save this file, edit values, then use:
#   certdiag create-cert --with-key --template-profile <this-file> -o cert.crt --key-output cert.key

kind: certdiag-cert-profile
version: "1"

name: "My Server Certificate"
description: "Template for a standard TLS server certificate"

subject:
  common_name: "example.com"
  organization: "%s"
  organizational_unit: "%s"
  country: "%s"
  state: "%s"
  locality: "%s"

sans:
  dns:
    - "example.com"
    - "www.example.com"
  ips: []
  #  - "192.168.1.1"
  emails: []

key:
  algorithm: "%s"       # rsa, ecdsa, ed25519
  # key_size: %d         # RSA only: 2048, 3072, 4096
  curve: "%s"            # ECDSA only: p256, p384, p521

validity:
  days: %d

# ca: false
# path_length: 0

key_usage:
  - "digitalSignature"
  - "keyEncipherment"

ext_key_usage:
  - "serverAuth"
`

const csrProfileTemplate = `# certdiag CSR profile
# Save this file, edit values, then use:
#   certdiag create-csr --with-key --template-profile <this-file> -o request.csr --key-output request.key

kind: certdiag-cert-profile
version: "1"

name: "My Certificate Request"
description: "Template for a certificate signing request"

subject:
  common_name: "example.com"
  organization: "%s"
  organizational_unit: "%s"
  country: "%s"
  state: "%s"
  locality: "%s"

sans:
  dns:
    - "example.com"
    - "www.example.com"
  ips: []
  #  - "192.168.1.1"
  emails: []

key:
  algorithm: "%s"       # rsa, ecdsa, ed25519
  # key_size: %d         # RSA only: 2048, 3072, 4096
  curve: "%s"            # ECDSA only: p256, p384, p521

key_usage:
  - "digitalSignature"
  - "keyEncipherment"

ext_key_usage:
  - "serverAuth"
  - "clientAuth"
`

const caProfileTemplate = `# certdiag CA certificate profile
# Save this file, edit values, then use:
#   certdiag create-cert --with-key --template-profile <this-file> -o ca.crt --key-output ca.key

kind: certdiag-cert-profile
version: "1"

name: "My Certificate Authority"
description: "Template for a root or intermediate CA"

subject:
  common_name: "My CA"
  organization: "%s"
  organizational_unit: "%s"
  country: "%s"
  state: "%s"
  locality: "%s"

sans:
  dns: []
  ips: []
  emails: []

key:
  algorithm: "%s"       # rsa, ecdsa, ed25519
  # key_size: %d         # RSA only: 2048, 3072, 4096
  curve: "%s"            # ECDSA only: p256, p384, p521

validity:
  days: %d

ca: true
path_length: -1            # -1 = unconstrained, 0 = no sub-CAs, 1+ = depth limit

key_usage:
  - "certSign"
  - "crlSign"

ext_key_usage: []
`
