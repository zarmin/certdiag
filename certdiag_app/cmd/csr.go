package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	csrSubject   string
	csrSAN       string
	csrKeyFile   string
	csrWithKey   bool
	csrKeyFlags  cmdutil.KeyGenFlags
	csrKeyOutput string
	csrOutput    string
	csrFormat    string
	csrNoConfirm bool
	csrPassword  string
	csrEncrypt   bool
	csrTemplate  string
	csrProfile   string
)

var csrCmd = &cobra.Command{
	Use:     "create-csr",
	Aliases: []string{"csr"},
	Short:   "Create a PKCS#10 Certificate Signing Request",
	Long: `Create a Certificate Signing Request (CSR).

A key is either loaded from file (--key-file) or generated on-the-fly (--with-key).

Templates: use --template to clone subject/SANs from an existing certificate, or
--template-profile to load a saved YAML profile. CLI flags always take precedence.

Examples:
  certdiag create-csr --with-key --subject "CN=example.com" -o example.csr --key-output example.key
  certdiag create-csr --with-key --subject "CN=web" --san "DNS:web.local,IP:10.0.0.1" -o web.csr
  certdiag create-csr -k existing.key --subject "CN=reuse" -o reuse.csr
  certdiag create-csr --with-key --template existing.crt --subject "CN=new" -o new.csr --key-output new.key`,
	Args: cobra.NoArgs,
	Run:  runCSR,
}

func init() {
	csrCmd.Flags().StringVar(&csrSubject, "subject", "", "CSR subject DN (e.g. CN=example,O=Org)")
	csrCmd.Flags().StringVar(&csrSAN, "san", "", "Subject Alternative Names (e.g. DNS:a.com,IP:1.2.3.4)")

	csrCmd.Flags().StringVarP(&csrKeyFile, "key-file", "k", "", "Use existing private key file")
	csrCmd.Flags().BoolVar(&csrWithKey, "with-key", false, "Generate a new private key")
	csrKeyFlags.Register(csrCmd, "")
	csrCmd.Flags().StringVar(&csrKeyOutput, "key-output", "", "Output path for generated key")
	csrCmd.Flags().BoolVar(&csrEncrypt, "encrypt-key", false, "Encrypt generated private key")

	csrCmd.Flags().StringVar(&csrTemplate, "template", "", "Clone subject/SANs from an existing certificate file")
	csrCmd.Flags().StringVar(&csrProfile, "template-profile", "", "Load settings from a YAML profile file")

	csrCmd.Flags().StringVarP(&csrOutput, "output-file", "o", "", "Output CSR file (default: stdout)")
	csrCmd.Flags().StringVarP(&csrFormat, "format", "f", "", "Output format: pem, der (default: pem)")
	csrCmd.Flags().BoolVar(&csrNoConfirm, "no-confirm", false, "Overwrite output files without confirmation")
	csrCmd.Flags().StringVarP(&csrPassword, "password", "p", "", "Password for encrypted key files")
	registerPasswordFileFlag(csrCmd)

	markOpenSSLSupported(csrCmd)
	rootCmd.AddCommand(csrCmd)
}

func runCSR(cmd *cobra.Command, args []string) {
	// Validate mutually exclusive template flags
	if csrTemplate != "" && csrProfile != "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --template and --template-profile are mutually exclusive"))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	keyDefaults := (&config.ConfigFile{}).GetKeyDefaults()
	subjectDefaults := (&config.ConfigFile{}).GetSubjectDefaults()
	if cfg != nil {
		keyDefaults = cfg.GetKeyDefaults()
		subjectDefaults = cfg.GetSubjectDefaults()
	}

	pm := cliPasswordManager(cmd, cfg, "password", []string{csrPassword}, 1)

	// Template options (from a cert file or a YAML profile), read with the
	// passwords known for that file so a PKCS#12 can serve as a template
	tmpl, err := cmdutil.LoadTemplateInputs(csrTemplate, csrProfile, pm.PasswordsForFile(csrTemplate))
	if err != nil {
		fail(1, "Error: %v", err)
	}
	tmpl.ApplyKeyDefaults(&keyDefaults)

	// Subject: config defaults, then template, then CLI; SANs: template unless --san
	subject, err := tmpl.ResolveSubject(subjectDefaults, csrSubject)
	if err != nil {
		fail(1, "Error: %v", err)
	}
	sans, err := tmpl.ResolveSANs(csrSAN, cmd.Flags().Changed("san"))
	if err != nil {
		fail(1, "Error: %v", err)
	}

	// Resolve output format
	var configFmt string
	if cfg != nil {
		configFmt = cfg.Defaults.Output.Format
	}
	format, err := cmdutil.ResolveOutputFormat(csrFormat, configFmt, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Resolve key algorithm params (CLI overrides template, which overrides config)
	csrKeyFlags.ApplyChanged(cmd, &keyDefaults)

	if err := cmdutil.ValidateKeyParams(cmd, keyDefaults.Algorithm, keyDefaults.KeySize, keyDefaults.Curve); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	var keyPasswords []certlib.TaggedPassword
	if csrKeyFile != "" {
		keyPasswords = pm.PasswordsForFile(csrKeyFile)
	}

	encryptPw := mustEncryptKeyPassword(cmd, csrEncrypt, "password", format)

	opts := certops.CreateCSROptions{
		Subject:          subject,
		SANs:             sans,
		KeyFilePath:      csrKeyFile,
		KeyFilePasswords: keyPasswords,
		WithKey:          csrWithKey,
		KeyOptions:       keyDefaults,
		CSROutputPath:    csrOutput,
		KeyOutputPath:    mustKeyDestination(csrOutput, csrKeyOutput, csrWithKey),
		OutputFormat:     format,
		EncryptKey:       csrEncrypt,
		KeyPassword:      encryptPw,
		Overwrite:        csrNoConfirm,
	}

	if showOpenSSLFlag {
		renderOpenSSL(certops.OpenSSLForCreateCSR(opts))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.CreateCSR(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if !result.CSRWritten {
		os.Stdout.Write(result.CSRBytes)
		if !result.KeyWritten {
			os.Stdout.Write(result.KeyBytes)
		}
	}

	fmt.Fprintf(os.Stderr, "created CSR (%s)\n", result.KeyType)
	fmt.Fprintf(os.Stderr, "  subject: %s\n", result.Subject)
	if result.CSRWritten {
		fmt.Fprintf(os.Stderr, "  csr:     %s\n", result.CSRPath)
	}
	if result.KeyWritten {
		fmt.Fprintf(os.Stderr, "  key:     %s\n", result.KeyPath)
	}
}
