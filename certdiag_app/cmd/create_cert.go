package cmd

import (
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	createCertSubject       string
	createCertSAN           string
	createCertDays          int
	createCertNotBefore     string
	createCertCA            bool
	createCertPathLength    int
	createCertPermitted     string
	createCertExcluded      string
	createCertNCNotCritical bool
	createCertKeyUsage      string
	createCertExtKeyUsage   string
	createCertSerial        string
	createCertKeyFile       string
	createCertWithKey       bool
	createCertKeyFlags      cmdutil.KeyGenFlags
	createCertKeyOutput     string
	createCertSignCA        string
	createCertSignKey       string
	createCertOutput        string
	createCertFormat        string
	createCertNoConfirm     bool
	createCertPassword      string
	createCertEncrypt       bool
	createCertTemplate      string
	createCertProfile       string
	createCertAutosign      bool
)

var createCertCmd = &cobra.Command{
	Use:   "create-cert",
	Short: "Create an X.509 certificate",
	Long: `Create a self-signed or CA-signed X.509 certificate.

A key is either loaded from file (--key-file) or generated on-the-fly (--with-key).
To sign with a CA, provide --sign-ca and --sign-key; otherwise a self-signed cert is created.

Templates: use --template to clone settings from an existing certificate, or
--template-profile to load a saved YAML profile. CLI flags always take precedence.

Examples:
  certdiag create-cert --with-key --subject "CN=test" -o test.crt --key-output test.key
  certdiag create-cert --with-key --ca --subject "CN=My CA" --days 3650 -o ca.crt --key-output ca.key
  certdiag create-cert --with-key --subject "CN=leaf" --san "DNS:leaf.local,IP:127.0.0.1" \
    --sign-ca ca.crt --sign-key ca.key -o leaf.crt --key-output leaf.key
  certdiag create-cert --with-key --template existing.crt --subject "CN=new" -o new.crt --key-output new.key
  certdiag create-cert --with-key --template-profile profile.yaml -o cert.crt --key-output cert.key`,
	Args: cobra.NoArgs,
	Run:  runCreateCert,
}

func init() {
	createCertCmd.Flags().StringVar(&createCertSubject, "subject", "", "Certificate subject DN (e.g. CN=example,O=Org)")
	createCertCmd.Flags().StringVar(&createCertSAN, "san", "", "Subject Alternative Names (e.g. DNS:a.com,IP:1.2.3.4)")
	createCertCmd.Flags().IntVar(&createCertDays, "days", 0, "Validity in days (default: 365 leaf, 3650 CA)")
	createCertCmd.Flags().StringVar(&createCertNotBefore, "not-before", "", "Not-before date (YYYY-MM-DD or RFC3339)")
	createCertCmd.Flags().BoolVar(&createCertCA, "ca", false, "Create a CA certificate")
	createCertCmd.Flags().IntVar(&createCertPathLength, "path-length", -1, "CA path length constraint (-1=unconstrained)")
	createCertCmd.Flags().StringVar(&createCertPermitted, "permitted-names", "", "CA only: names this CA may issue for (DNS:example.com,IP:10.0.0.0/8,email:example.com,URI:.example.com)")
	createCertCmd.Flags().StringVar(&createCertExcluded, "excluded-names", "", "CA only: names this CA must never issue for (same syntax)")
	createCertCmd.Flags().BoolVar(&createCertNCNotCritical, "name-constraints-not-critical", false, "Mark name constraints non-critical (RFC 5280 says they must be critical)")
	createCertCmd.Flags().StringVar(&createCertKeyUsage, "key-usage", "", "Key usage (comma-separated): "+strings.Join(certlib.KeyUsageNames, ", "))
	createCertCmd.Flags().StringVar(&createCertExtKeyUsage, "ext-key-usage", "", "Extended key usage (comma-separated): "+strings.Join(certlib.ExtKeyUsageNames, ", "))
	createCertCmd.Flags().StringVar(&createCertSerial, "serial", "", "Certificate serial number (hex)")

	createCertCmd.Flags().StringVarP(&createCertKeyFile, "key-file", "k", "", "Use existing private key file")
	createCertCmd.Flags().BoolVar(&createCertWithKey, "with-key", false, "Generate a new private key")
	createCertKeyFlags.Register(createCertCmd, "")
	createCertCmd.Flags().StringVar(&createCertKeyOutput, "key-output", "", "Output path for generated key")
	createCertCmd.Flags().BoolVar(&createCertEncrypt, "encrypt-key", false, "Encrypt generated private key")

	createCertCmd.Flags().StringVar(&createCertSignCA, "sign-ca", "", "CA certificate for signing")
	createCertCmd.Flags().StringVar(&createCertSignKey, "sign-key", "", "CA private key for signing")

	createCertCmd.Flags().BoolVar(&createCertAutosign, "autosign", false, "Auto-discover a CA in the working directory for signing")

	createCertCmd.Flags().StringVar(&createCertTemplate, "template", "", "Clone settings from an existing certificate file")
	createCertCmd.Flags().StringVar(&createCertProfile, "template-profile", "", "Load settings from a YAML profile file")

	createCertCmd.Flags().StringVarP(&createCertOutput, "output-file", "o", "", "Output certificate file (default: stdout)")
	createCertCmd.Flags().StringVarP(&createCertFormat, "format", "f", "", "Output format: pem, der (default: pem)")
	createCertCmd.Flags().BoolVar(&createCertNoConfirm, "no-confirm", false, "Overwrite output files without confirmation")
	createCertCmd.Flags().StringVarP(&createCertPassword, "password", "p", "", "Password for encrypted key files")
	registerPasswordFileFlag(createCertCmd)

	markOpenSSLSupported(createCertCmd)
	rootCmd.AddCommand(createCertCmd)
}

func runCreateCert(cmd *cobra.Command, args []string) {
	// Validate mutually exclusive flags
	if createCertAutosign && (createCertSignCA != "" || createCertSignKey != "") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --autosign and --sign-ca/--sign-key are mutually exclusive"))
		os.Exit(1)
	}

	// Validate mutually exclusive template flags
	if createCertTemplate != "" && createCertProfile != "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --template and --template-profile are mutually exclusive"))
		os.Exit(1)
	}

	if createCertSubject == "" && createCertTemplate == "" && createCertProfile == "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --subject is required (or use --template/--template-profile)"))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	keyDefaults := (&config.ConfigFile{}).GetKeyDefaults()
	certDefaults := (&config.ConfigFile{}).GetCertDefaults()
	subjectDefaults := (&config.ConfigFile{}).GetSubjectDefaults()
	if cfg != nil {
		keyDefaults = cfg.GetKeyDefaults()
		certDefaults = cfg.GetCertDefaults()
		subjectDefaults = cfg.GetSubjectDefaults()
	}

	pm := cliPasswordManager(cmd, cfg, "password", []string{createCertPassword}, 1)

	// Template options (from a cert file or a YAML profile), read with the
	// passwords known for that file so a PKCS#12 can serve as a template
	tmpl, err := cmdutil.LoadTemplateInputs(createCertTemplate, createCertProfile, pm.PasswordsForFile(createCertTemplate))
	if err != nil {
		fail(1, "Error: %v", err)
	}
	tmpl.ApplyKeyDefaults(&keyDefaults)
	tmplOpts := tmpl.Cert

	// Subject: config defaults, then template, then CLI; SANs: template unless --san
	subject, err := tmpl.ResolveSubject(subjectDefaults, createCertSubject)
	if err != nil {
		fail(1, "Error: %v", err)
	}
	sans, err := tmpl.ResolveSANs(createCertSAN, cmd.Flags().Changed("san"))
	if err != nil {
		fail(1, "Error: %v", err)
	}

	// Resolve IsCA: template provides base, CLI --ca overrides
	isCA := false
	if tmplOpts != nil {
		isCA = tmplOpts.IsCA
	}
	if cmd.Flags().Changed("ca") {
		isCA = createCertCA
	}

	// Resolve days: config default -> template -> CLI
	days := certDefaults.Days
	if isCA {
		days = certDefaults.CADays
	}
	if tmplOpts != nil && tmplOpts.Days > 0 {
		days = tmplOpts.Days
	}
	if cmd.Flags().Changed("days") {
		days = createCertDays
	}
	if days <= 0 {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --days must be a positive number"))
		os.Exit(1)
	}

	// Resolve not-before
	var notBefore time.Time
	if createCertNotBefore != "" {
		notBefore, err = parseNotBefore(createCertNotBefore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: invalid not-before: %v", err)))
			os.Exit(1)
		}
	}

	// Resolve path length: template provides base, CLI overrides
	pathLength := -1
	if tmplOpts != nil {
		pathLength = tmplOpts.PathLength
	}
	if cmd.Flags().Changed("path-length") {
		pathLength = createCertPathLength
	}

	// Resolve key usage: config default -> template -> CLI
	ku := certDefaults.KeyUsage
	if tmplOpts != nil && tmplOpts.KeyUsage != 0 {
		ku = tmplOpts.KeyUsage
	}
	if cmd.Flags().Changed("key-usage") {
		ku, err = certlib.ParseKeyUsage(createCertKeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}

	// Resolve ext key usage: config default -> template -> CLI
	eku := certDefaults.ExtKeyUsage
	if tmplOpts != nil && len(tmplOpts.ExtKeyUsage) > 0 {
		eku = tmplOpts.ExtKeyUsage
	}
	if cmd.Flags().Changed("ext-key-usage") {
		eku, err = certlib.ParseExtKeyUsage(createCertExtKeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}

	// Parse serial
	var serial *big.Int
	if createCertSerial != "" {
		serial = new(big.Int)
		_, ok := serial.SetString(createCertSerial, 16)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: invalid serial number (hex): %q", createCertSerial)))
			os.Exit(1)
		}
	}

	// Resolve output format
	var configFmt string
	if cfg != nil {
		configFmt = cfg.Defaults.Output.Format
	}
	format, err := cmdutil.ResolveOutputFormat(createCertFormat, configFmt, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Resolve key algorithm params (CLI overrides template, which overrides config)
	createCertKeyFlags.ApplyChanged(cmd, &keyDefaults)

	if err := cmdutil.ValidateKeyParams(cmd, keyDefaults.Algorithm, keyDefaults.KeySize, keyDefaults.Curve); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	var keyPasswords []certlib.TaggedPassword
	if createCertKeyFile != "" {
		keyPasswords = pm.PasswordsForFile(createCertKeyFile)
	}
	var signerPasswords []certlib.TaggedPassword
	if createCertSignKey != "" {
		signerPasswords = pm.PasswordsForFile(createCertSignKey)
	}

	encryptPw := mustEncryptKeyPassword(cmd, createCertEncrypt, "password", format)

	// Autosign: discover CA
	if createCertAutosign {
		searchDirs := certops.AutosignSearchDirs(createCertOutput)
		caResult, err := certops.FindCA(certops.FindCAOptions{
			SearchDirs: searchDirs,
			Passwords:  pm.PasswordsForFile(""),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: autosign: %v", err)))
			os.Exit(1)
		}
		createCertSignCA = caResult.CACertPath
		createCertSignKey = caResult.CAKeyPath
		signerPasswords = pm.PasswordsForFile(createCertSignKey)
		fmt.Fprintf(os.Stderr, "autosign: using CA %s + %s\n", caResult.CACertPath, caResult.CAKeyPath)
	}

	nameConstraints, ncErr := resolveNameConstraints(isCA,
		createCertPermitted, createCertExcluded, createCertNCNotCritical)
	// A profile or a cloned template can carry constraints too; explicit flags
	// win, since they are the more specific instruction.
	if nameConstraints.Empty() && tmplOpts != nil {
		nameConstraints = certlib.NameConstraintsFromGenOptions(*tmplOpts)
	}
	if ncErr != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: "+ncErr.Error()))
		os.Exit(1)
	}

	opts := certops.CreateCertOptions{
		Subject:            subject,
		SANs:               sans,
		KeyFilePath:        createCertKeyFile,
		KeyFilePasswords:   keyPasswords,
		WithKey:            createCertWithKey,
		KeyOptions:         keyDefaults,
		SignerCertPath:     createCertSignCA,
		SignerKeyPath:      createCertSignKey,
		SignerKeyPasswords: signerPasswords,
		Days:               days,
		NotBefore:          notBefore,
		IsCA:               isCA,
		PathLength:         pathLength,
		NameConstraints:    nameConstraints,
		KeyUsage:           ku,
		ExtKeyUsage:        eku,
		Serial:             serial,
		CertOutputPath:     createCertOutput,
		KeyOutputPath:      mustKeyDestination(createCertOutput, createCertKeyOutput, createCertWithKey),
		OutputFormat:       format,
		EncryptKey:         createCertEncrypt,
		KeyPassword:        encryptPw,
		Overwrite:          createCertNoConfirm,
	}

	if showOpenSSLFlag {
		renderOpenSSL(certops.OpenSSLForCreateCert(opts))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.CreateCert(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if !result.CertWritten {
		os.Stdout.Write(result.CertBytes)
		if !result.KeyWritten {
			os.Stdout.Write(result.KeyBytes)
		}
	}

	// Print summary to stderr
	certType := "leaf"
	if result.IsCA {
		certType = "CA"
	}
	signMode := "self-signed"
	if !result.IsSelfSigned {
		signMode = fmt.Sprintf("signed by %s", result.Issuer)
	}

	fmt.Fprintf(os.Stderr, "created %s certificate (%s, %s)\n", certType, result.KeyType, signMode)
	fmt.Fprintf(os.Stderr, "  subject:  %s\n", result.Subject)
	fmt.Fprintf(os.Stderr, "  issuer:   %s\n", result.Issuer)
	fmt.Fprintf(os.Stderr, "  serial:   %s\n", result.SerialHex)
	fmt.Fprintf(os.Stderr, "  validity: %s - %s\n",
		result.NotBefore.Format("2006-01-02"), result.NotAfter.Format("2006-01-02"))

	if result.CertWritten {
		fmt.Fprintf(os.Stderr, "  cert:     %s\n", result.CertPath)
	}
	if result.KeyWritten {
		fmt.Fprintf(os.Stderr, "  key:      %s\n", result.KeyPath)
	}
}

func parseNotBefore(s string) (time.Time, error) {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Try YYYY-MM-DD
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("expected YYYY-MM-DD or RFC3339 format, got %q", s)
}

// resolveNameConstraints parses the two constraint flags into one set. They only
// mean something on a CA, so asking for them on a leaf is a mistake worth
// naming rather than quietly ignoring.
func resolveNameConstraints(isCA bool, permitted, excluded string, notCritical bool) (certlib.NameConstraints, error) {
	if permitted == "" && excluded == "" {
		return certlib.NameConstraints{}, nil
	}
	if !isCA {
		return certlib.NameConstraints{}, fmt.Errorf("--permitted-names and --excluded-names apply to a CA; add --ca")
	}

	nc, err := certlib.ParseNameConstraints(permitted)
	if err != nil {
		return certlib.NameConstraints{}, err
	}
	ex, err := certlib.ParseNameConstraints(excluded)
	if err != nil {
		return certlib.NameConstraints{}, err
	}
	nc = nc.Merge(ex.Excluded())
	// RFC 5280 says the extension MUST be critical, so that is the default.
	nc.Critical = !notCritical
	return nc, nil
}
