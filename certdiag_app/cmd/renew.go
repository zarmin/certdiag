package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	renewDays      int
	renewKeyFile   string
	renewNewKey    bool
	renewKeyFlags  cmdutil.KeyGenFlags
	renewSignCA    string
	renewSignKey   string
	renewAutosign  bool
	renewOutput    string
	renewFormat    string
	renewKeyOutput string
	renewEncrypt   bool
	renewNoConfirm bool
	renewPassword  string
)

var renewCmd = &cobra.Command{
	Use:   "renew <cert-file>",
	Short: "Renew a certificate preserving its subject, SANs, and extensions",
	Long: `Renew an existing certificate by creating a new one with the same subject,
SANs, key usage and other extensions. A new serial number and validity period are generated.

By default the original private key is reused (discovered from the same file or sibling files).
Use --new-key to generate a fresh key pair, or --key-file to specify an existing key.

For self-signed certificates, the renewed cert is self-signed again.
For CA-signed certificates, provide --sign-ca/--sign-key or use --autosign.

Examples:
  certdiag renew server.crt -o server-renewed.crt
  certdiag renew server.crt --new-key -o server-renewed.crt --key-output server-renewed.key
  certdiag renew server.crt --days 730 --autosign -o server-renewed.crt
  certdiag renew ca.crt --days 3650 -o ca-renewed.crt`,
	Args: cobra.ExactArgs(1),
	Run:  runRenew,
}

func init() {
	renewCmd.Flags().IntVar(&renewDays, "days", 0, "Validity in days (default: same as original)")
	renewCmd.Flags().StringVarP(&renewKeyFile, "key-file", "k", "", "Use this private key instead of discovering one")
	renewCmd.Flags().BoolVar(&renewNewKey, "new-key", false, "Generate a new private key")
	renewKeyFlags.Register(renewCmd, " for --new-key")

	renewCmd.Flags().StringVar(&renewSignCA, "sign-ca", "", "CA certificate for signing")
	renewCmd.Flags().StringVar(&renewSignKey, "sign-key", "", "CA private key for signing")
	renewCmd.Flags().BoolVar(&renewAutosign, "autosign", false, "Auto-discover a CA in the working directory")

	renewCmd.Flags().StringVarP(&renewOutput, "output-file", "o", "", "Output certificate file (default: <name>-renewed.<ext>)")
	renewCmd.Flags().StringVarP(&renewFormat, "format", "f", "", "Output format: pem, der (default: pem)")
	renewCmd.Flags().StringVar(&renewKeyOutput, "key-output", "", "Output path for generated key")
	renewCmd.Flags().BoolVar(&renewEncrypt, "encrypt-key", false, "Encrypt generated private key")
	renewCmd.Flags().BoolVar(&renewNoConfirm, "no-confirm", false, "Overwrite output files without confirmation")
	renewCmd.Flags().StringVarP(&renewPassword, "password", "p", "", "Password for encrypted files")
	registerPasswordFileFlag(renewCmd)

	rootCmd.AddCommand(renewCmd)
}

func runRenew(cmd *cobra.Command, args []string) {
	certPath := args[0]

	if renewAutosign && (renewSignCA != "" || renewSignKey != "") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --autosign and --sign-ca/--sign-key are mutually exclusive"))
		os.Exit(1)
	}
	if (renewSignCA == "") != (renewSignKey == "") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --sign-ca and --sign-key must be specified together"))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	keyDefaults := (&config.ConfigFile{}).GetKeyDefaults()
	if cfg != nil {
		keyDefaults = cfg.GetKeyDefaults()
	}
	renewKeyFlags.ApplyChanged(cmd, &keyDefaults)

	if renewNewKey {
		if err := cmdutil.ValidateKeyParams(cmd, keyDefaults.Algorithm, keyDefaults.KeySize, keyDefaults.Curve); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}

	// Resolve output format
	format, err := cmdutil.ResolveOutputFormat(renewFormat, "", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Default output path
	outputPath := renewOutput
	if outputPath == "" {
		ext := filepath.Ext(certPath)
		base := strings.TrimSuffix(filepath.Base(certPath), ext)
		if ext == "" {
			ext = ".crt"
		}
		outputPath = filepath.Join(filepath.Dir(certPath), base+"-renewed"+ext)
	}

	// Resolve passwords
	masterPw := resolveMasterPassword(false)
	var cliPasswords []string
	if cmd.Flags().Changed("password") {
		cliPasswords = []string{renewPassword}
	}
	pm, err := cmdutil.NewSimplePasswordManager(cliPasswords, passwordFiles, cfg, masterPw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	certPasswords := pm.PasswordsForFile(certPath)
	var keyPasswords []certlib.TaggedPassword
	if renewKeyFile != "" {
		keyPasswords = pm.PasswordsForFile(renewKeyFile)
	}
	var signerPasswords []certlib.TaggedPassword
	if renewSignKey != "" {
		signerPasswords = pm.PasswordsForFile(renewSignKey)
	}

	encryptPw := mustEncryptKeyPassword(cmd, renewEncrypt, "password", format)

	opts := certops.RenewOptions{
		CertPath:           certPath,
		CertPasswords:      certPasswords,
		KeyFilePath:        renewKeyFile,
		KeyFilePasswords:   keyPasswords,
		NewKey:             renewNewKey,
		KeyOptions:         keyDefaults,
		SignerCertPath:     renewSignCA,
		SignerKeyPath:      renewSignKey,
		SignerKeyPasswords: signerPasswords,
		Days:               renewDays,
		CertOutputPath:     outputPath,
		KeyOutputPath:      mustKeyDestination(outputPath, renewKeyOutput, renewNewKey),
		OutputFormat:       format,
		EncryptKey:         renewEncrypt,
		KeyPassword:        encryptPw,
		Overwrite:          renewNoConfirm,
	}

	if renewAutosign {
		opts.AutosignDirs = certops.AutosignSearchDirs(outputPath)
		opts.AutosignPasswords = pm.PasswordsForFile("")
	}

	result, err := certops.Renew(opts)
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

	// Print summary
	certType := "leaf"
	if result.IsCA {
		certType = "CA"
	}
	signMode := "self-signed"
	if !result.IsSelfSigned {
		signMode = fmt.Sprintf("signed by %s", result.Issuer)
	}
	keyMode := "new key"
	if result.KeyReused {
		keyMode = "reused key"
	}

	fmt.Fprintf(os.Stderr, "renewed %s certificate (%s, %s, %s)\n", certType, result.KeyType, signMode, keyMode)
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
