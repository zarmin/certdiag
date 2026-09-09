package cmd

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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
	signCACert      string
	signCAKey       string
	signDays        int
	signNotBefore   string
	signCA          bool
	signPathLength  int
	signKeyUsage    string
	signExtKeyUsage string
	signSerial      string
	signOutput      string
	signFormat      string
	signNoConfirm   bool
	signPassword    string
	signAutosign    bool
)

var signCmd = &cobra.Command{
	Use:   "sign <csr-file>",
	Short: "Sign a CSR with a CA certificate",
	Long: `Sign a PKCS#10 Certificate Signing Request with a CA certificate and key.

The CSR file is given as a positional argument. CA cert and key are required (--ca-cert, --ca-key)
or auto-discovered with --autosign.

Examples:
  certdiag sign request.csr --ca-cert ca.crt --ca-key ca.key -o signed.crt
  certdiag sign request.csr --ca-cert ca.crt --ca-key ca.key --days 730 -o signed.crt
  certdiag sign request.csr --ca-cert ca.crt --ca-key ca.key --ca -o sub-ca.crt
  certdiag sign request.csr --autosign -o signed.crt`,
	Args: cobra.ExactArgs(1),
	Run:  runSign,
}

func init() {
	signCmd.Flags().StringVar(&signCACert, "ca-cert", "", "CA certificate file (required)")
	signCmd.Flags().StringVar(&signCAKey, "ca-key", "", "CA private key file (required)")
	signCmd.Flags().IntVar(&signDays, "days", 0, "Validity in days (default: 365 leaf, 3650 CA)")
	signCmd.Flags().StringVar(&signNotBefore, "not-before", "", "Not-before date (YYYY-MM-DD or RFC3339)")
	signCmd.Flags().BoolVar(&signCA, "ca", false, "Sign as a CA certificate")
	signCmd.Flags().IntVar(&signPathLength, "path-length", -1, "CA path length constraint (-1=unconstrained)")
	signCmd.Flags().StringVar(&signKeyUsage, "key-usage", "", "Key usage (comma-separated): "+strings.Join(certlib.KeyUsageNames, ", "))
	signCmd.Flags().StringVar(&signExtKeyUsage, "ext-key-usage", "", "Extended key usage (comma-separated): "+strings.Join(certlib.ExtKeyUsageNames, ", "))
	signCmd.Flags().StringVar(&signSerial, "serial", "", "Certificate serial number (hex)")

	signCmd.Flags().StringVarP(&signOutput, "output-file", "o", "", "Output certificate file (default: stdout)")
	signCmd.Flags().StringVarP(&signFormat, "format", "f", "", "Output format: pem, der (default: pem)")
	signCmd.Flags().BoolVar(&signNoConfirm, "no-confirm", false, "Overwrite output file without confirmation")
	signCmd.Flags().StringVarP(&signPassword, "password", "p", "", "Password for encrypted key files")
	registerPasswordFileFlag(signCmd)
	signCmd.Flags().BoolVar(&signAutosign, "autosign", false, "Auto-discover a CA in the working directory")

	markOpenSSLSupported(signCmd)
	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) {
	csrPath := args[0]

	// Validate CA flags
	if signAutosign && (signCACert != "" || signCAKey != "") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --autosign and --ca-cert/--ca-key are mutually exclusive"))
		os.Exit(1)
	}
	if !signAutosign && (signCACert == "" || signCAKey == "") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --ca-cert and --ca-key are required (or use --autosign)"))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	var err error

	certDefaults := (&config.ConfigFile{}).GetCertDefaults()
	if cfg != nil {
		certDefaults = cfg.GetCertDefaults()
	}

	// Resolve days
	days := certDefaults.Days
	if signCA {
		days = certDefaults.CADays
	}
	if cmd.Flags().Changed("days") {
		days = signDays
	}
	if days <= 0 {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --days must be a positive number"))
		os.Exit(1)
	}

	// Resolve not-before
	var notBefore time.Time
	if signNotBefore != "" {
		notBefore, err = parseNotBefore(signNotBefore)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: invalid not-before: %v", err)))
			os.Exit(1)
		}
	}

	// Resolve key usage
	ku := certDefaults.KeyUsage
	if cmd.Flags().Changed("key-usage") {
		ku, err = certlib.ParseKeyUsage(signKeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}
	eku := certDefaults.ExtKeyUsage
	if cmd.Flags().Changed("ext-key-usage") {
		eku, err = certlib.ParseExtKeyUsage(signExtKeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}

	// Parse serial
	var serial *big.Int
	if signSerial != "" {
		serial = new(big.Int)
		_, ok := serial.SetString(signSerial, 16)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: invalid serial number (hex): %q", signSerial)))
			os.Exit(1)
		}
	}

	// Resolve output format
	var configFmt string
	if cfg != nil {
		configFmt = cfg.Defaults.Output.Format
	}
	format, err := cmdutil.ResolveOutputFormat(signFormat, configFmt, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Resolve passwords
	masterPw := resolveMasterPassword(false)
	var cliPasswords []string
	if cmd.Flags().Changed("password") {
		cliPasswords = []string{signPassword}
	}
	pm, err := cmdutil.NewSimplePasswordManager(cliPasswords, passwordFiles, cfg, masterPw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Autosign: discover CA
	if signAutosign {
		searchDirs := certops.AutosignSearchDirs(signOutput)
		// Also search near the CSR file
		csrDir, err := filepath.Abs(filepath.Dir(csrPath))
		if err == nil {
			found := false
			for _, d := range searchDirs {
				if d == csrDir {
					found = true
					break
				}
			}
			if !found {
				searchDirs = append(searchDirs, csrDir)
			}
		}
		caResult, err := certops.FindCA(certops.FindCAOptions{
			SearchDirs: searchDirs,
			Passwords:  pm.PasswordsForFile(""),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: autosign: %v", err)))
			os.Exit(1)
		}
		signCACert = caResult.CACertPath
		signCAKey = caResult.CAKeyPath
		fmt.Fprintf(os.Stderr, "autosign: using CA %s + %s\n", caResult.CACertPath, caResult.CAKeyPath)
	}

	caKeyPasswords := pm.PasswordsForFile(signCAKey)

	opts := certops.SignCSROptions{
		CSRPath:        csrPath,
		CACertPath:     signCACert,
		CAKeyPath:      signCAKey,
		CAKeyPasswords: caKeyPasswords,
		Days:           days,
		NotBefore:      notBefore,
		IsCA:           signCA,
		PathLength:     signPathLength,
		KeyUsage:       ku,
		ExtKeyUsage:    eku,
		Serial:         serial,
		CertOutputPath: signOutput,
		OutputFormat:   format,
		Overwrite:      signNoConfirm,
	}

	if showOpenSSLFlag {
		renderOpenSSL(certops.OpenSSLForSignCSR(opts))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.SignCSR(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if !result.CertWritten {
		os.Stdout.Write(result.CertBytes)
	}

	certType := "leaf"
	if result.IsCA {
		certType = "CA"
	}
	fmt.Fprintf(os.Stderr, "signed %s certificate\n", certType)
	fmt.Fprintf(os.Stderr, "  subject:  %s\n", result.Subject)
	fmt.Fprintf(os.Stderr, "  issuer:   %s\n", result.Issuer)
	fmt.Fprintf(os.Stderr, "  serial:   %s\n", result.SerialHex)
	fmt.Fprintf(os.Stderr, "  validity: %s - %s\n",
		result.NotBefore.Format("2006-01-02"), result.NotAfter.Format("2006-01-02"))
	if result.CertWritten {
		fmt.Fprintf(os.Stderr, "  cert:     %s\n", result.CertPath)
	}
	for _, note := range result.Notes {
		fmt.Fprintf(os.Stderr, "  note:     %s\n", note)
	}
}
