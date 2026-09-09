package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"os"
)

var (
	convertOutputFile   string
	convertFormat       string
	convertPassword     string
	convertOutputPw     string
	convertAlias        string
	convertInclude      string
	convertNoConfirm    bool
	convertLegacyPKCS12 bool
)

var convertCmd = &cobra.Command{
	Use:   "convert <input-file>",
	Short: "Convert certificate files between formats",
	Long: `Convert certificate files between formats (PEM, DER, PKCS#12, PKCS#7, JKS).

Output format is inferred from the -o file extension, or set explicitly with -f.

Examples:
  certdiag convert server.crt -o server.der
  certdiag convert server.crt -o bundle.p12 --output-password "pass"
  certdiag convert keystore.p12 -p "pass" -o certs.pem
  certdiag convert certs.p7b -o certs.pem
  certdiag convert keystore.jks -p "pass" -o keystore.p12 --output-password "pass"`,
	Args: cobra.ExactArgs(1),
	Run:  runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertOutputFile, "output-file", "o", "", "Output file path (required)")
	convertCmd.Flags().StringVarP(&convertFormat, "format", "f", "", "Output format: pem, der, pkcs12, pkcs7, jks")
	convertCmd.Flags().StringVarP(&convertPassword, "password", "p", "", "Input file password")
	registerPasswordFileFlag(convertCmd)
	convertCmd.Flags().StringVar(&convertOutputPw, "output-password", "", "Output password (for p12/jks)")
	convertCmd.Flags().StringVar(&convertAlias, "alias", "", "Alias for keystore entries")
	convertCmd.Flags().StringVar(&convertInclude, "include", "all", "Filter: certs, keys, all")
	convertCmd.Flags().BoolVar(&convertNoConfirm, "no-confirm", false, "Overwrite output file without confirmation")
	convertCmd.Flags().BoolVar(&convertLegacyPKCS12, "legacy-pkcs12", false, "Use legacy PKCS#12 algorithms for compatibility")

	_ = convertCmd.MarkFlagRequired("output-file")

	markOpenSSLSupported(convertCmd)
	rootCmd.AddCommand(convertCmd)
}

func runConvert(cmd *cobra.Command, args []string) {
	inputPath := args[0]

	if convertOutputFile == "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --output-file (-o) is required"))
		os.Exit(1)
	}

	if cmd.Flags().Changed("format") && convertFormat == "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --format (-f) requires a non-empty value"))
		os.Exit(1)
	}

	outFormat, err := cmdutil.ResolveOutputFormat(convertFormat, "", convertOutputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", []string{convertPassword}, 1)
	outputPw := mustOutputPassword(cmd, outFormat)

	inputPasswords := pm.PasswordsForFile(inputPath)

	opts := certops.ConvertOptions{
		InputPath:      inputPath,
		InputPasswords: inputPasswords,
		OutputPath:     convertOutputFile,
		OutputFormat:   outFormat,
		OutputPassword: outputPw,
		Alias:          convertAlias,
		Include:        convertInclude,
		Overwrite:      convertNoConfirm,
		LegacyPKCS12:   convertLegacyPKCS12,
	}

	if showOpenSSLFlag {
		renderOpenSSL(certops.OpenSSLForConvert(opts))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.Convert(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	fmt.Fprintf(os.Stderr, "converted %s -> %s (%d items) -> %s\n",
		result.InputFormat, result.OutputFormat, result.ItemCount, result.OutputPath)
}
