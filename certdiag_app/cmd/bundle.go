package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	bundleOutput       string
	bundleFormat       string
	bundleOutputPw     string
	bundleAutoChain    bool
	bundleAutoAssemble string
	bundleIncludeRoot  bool
	bundleAlias        string
	bundlePassword     string
	bundleNoConfirm    bool
	bundleLegacyPKCS12 bool
)

var bundleCmd = &cobra.Command{
	Use:   "bundle [files...]",
	Short: "Bundle certificates, keys and CA chains into a single file",
	Long: `Bundle multiple certificate and key files into a single output file.
Supports PEM, PKCS#12, PKCS#7, and JKS output formats.

Use --auto-chain to automatically order certificates in chain order (leaf first, root last).
Use --auto-assemble to scan a directory and automatically find a leaf cert, its key, and chain.

Examples:
  certdiag bundle server.crt ca.crt -o chain.pem
  certdiag bundle server.crt server.key ca.crt --auto-chain -o server.p12 --output-password "pass"
  certdiag bundle --auto-assemble /path/to/certs -o server.p12 --output-password "pass"
  certdiag bundle server.crt ca.crt -o chain.p7b`,
	Args: cobra.ArbitraryArgs,
	Run:  runBundle,
}

func init() {
	bundleCmd.Flags().StringVarP(&bundleOutput, "output-file", "o", "", "Output file path (required)")
	bundleCmd.Flags().StringVarP(&bundleFormat, "format", "f", "", "Output format: pem, pkcs12, pkcs7, jks")
	bundleCmd.Flags().StringVar(&bundleOutputPw, "output-password", "", "Output password (for p12/jks)")
	bundleCmd.Flags().BoolVar(&bundleAutoChain, "auto-chain", false, "Automatically order certificates in chain order")
	bundleCmd.Flags().StringVar(&bundleAutoAssemble, "auto-assemble", "", "Scan directory to auto-assemble chain + key")
	bundleCmd.Flags().BoolVar(&bundleIncludeRoot, "include-root", true, "Include root CA in bundle")
	bundleCmd.Flags().StringVar(&bundleAlias, "alias", "", "Alias for keystore entries")
	bundleCmd.Flags().StringVarP(&bundlePassword, "password", "p", "", "Input file password")
	registerPasswordFileFlag(bundleCmd)
	bundleCmd.Flags().BoolVar(&bundleNoConfirm, "no-confirm", false, "Overwrite output file without confirmation")
	bundleCmd.Flags().BoolVar(&bundleLegacyPKCS12, "legacy-pkcs12", false, "Use legacy PKCS#12 algorithms for compatibility")

	_ = bundleCmd.MarkFlagRequired("output-file")

	rootCmd.AddCommand(bundleCmd)
}

func runBundle(cmd *cobra.Command, args []string) {
	if len(args) == 0 && bundleAutoAssemble == "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: provide input files or --auto-assemble directory"))
		os.Exit(1)
	}
	if len(args) > 0 && bundleAutoAssemble != "" {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: cannot use both input files and --auto-assemble"))
		os.Exit(1)
	}

	outFormat, err := cmdutil.ResolveOutputFormat(bundleFormat, "", bundleOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", []string{bundlePassword}, 1)
	outputPw := mustOutputPassword(cmd, outFormat)

	// Collect passwords from all input files
	var inputPasswords []certlib.TaggedPassword
	for _, path := range args {
		pws := pm.PasswordsForFile(path)
		inputPasswords = append(inputPasswords, pws...)
	}
	if bundleAutoAssemble != "" {
		inputPasswords = pm.PasswordsForFile("")
	}

	opts := certops.BundleOptions{
		InputPaths:      args,
		InputPasswords:  inputPasswords,
		AutoAssembleDir: bundleAutoAssemble,
		AutoChain:       bundleAutoChain,
		IncludeRoot:     bundleIncludeRoot,
		OutputPath:      bundleOutput,
		OutputFormat:    outFormat,
		OutputPassword:  outputPw,
		Alias:           bundleAlias,
		LegacyPKCS12:    bundleLegacyPKCS12,
		Overwrite:       bundleNoConfirm,
	}

	result, err := certops.Bundle(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	fmt.Fprintf(os.Stderr, "bundled %d items -> %s (%s)\n", result.ItemCount, result.OutputPath, outFormat)
	if len(result.ChainOrder) > 0 {
		display := make([]string, len(result.ChainOrder))
		for i, cn := range result.ChainOrder {
			display[len(result.ChainOrder)-1-i] = cn
		}
		fmt.Fprintf(os.Stderr, "  chain: %s\n", strings.Join(display, " -> "))
	}
}
