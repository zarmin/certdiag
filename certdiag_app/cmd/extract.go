package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	extractOutputDir      string
	extractOutputFile     string
	extractOutputPassword string
	extractFormat         string
	extractPassword       string
	extractIndex          int
	extractAlias          string
	extractType           string
	extractNaming         string
	extractNoConfirm      bool
)

var extractCmd = &cobra.Command{
	Use:   "extract <input-file>",
	Short: "Extract individual items from certificate files",
	Long: `Extract individual certificates, keys, or other items from container files.

Each item is written to a separate file in the output directory.

Examples:
  certdiag extract bundle.p12 -p "pass" -d /tmp/extracted/
  certdiag extract bundle.pem -d ./certs/ --type certs
  certdiag extract keystore.jks -p "pass" --index 1
  certdiag extract bundle.p12 -p "pass" --naming "{subject}-{type}"`,
	Args: cobra.ExactArgs(1),
	Run:  runExtract,
}

func init() {
	extractCmd.Flags().StringVar(&extractOutputDir, "output-dir", ".", "Output directory")
	extractCmd.Flags().StringVarP(&extractOutputFile, "output-file", "o", "", "Output file path (single-item extraction)")
	extractCmd.Flags().StringVarP(&extractFormat, "format", "f", "pem", "Output format: pem, der, p12, p7b, jks")
	extractCmd.Flags().StringVar(&extractOutputPassword, "output-password", "", "Output password (for p12/jks)")
	extractCmd.Flags().StringVarP(&extractPassword, "password", "p", "", "Input file password")
	registerPasswordFileFlag(extractCmd)
	extractCmd.Flags().IntVar(&extractIndex, "index", 0, "Extract specific item by 1-based index")
	extractCmd.Flags().StringVar(&extractAlias, "alias", "", "Extract by alias name")
	extractCmd.Flags().StringVar(&extractType, "type", "all", "Filter: certs, keys, all")
	extractCmd.Flags().StringVar(&extractNaming, "naming", "{filename}-{index}-{type}", "Filename pattern: {filename}, {index}, {type}, {alias}, {subject}, {format}")
	extractCmd.Flags().BoolVar(&extractNoConfirm, "no-confirm", false, "Overwrite existing files without confirmation")

	rootCmd.AddCommand(extractCmd)
}

func runExtract(cmd *cobra.Command, args []string) {
	inputPath := args[0]

	outFormat, err := cmdutil.ResolveOutputFormat(extractFormat, "", extractOutputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if err := cmdutil.ValidateExtractType(extractType); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if cmd.Flags().Changed("index") && extractIndex < 1 {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --index must be >= 1"))
		os.Exit(1)
	}

	// Create output dir if needed
	if extractOutputDir != "." {
		if err := os.MkdirAll(extractOutputDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error creating output directory: %v", err)))
			os.Exit(1)
		}
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", []string{extractPassword}, 1)
	outputPw := mustOutputPassword(cmd, outFormat)

	inputPasswords := pm.PasswordsForFile(inputPath)

	opts := certops.ExtractOptions{
		InputPath:      inputPath,
		InputPasswords: inputPasswords,
		OutputDir:      extractOutputDir,
		OutputFile:     extractOutputFile,
		OutputFormat:   outFormat,
		OutputPassword: outputPw,
		Index:          extractIndex,
		Alias:          extractAlias,
		TypeFilter:     extractType,
		NamingPattern:  extractNaming,
		Overwrite:      extractNoConfirm,
	}

	result, err := certops.Extract(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "extracted %d item(s) from %s -> %s/\n",
		len(result.ExtractedFiles), inputPath, extractOutputDir)

	for _, f := range result.ExtractedFiles {
		fmt.Fprintf(os.Stderr, "  %s (%s: %s)\n", f.Path, f.Type, f.Subject)
	}
}
