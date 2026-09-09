package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

var (
	diffDetails     int
	diffOutputFmt   string
	diffIndex       string
	diffOnlyChanges bool
)

var diffCmd = &cobra.Command{
	Use:   "diff <file1> <file2>",
	Short: "Compare two certificates side by side",
	Long: `Compare two certificates field by field, showing what changed.

Exit codes:
  0  Certificates are identical
  1  Certificates differ
  2  Error (file not found, parse error, bad index)`,
	Args: cobra.ExactArgs(2),
	Run:  runDiff,
}

func init() {
	diffCmd.Flags().CountVarP(&diffDetails, "details", "d", "Include extended fields (fingerprints, key IDs, AIA, CRL)")
	diffCmd.Flags().StringVarP(&diffOutputFmt, "output", "o", "human", "Output format: human, json, yaml")
	diffCmd.Flags().StringVar(&diffIndex, "index", "1:1", "Compare specific items by index (1-based), e.g. 2:1")
	diffCmd.Flags().BoolVar(&diffOnlyChanges, "only-changes", false, "Hide fields that are the same")

	registerPasswordFlags(diffCmd, passwordFlagOpts{prompt: true})

	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) {
	if err := cmdutil.ValidateDisplayFormat(diffOutputFmt, cmdutil.OutputHuman, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	leftIdx, rightIdx, err := parseDiffIndex(diffIndex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 2)

	var masterPw []byte
	if cfg != nil && cfg.HasEncryptedPasswords() {
		masterPw = resolveMasterPassword(interactivePrompt)
	}

	pm, err := password.NewPasswordManager(password.PasswordManagerOpts{
		CLIPasswords:   passwords,
		PasswordFiles:  passwordFiles,
		Config:         cfg,
		MasterPassword: masterPw,
		Interactive:    interactivePrompt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	scanOpts := certlib.ScanOptions{
		PasswordProvider: pm,
	}
	if pm.IsInteractive() {
		scanOpts.InteractiveRetry = pm.HandleInteractive
	}

	leftItem, leftSource, err := scanAndExtractCert(args[0], leftIdx, "left", scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	rightItem, rightSource, err := scanAndExtractCert(args[1], rightIdx, "right", scanOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	result := certlib.CompareCertificates(leftItem.Certificate, rightItem.Certificate, diffDetails >= 1)
	result.Left = leftSource
	result.Right = rightSource

	opts := output.DiffOutputOptions{
		OnlyChanges:       diffOnlyChanges,
		FingerprintFormat: resolveFingerprintFormat(cfg),
	}

	cmdutil.EmitStructured(diffOutputFmt,
		func() string { return output.FormatDiffHuman(result, opts) },
		func() string { return output.FormatDiffJSON(result, opts) },
		func() string { return output.FormatDiffYAML(result, opts) },
	)

	if !result.Identical() {
		os.Exit(1)
	}
}

func parseDiffIndex(s string) (int, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid --index format %q, expected LEFT:RIGHT (e.g. 1:1)", s)
	}
	left, err := strconv.Atoi(parts[0])
	if err != nil || left < 1 {
		return 0, 0, fmt.Errorf("invalid left index %q, must be a positive integer", parts[0])
	}
	right, err := strconv.Atoi(parts[1])
	if err != nil || right < 1 {
		return 0, 0, fmt.Errorf("invalid right index %q, must be a positive integer", parts[1])
	}
	return left - 1, right - 1, nil
}

func scanAndExtractCert(path string, certIndex int, label string, scanOpts certlib.ScanOptions) (*certlib.CertItem, certlib.DiffSource, error) {
	store, err := certlib.ScanPathWithOptions(path, scanOpts)
	if err != nil {
		return nil, certlib.DiffSource{}, fmt.Errorf("%s file: %v", label, err)
	}

	if len(store.Containers) == 0 {
		return nil, certlib.DiffSource{}, fmt.Errorf("%s file %q: no data found", label, path)
	}

	var certs []*certlib.CertItem
	var container *certlib.CertContainer
	for ci := range store.Containers {
		c := &store.Containers[ci]
		for ii := range c.Items {
			item := &c.Items[ii]
			if item.Type == certlib.ContentCertificate && item.Certificate != nil {
				certs = append(certs, item)
				if container == nil {
					container = c
				}
			}
		}
	}

	if len(certs) == 0 {
		return nil, certlib.DiffSource{}, fmt.Errorf("%s file %q contains no certificates", label, path)
	}

	if certIndex >= len(certs) {
		return nil, certlib.DiffSource{}, fmt.Errorf("%s file %q has %d certificate(s), requested index %d", label, path, len(certs), certIndex+1)
	}

	item := certs[certIndex]
	source := certlib.DiffSource{
		FilePath:  path,
		ItemIndex: certIndex,
		Alias:     item.Alias,
		Format:    string(container.Format),
	}

	return item, source, nil
}
