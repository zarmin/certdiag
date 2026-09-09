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
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

const severityAll = "all"

var (
	checkRecursive      bool
	checkDepth          int
	checkSignatureScan  bool
	checkOutputFormat   string
	checkSeverity       string
	checkExpiryWarn     int
	checkExpiryCritical int
	checkCategory       string
	checkStrict         bool
	checkTrust          bool
	checkAIA            bool
	checkListChecks     bool
	checkRevocation     bool
	checkRevMethod      string
	checkRevRequire     bool
	checkCRLFile        string
)

var checkCmd = &cobra.Command{
	Use:   "check [paths...]",
	Short: "Run certificate health checks",
	Long: `Run comprehensive certificate health checks and validation.

Scans certificates, keys, and keystores for common issues including expired
certificates, weak keys, deprecated algorithms, missing SANs, and chain problems.

Exit codes:
  0  No issues found (at or above requested severity)
  1  WARNING-level issues found (no critical)
  2  CRITICAL-level issues found`,
	Args: cobra.ArbitraryArgs,
	Run:  runCheck,
}

func init() {
	checkCmd.Flags().BoolVarP(&checkRecursive, "recursive", "r", false, "Scan directories recursively")
	checkCmd.Flags().IntVar(&checkDepth, "depth", 0, "Maximum recursion depth (requires --recursive)")
	checkCmd.Flags().BoolVar(&checkSignatureScan, "file-signature-scan", false, "Detect certs by magic bytes, not just extension")
	checkCmd.Flags().StringVarP(&checkOutputFormat, "output", "o", "human", "Output format: human, json, yaml")
	checkCmd.Flags().StringVar(&checkSeverity, "severity", "all", "Minimum severity to show: all, info, warning, critical")
	checkCmd.Flags().IntVar(&checkExpiryWarn, "expiry-warn", 0, "Warn about certs expiring within N days (default 30)")
	checkCmd.Flags().IntVar(&checkExpiryCritical, "expiry-critical", 0, "Critical alert for certs expiring within N days (default 7)")
	checkCmd.Flags().StringVar(&checkCategory, "category", "", "Run only specific check categories (comma-separated)")
	checkCmd.Flags().BoolVar(&checkStrict, "strict", false, "Fail on any finding at WARNING or above")
	checkCmd.Flags().BoolVar(&checkTrust, "trust", false, "Evaluate whether this machine trusts each certificate (enables the trust checks)")
	checkCmd.Flags().BoolVar(&checkAIA, "aia", false, "Fetch missing issuers over AIA (network; implies --trust)")
	checkCmd.Flags().BoolVar(&aiaRefresh, "aia-refresh", false, "Ignore the AIA cache for this run")
	checkCmd.Flags().BoolVar(&checkListChecks, "list-checks", false, "List all available checks and exit")
	checkCmd.Flags().BoolVar(&checkRevocation, "revocation", false, "Enable revocation checking (live OCSP/CRL; network, opt-in). Live OCSP discloses the inspected certificate to the CA.")
	checkCmd.Flags().StringVar(&checkRevMethod, "revocation-method", "auto", "Revocation method: auto, ocsp, crl")
	checkCmd.Flags().BoolVar(&checkRevRequire, "revocation-require", false, "Treat undetermined revocation status as critical")
	checkCmd.Flags().StringVar(&checkCRLFile, "crl-file", "", "Check against a local CRL file instead of downloading (offline)")

	registerPasswordFlags(checkCmd, passwordFlagOpts{prompt: true, noTryAll: true})
	checkCmd.Flags().BoolVarP(&discover, "discover", "D", false, "Discover related files in same directory")

	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) {
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	var disabledChecks []string
	expiryWarn := checkExpiryWarn
	expiryCritical := checkExpiryCritical
	if cfg != nil {
		disabledChecks = cfg.Defaults.Check.DisabledChecks
		expiryWarn = resolveExpiryThreshold(checkExpiryWarn, cfg.Defaults.Check.ExpiryWarnDays)
		expiryCritical = resolveExpiryThreshold(checkExpiryCritical, cfg.Defaults.Check.ExpiryCriticalDays)
	}

	if err := cmdutil.ValidateDisplayFormat(checkOutputFormat, cmdutil.OutputHuman, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
	if !strings.EqualFold(checkSeverity, severityAll) {
		if _, err := cmdutil.ParseCheckSeverity(checkSeverity); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
	}

	if checkListChecks {
		cmdutil.EmitStructured(checkOutputFormat,
			func() string { return output.FormatCheckListHuman(disabledChecks) },
			func() string { return output.FormatCheckListJSON(disabledChecks) },
			func() string { return output.FormatCheckListYAML(disabledChecks) },
		)
		return
	}

	if len(args) == 0 {
		cmd.Help()
		return
	}

	if checkDepth > 0 && !checkRecursive {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: --depth requires --recursive"))
		os.Exit(1)
	}

	// Prompt for the master password only when the config holds something
	// it would unlock; otherwise -i is about file passwords alone.
	var masterPw []byte
	if cfg != nil && cfg.HasEncryptedPasswords() {
		masterPw = resolveMasterPassword(interactivePrompt)
	}

	pm, err := password.NewPasswordManager(password.PasswordManagerOpts{
		CLIPasswords:   passwords,
		PasswordFiles:  passwordFiles,
		Config:         cfg,
		MasterPassword: masterPw,
		NoTryAll:       noTryAllPasswords,
		Interactive:    interactivePrompt,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	scanOpts := certlib.ScanOptions{
		Recursive:        checkRecursive,
		MaxDepth:         checkDepth,
		UseSignatureScan: checkSignatureScan,
		PasswordProvider: pm,
	}
	if pm.IsInteractive() {
		scanOpts.InteractiveRetry = pm.HandleInteractive
	}

	minSev := resolveCheckSeverity(checkSeverity)

	var categories []string
	if checkCategory != "" {
		categories = strings.Split(checkCategory, ",")
	}

	checkOpts := certlib.CheckOptions{
		ExpiryWarnDays:     expiryWarn,
		ExpiryCriticalDays: expiryCritical,
		MinSeverity:        minSev,
		Categories:         categories,
		DisabledChecks:     disabledChecks,
	}

	revCfg, err := buildRevocationConfig(cmd, checkRevocation, checkRevMethod, checkRevRequire, checkCRLFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	trustEnabled := checkTrust
	if !trustEnabled && cfg != nil && cfg.Defaults.Output.Trust {
		trustEnabled = true
	}

	scanResult := certops.Scan(certops.ScanOptions{
		Paths:        args,
		Scan:         scanOpts,
		Discover:     discover,
		Check:        true,
		CheckOptions: checkOpts,
		Revocation:   revCfg,
		Trust: certops.TrustConfig{
			Enabled:    trustEnabled || checkAIA,
			BundleDir:  bundleDirOrEmpty(),
			Passwords:  pm.PasswordsForFile(""),
			AIA:        checkAIA,
			AIAOptions: aiaOptions(cfg),
		},
	})
	store := scanResult.Store
	relIndex := scanResult.RelIndex
	result := scanResult.CheckResult
	scanErrors := scanResult.ParseErrors
	pathErrors := scanResult.PathErrors

	cmdutil.EmitStructured(checkOutputFormat,
		func() string {
			hiddenInfo := 0
			if minSev == certlib.SeverityWarning {
				// Re-run without filter to count info. Reuse the effective options
				// (incl. revocation) so the recomputation matches the main run.
				unfilteredOpts := scanResult.CheckOptions
				unfilteredOpts.MinSeverity = ""
				unfiltered := certlib.RunChecks(store, relIndex, unfilteredOpts)
				hiddenInfo = unfiltered.Summary.Info
			}
			return output.FormatCheckHuman(result, hiddenInfo)
		},
		func() string { return output.FormatCheckJSON(result) },
		func() string { return output.FormatCheckYAML(result) },
	)

	printSkipped(scanResult.Skipped, 1)

	reportErrors := pathErrors
	if !checkSignatureScan {
		reportErrors = append(reportErrors, scanErrors...)
	}
	if len(reportErrors) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, output.ColorizeError("Errors:"))
		for _, e := range reportErrors {
			fmt.Fprintf(os.Stderr, "  %s\n", output.ColorizeError(e))
		}
	}

	strictSummary := result.Summary
	if checkStrict && minSev == certlib.SeverityCritical {
		// Reuse the effective options so revocation warnings (computed inside
		// Scan, not present on the CLI-built checkOpts) are visible to the
		// strict re-run - otherwise --strict would silently drop them.
		strictOpts := scanResult.CheckOptions
		strictOpts.MinSeverity = certlib.SeverityWarning
		strictSummary = certlib.RunChecks(store, relIndex, strictOpts).Summary
	}

	exitCode := checkExitCode(len(reportErrors) > 0, result.Summary, checkStrict, strictSummary)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func checkExitCode(hasScanErrors bool, summary certlib.CheckSummary, strict bool, strictSummary certlib.CheckSummary) int {
	exitCode := 0
	if hasScanErrors {
		exitCode = 2
	}
	if summary.Critical > 0 && exitCode < 2 {
		exitCode = 2
	}
	if summary.Warning > 0 && exitCode < 1 {
		exitCode = 1
	}
	if strict && (strictSummary.Warning > 0 || strictSummary.Critical > 0) && exitCode < 2 {
		exitCode = 2
	}
	return exitCode
}

func resolveExpiryThreshold(flagValue, configValue int) int {
	if flagValue == 0 && configValue > 0 {
		return configValue
	}
	return flagValue
}

func resolveCheckSeverity(sev string) certlib.CheckSeverity {
	s, err := cmdutil.ParseCheckSeverity(sev)
	if err != nil {
		return ""
	}
	return s
}
