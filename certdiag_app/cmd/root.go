package cmd

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
	"golang.org/x/term"
)

var (
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

var (
	passwords             []string
	passwordFiles         []string
	recursive             bool
	depth                 int
	signatureScan         bool
	tableView             bool
	details               int
	aiaEnabled            bool
	aiaRefresh            bool
	insecure              bool
	query                 string
	outputFormat          string
	noTryAllPasswords     bool
	masterPasswordFlag    string
	interactivePrompt     bool
	configFile            string
	discover              bool
	inlineCheck           bool
	expiryWarn            int
	expiryCritical        int
	globalNoColor         bool
	fingerprintFormatFlag string
	relationships         bool
	noRelationships       bool
	trustFlag             bool
)

var rootCmd = &cobra.Command{
	Use:     "certdiag [paths...]",
	Short:   "Certificate diagnostic tool",
	Long:    GetLongDescription(),
	Example: GetColorsHelp(),
	Version: Version,
	Args:    cobra.ArbitraryArgs,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if globalNoColor {
			os.Setenv("NO_COLOR", "1")
			output.InitColors()
		}
		if manualFlag {
			showManual(cmd.Root())
			os.Exit(0)
		}
		return validateOpenSSLFlags(cmd)
	},
	Run: runRoot,
}

// detailLevel folds the -d count and --insecure-details into one level:
// --insecure-details on its own still implies -d.
func detailLevel(count int, insecure bool) int {
	if count == 0 && insecure {
		return 1
	}
	return count
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	registerPasswordFlags(rootCmd, passwordFlagOpts{prompt: true, noTryAll: true})
	rootCmd.PersistentFlags().StringVar(&masterPasswordFlag, "master-password", "", "Master password for decrypting encrypted config passwords")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config-file", "c", "", "Path to config file")
	rootCmd.PersistentFlags().BoolVar(&globalNoColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&manualFlag, "manual", false, "Display the full manual (via pager)")
	rootCmd.PersistentFlags().BoolVar(&showOpenSSLFlag, "show-openssl", false, "Print the equivalent openssl command alongside the operation")
	rootCmd.PersistentFlags().BoolVar(&dryRunFlag, "dry-run", false, "With --show-openssl, print the command only and perform no work")
	rootCmd.PersistentFlags().StringVar(&fingerprintFormatFlag, "fingerprint-format", "", "Fingerprint display format: hex, hex-colon, base64 (display only; JSON/YAML always use hex)")
	markOpenSSLSupported(rootCmd)

	registerScanFlags(rootCmd)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(schemaCmd)
	rootCmd.AddCommand(tuiCmd)
}

func runRoot(cmd *cobra.Command, args []string) {
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	if len(args) == 0 {
		cmd.Help()
		return
	}

	localPaths, remoteTargets := classifyRootArgs(args)
	if len(remoteTargets) > 0 && len(localPaths) > 0 {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: cannot mix local files and remote targets in one invocation"))
		os.Exit(1)
	}
	if len(remoteTargets) > 0 {
		settings, rerr := loadRemoteSettings()
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(rerr.Error()))
			os.Exit(1)
		}
		// Reject filesystem-scan flags that have no meaning for a remote target,
		// rather than silently ignoring them.
		for _, f := range []string{"recursive", "depth", "check", "query", "trust", "aia", "aia-refresh", "discover", "file-signature-scan"} {
			if cmd.Flags().Changed(f) {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: --%s does not apply to remote targets", f)))
				os.Exit(1)
			}
		}
		// Map the flags that do have a remote equivalent onto the remote vars.
		if cmd.Flags().Changed("expiry-warn") {
			remoteExpiryWarn = expiryWarn
		}
		if cmd.Flags().Changed("details") {
			remoteDetails = details
		}
		if tableView {
			fmt.Fprintln(os.Stderr, output.ColorizeError("Error: remote targets support only json or yaml output (omit -o for human-readable); table is not supported"))
			os.Exit(1)
		}
		rof, ferr := rootFormatToRemote(outputFormat)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: "+ferr.Error()))
			os.Exit(1)
		}
		remoteOutputFormat = rof
		validateRemoteTargets(remoteTargets)
		runRemoteFetch(remoteTargets, settings, true)
		return
	}

	if depth > 0 && !recursive {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: --depth requires --recursive"))
		os.Exit(1)
	}

	var masterPw []byte
	if cfg != nil && cfg.HasEncryptedPasswords() {
		masterPw = resolveMasterPassword(interactivePrompt)
		if len(masterPw) > 0 {
			fmt.Fprintln(os.Stderr, "master password: OK")
		} else {
			fmt.Fprintln(os.Stderr, "master password: not provided")
		}
	}

	for _, pf := range passwordFiles {
		if _, err := os.Stat(pf); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: password file not found: %s", pf)))
			os.Exit(1)
		}
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
		Recursive:        recursive,
		MaxDepth:         depth,
		UseSignatureScan: signatureScan,
		PasswordProvider: pm,
	}

	if pm.IsInteractive() {
		scanOpts.InteractiveRetry = pm.HandleInteractive
	}

	opts := output.OutputOptions{
		DetailLevel:       detailLevel(details, insecure),
		InsecureDetails:   insecure,
		HighlightQuery:    query,
		FingerprintFormat: resolveFingerprintFormat(cfg),
	}

	var checkOpts certlib.CheckOptions
	if inlineCheck {
		checkOpts = certlib.CheckOptions{
			ExpiryWarnDays:     expiryWarn,
			ExpiryCriticalDays: expiryCritical,
		}
		if cfg != nil {
			if checkOpts.ExpiryWarnDays == 0 && cfg.Defaults.Check.ExpiryWarnDays > 0 {
				checkOpts.ExpiryWarnDays = cfg.Defaults.Check.ExpiryWarnDays
			}
			if checkOpts.ExpiryCriticalDays == 0 && cfg.Defaults.Check.ExpiryCriticalDays > 0 {
				checkOpts.ExpiryCriticalDays = cfg.Defaults.Check.ExpiryCriticalDays
			}
			checkOpts.DisabledChecks = cfg.Defaults.Check.DisabledChecks
		}
	}

	trustEnabled := trustFlag
	if !trustEnabled && cfg != nil && cfg.Defaults.Output.Trust {
		trustEnabled = true
	}

	// AIA reaches the network, so it happens only when asked, and asking for it
	// is asking a trust question.
	aiaOn := aiaEnabled || aiaRefresh
	if !aiaOn && cfg != nil && cfg.Defaults.AIA.Enabled {
		aiaOn = true
	}
	if aiaOn {
		trustEnabled = true
	}

	scanResult := certops.Scan(certops.ScanOptions{
		Paths:          args,
		Scan:           scanOpts,
		Discover:       discover,
		AssembleChains: true,
		Check:          inlineCheck,
		CheckOptions:   checkOpts,
		Trust: certops.TrustConfig{
			Enabled:    trustEnabled,
			BundleDir:  bundleDirOrEmpty(),
			Passwords:  pm.PasswordsForFile(""),
			AIA:        aiaOn,
			AIAOptions: aiaOptions(cfg),
		},
	})
	store := scanResult.Store
	errors := scanResult.ParseErrors
	pathErrors := scanResult.PathErrors
	opts.Skipped = scanResult.Skipped

	if showOpenSSLFlag {
		renderOpenSSL(buildInspectOpenSSL(store))
		if dryRunFlag {
			return
		}
	}

	if scanResult.TrustIndex != nil {
		opts.TrustIndex = scanResult.TrustIndex
		presence := scanResult.StorePresence
		opts.StoreTags = func(cert *x509.Certificate) []string {
			return presence.TagsFor(cert)
		}
	}
	for _, w := range scanResult.TrustWarnings {
		fmt.Fprintf(os.Stderr, "certdiag: trust: %s\n", w)
	}

	showRelationships := relationships && !noRelationships
	if showRelationships && scanResult.RelIndex != nil {
		opts.RelationIndex = scanResult.RelIndex
		opts.Chains = scanResult.Chains
		opts.ChainsContaining = scanResult.ChainsContaining
		opts.Store = store
	}
	if inlineCheck {
		opts.CheckResult = scanResult.CheckResult
	}

	type indexedContainer struct {
		container *certlib.CertContainer
		storeIdx  int
	}

	var allContainers []*certlib.CertContainer
	var indexed []indexedContainer
	for i := range store.Containers {
		c := &store.Containers[i]
		if c.RelationsOnly {
			continue
		}
		allContainers = append(allContainers, c)
		indexed = append(indexed, indexedContainer{container: c, storeIdx: i})
	}

	format, err := resolveFormat(outputFormat, tableView)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
		os.Exit(1)
	}

	if query != "" {
		allContainers = certlib.FilterContainers(allContainers, query)
		filtered := make(map[*certlib.CertContainer]bool)
		for _, c := range allContainers {
			filtered[c] = true
		}
		var newIndexed []indexedContainer
		for _, ic := range indexed {
			if filtered[ic.container] {
				newIndexed = append(newIndexed, ic)
			}
		}
		indexed = newIndexed
	}

	if strings.HasPrefix(format, cmdutil.OutputJSONPathPrefix) {
		expr := strings.TrimPrefix(format, cmdutil.OutputJSONPathPrefix)
		result, jerr := cmdutil.EvalJSONPath([]byte(output.FormatJSONView(allContainers, opts)), expr)
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(jerr.Error()))
			os.Exit(1)
		}
		fmt.Println(result)
	} else {
		switch format {
		case cmdutil.OutputTable:
			formatted := output.FormatTableView(allContainers, opts)
			highlighted := output.HighlightMatches(formatted, query)
			fmt.Print(highlighted)
		case cmdutil.OutputYAML:
			fmt.Print(output.FormatYAMLView(allContainers, opts))
		case cmdutil.OutputJSON:
			fmt.Print(output.FormatJSONView(allContainers, opts))
		default:
			for _, ic := range indexed {
				formatted := output.FormatListView(ic.container, ic.storeIdx, opts)
				highlighted := output.HighlightMatches(formatted, query)
				fmt.Print(highlighted)
				fmt.Println()
			}
		}
	}

	printSkipped(scanResult.Skipped, details)

	reportErrors := pathErrors
	if !signatureScan {
		reportErrors = append(reportErrors, errors...)
	}
	if len(reportErrors) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, output.ColorizeError("Errors:"))
		for _, e := range reportErrors {
			fmt.Fprintf(os.Stderr, "  %s\n", output.ColorizeError(e))
		}
		os.Exit(1)
	}
}

func flagPassword(cmd *cobra.Command, flagName string) ([]byte, bool) {
	return cmdutil.FlagPassword(cmd, flagName)
}

func resolveMasterPassword(allowPrompt bool) []byte {
	if masterPasswordFlag != "" {
		fmt.Fprintln(os.Stderr, output.ColorizeWarning("Warning: master password provided via --master-password is visible in process listing"))
		return []byte(masterPasswordFlag)
	}

	if env := os.Getenv("CERTDIAG_MASTER_KEY"); env != "" {
		return []byte(env)
	}

	if allowPrompt && term.IsTerminal(int(os.Stdin.Fd())) {
		pw, err := password.PromptPassword("Enter master password: ")
		if err != nil {
			return nil
		}
		return pw
	}

	return nil
}

func resolveFormat(format string, tableFlag bool) (string, error) {
	if format != "" && tableFlag {
		return "", fmt.Errorf("cannot use both --output and -t flags")
	}
	if format != "" {
		if strings.HasPrefix(format, cmdutil.OutputJSONPathPrefix) {
			return format, nil
		}
		switch format {
		case cmdutil.OutputList, cmdutil.OutputTable, cmdutil.OutputYAML, cmdutil.OutputJSON:
			return format, nil
		default:
			return "", fmt.Errorf("unknown output format %q (valid: list, table, yaml, json, jsonpath=EXPR)", format)
		}
	}
	if tableFlag {
		return "table", nil
	}
	return "list", nil
}

// resolveFingerprintFormat applies the precedence flag > config > hex. An
// invalid flag value is a usage error rather than a silent fallback, because a
// user who asked for a specific encoding should not get a different one.
func resolveFingerprintFormat(cfg *config.ConfigFile) certlib.FingerprintFormat {
	// The flag is a string whose zero value is not a valid format, so
	// emptiness is a sound "unset" signal and avoids needing the command.
	if strings.TrimSpace(fingerprintFormatFlag) != "" {
		value := strings.ToLower(strings.TrimSpace(fingerprintFormatFlag))
		for _, f := range certlib.FingerprintFormats {
			if string(f) == value {
				return f
			}
		}
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(
			fmt.Sprintf("Error: invalid --fingerprint-format %q (valid: hex, hex-colon, base64)", fingerprintFormatFlag)))
		os.Exit(1)
	}
	return config.FingerprintFormat(cfg)
}

// aiaOptions builds the chase options from the config. The cache is off unless
// the user turned it on, and --aia-refresh bypasses it for one run.
func aiaOptions(cfg *config.ConfigFile) certlib.AIAOptions {
	opts := certlib.AIAOptions{}
	if cfg == nil || !cfg.Defaults.AIA.Cache || aiaRefresh {
		return opts
	}
	cache, err := certops.OpenAIACache(cfg.Defaults.AIA.CacheTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certdiag: aia cache: %v\n", err)
		return opts
	}
	opts.Cache = cache
	return opts
}
