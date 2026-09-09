package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
	"github.com/zarmin/certdiag/certdiag_app/internal/tui"
	"github.com/zarmin/certdiag/certdiag_app/pkg/oscountry"
)

// writeConfigPreservingMode overwrites a config file, preserving its existing
// permissions (default 0600). Config files may hold plaintext passwords, so we
// must never widen them to 0644 on rewrite, and the write must be atomic
// (temp+rename) so a crash mid-write cannot truncate the config.
func writeConfigPreservingMode(path string, data []byte) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".certdiag-cfg-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	return os.Rename(tmpPath, path)
}

func makeSaveColumns(cfgPath string) func(cols []string) error {
	return func(cols []string) error {
		if cfgPath == "" {
			return fmt.Errorf("no config path available")
		}
		if err := config.EnsureConfig(cfgPath); err != nil {
			return err
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return err
		}
		result, err := config.RewriteTUIColumns(data, cols)
		if err != nil {
			return err
		}
		return writeConfigPreservingMode(cfgPath, result)
	}
}

func makeSaveStoreOptions(cfgPath string) func(cols []string, grouping string) error {
	return func(cols []string, grouping string) error {
		if cfgPath == "" {
			return fmt.Errorf("no config path available")
		}
		if err := config.EnsureConfig(cfgPath); err != nil {
			return err
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return err
		}
		result, err := config.RewriteTrustStoreOptions(data, cols, grouping)
		if err != nil {
			return err
		}
		return writeConfigPreservingMode(cfgPath, result)
	}
}

func makeSaveOptions(cfgPath string) func(tui.SavedOptions) error {
	return func(opts tui.SavedOptions) error {
		if cfgPath == "" {
			return fmt.Errorf("no config path available")
		}
		if err := config.EnsureConfig(cfgPath); err != nil {
			return err
		}
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return err
		}
		result, err := config.RewriteTUIOptions(data, config.TUIOptionsForSave{
			Recursive:         opts.Recursive,
			MaxDepth:          opts.MaxDepth,
			FileSignatureScan: opts.FileSignatureScan,
			AutoDiscover:      opts.AutoDiscover,
			PathDisplay:       opts.PathDisplay,
		})
		if err != nil {
			return err
		}
		// The fingerprint format lives under defaults.output, not defaults.tui,
		// so it needs its own pass over the already-rewritten bytes.
		if opts.FingerprintFormat != "" {
			result, err = config.RewriteOutputFingerprintFormat(result, opts.FingerprintFormat)
			if err != nil {
				return err
			}
		}
		return writeConfigPreservingMode(cfgPath, result)
	}
}

var tuiCmd = &cobra.Command{
	Use:   "tui [path]",
	Short: "Interactive certificate browser",
	Long:  "Launch an interactive TUI to browse and inspect certificates.",
	Args:  cobra.MaximumNArgs(1),
	Run:   runTUI,
}

var (
	tuiPcapFilter      string
	tuiPcapAggressive  bool
	tuiProxyListen     string
	tuiProxyTarget     string
	tuiProxyFilter     string
	tuiProxyAggressive bool
	tuiStoreGrouping   string
	tuiStoreFiles      []string
)

var tuiStoreCmd = &cobra.Command{
	Use:   "store",
	Short: "Open TUI with the trust store browser",
	Long: `Open the TUI directly in the read-only trust store browser.

Loads the OS trust store, every detected JDK cacerts and the OpenSSL bundle.

Examples:
  certdiag tui store
  certdiag tui store --group kind
  certdiag tui store --trust-file /path/to/ca.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		runTUIStore()
	},
}

var tuiPcapCmd = &cobra.Command{
	Use:   "pcap [flags] <file.pcap>",
	Short: "Open TUI with pcap analysis view",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runTUIPcap(args[0])
	},
}

var tuiProxyCmd = &cobra.Command{
	Use:   "proxy [flags]",
	Short: "Open TUI with proxy interception view",
	Run: func(cmd *cobra.Command, args []string) {
		if tuiProxyListen == "" || tuiProxyTarget == "" {
			fmt.Fprintln(os.Stderr, "Error: both --listen and --target are required")
			os.Exit(1)
		}
		runTUIProxy()
	},
}

func init() {
	registerPasswordFlags(tuiCmd, passwordFlagOpts{noTryAll: true})
	tuiCmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Scan directories recursively")
	tuiCmd.Flags().IntVar(&depth, "depth", 0, "Maximum recursion depth")
	tuiCmd.Flags().BoolVar(&signatureScan, "file-signature-scan", false, "Detect certs by magic bytes")
	tuiCmd.Flags().BoolVarP(&discover, "discover", "D", false, "Discover related files in same directory")

	tuiPcapCmd.Flags().StringVarP(&tuiPcapFilter, "filter", "f", "", "Search string for session filtering")
	tuiPcapCmd.Flags().BoolVarP(&tuiPcapAggressive, "aggressive", "a", false, "Scan for TLS within streams (STARTTLS)")
	tuiCmd.AddCommand(tuiPcapCmd)

	tuiProxyCmd.Flags().StringVarP(&tuiProxyListen, "listen", "l", "", "Proxy listen address")
	tuiProxyCmd.Flags().StringVarP(&tuiProxyTarget, "target", "t", "", "Proxy target address")
	tuiProxyCmd.Flags().StringVarP(&tuiProxyFilter, "filter", "f", "", "Search string for session filtering")
	tuiProxyCmd.Flags().BoolVarP(&tuiProxyAggressive, "aggressive", "a", false, "Scan for TLS within streams")
	tuiCmd.AddCommand(tuiProxyCmd)

	tuiStoreCmd.Flags().StringVar(&tuiStoreGrouping, "group", "", "Initial grouping: instance or kind")
	tuiStoreCmd.Flags().StringArrayVar(&tuiStoreFiles, "trust-file", nil, "Additional CA bundle file(s) to load as stores")
	tuiStoreCmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password(s) for encrypted store files")
	registerPasswordFileFlag(tuiStoreCmd)
	tuiCmd.AddCommand(tuiStoreCmd)
}

func runTUIPcap(path string) {
	ensureNotNestedShell()

	setup := newTUISetup()
	setup.opts.InitialPcapFile = path
	setup.opts.InitialPcapFilter = tuiPcapFilter
	setup.opts.InitialPcapAggr = tuiPcapAggressive
	runTUISetup(".", setup)
}

func runTUIProxy() {
	ensureNotNestedShell()

	setup := newTUISetup()
	setup.opts.InitialProxyListen = tuiProxyListen
	setup.opts.InitialProxyTarget = tuiProxyTarget
	setup.opts.InitialProxyFilter = tuiProxyFilter
	setup.opts.InitialProxyAggr = tuiProxyAggressive
	runTUISetup(".", setup)
}

func ensureNotNestedShell() {
	if os.Getenv("CERTDIAG_SHELL") != "" {
		fmt.Fprintln(os.Stderr, "Error: cannot start TUI inside a certdiag subshell (nested shell detected). Exit the current shell first.")
		os.Exit(1)
	}
}

// tuiSetup is everything a TUI entry point needs from the config and the
// shared flags, loaded once. Every `tui ...` command starts from it, so the
// four entry points cannot drift apart again (M31 M20, R2).
type tuiSetup struct {
	cfg      *config.ConfigFile
	cfgScan  config.TUIScanDefaults
	opts     tui.TUIOptions
	scan     certlib.ScanOptions
	discover bool
}

func newTUISetup() tuiSetup {
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	cfgScan := config.GetTUIScanDefaults(cfg)
	configPath, _ := config.ResolveConfigPath(configFile)
	masterPw := resolveMasterPassword(false)

	pm, err := password.NewPasswordManager(password.PasswordManagerOpts{
		CLIPasswords:   passwords,
		PasswordFiles:  passwordFiles,
		Config:         cfg,
		MasterPassword: masterPw,
		NoTryAll:       noTryAllPasswords,
		Interactive:    false,
	})
	if err != nil {
		fail(1, "Error: %v", err)
	}

	var tuiOpts tui.TUIOptions
	tuiOpts.ActiveCols = config.ActiveColumns(cfg)
	tuiOpts.ConfigPath = configPath
	tuiOpts.PathDisplay = cfgScan.PathDisplay
	tuiOpts.SubjectOrg = "Example Org"
	tuiOpts.SubjectCountry = oscountry.GuessCountry()
	tuiOpts.BundleDir = bundleDirOrEmpty()
	tuiOpts.KeyDefaults = (&config.ConfigFile{}).GetKeyDefaults()
	certDefs := (&config.ConfigFile{}).GetCertDefaults()
	if cfg != nil {
		if cfg.Defaults.Subject.Organization != nil {
			tuiOpts.SubjectOrg = *cfg.Defaults.Subject.Organization
		}
		if cfg.Defaults.Subject.Country != "" {
			tuiOpts.SubjectCountry = cfg.Defaults.Subject.Country
		}
		tuiOpts.KeyDefaults = cfg.GetKeyDefaults()
		certDefs = cfg.GetCertDefaults()
		tuiOpts.DisabledChecks = cfg.Defaults.Check.DisabledChecks
		if cfg.HasEncryptedPasswords() && len(masterPw) > 0 {
			tuiOpts.StatusMessage = "master password: OK"
		}
		// Only when the user turned caching on: fetched certificates are
		// otherwise used for the session and forgotten.
		if cfg.Defaults.AIA.Cache {
			if cache, err := certops.OpenAIACache(cfg.Defaults.AIA.CacheTTL); err == nil {
				tuiOpts.AIACache = cache
			}
		}
	}
	tuiOpts.DefaultDays = certDefs.Days
	tuiOpts.DefaultCADays = certDefs.CADays
	tuiOpts.SaveColumns = makeSaveColumns(configPath)
	tuiOpts.SaveOptions = makeSaveOptions(configPath)
	tuiOpts.SaveStoreOptions = makeSaveStoreOptions(configPath)
	tuiOpts.StoreCols = config.ActiveStoreColumns(cfg)
	tuiOpts.StoreGrouping = config.StoreGrouping(cfg)
	tuiOpts.FingerprintFormat = string(resolveFingerprintFormat(cfg))

	return tuiSetup{
		cfg:     cfg,
		cfgScan: cfgScan,
		opts:    tuiOpts,
		scan: certlib.ScanOptions{
			Recursive:        cfgScan.Recursive,
			MaxDepth:         cfgScan.MaxDepth,
			UseSignatureScan: cfgScan.FileSignatureScan,
			PasswordProvider: pm,
		},
		discover: cfgScan.AutoDiscover,
	}
}

// runTUISetup starts the TUI from a prepared setup.
func runTUISetup(path string, setup tuiSetup) {
	if err := tui.Run(path, setup.scan, setup.discover, output.OutputOptions{}, setup.opts); err != nil {
		fail(1, "Error: %v", err)
	}
}

func runTUIStore() {
	ensureNotNestedShell()

	if tuiStoreGrouping != "" && tuiStoreGrouping != "instance" && tuiStoreGrouping != "kind" {
		fail(1, "Error: --group must be 'instance' or 'kind'")
	}

	setup := newTUISetup()
	setup.opts.InitialTrustStore = true
	setup.opts.InitialStoreFiles = tuiStoreFiles
	if tuiStoreGrouping != "" {
		setup.opts.StoreGrouping = tuiStoreGrouping
	}
	runTUISetup(".", setup)
}

func runTUI(cmd *cobra.Command, args []string) {
	ensureNotNestedShell()

	if len(args) == 0 {
		args = []string{"."}
	}

	setup := newTUISetup()

	// Config defaults first, then the explicit CLI flags; a flag that was
	// given locks its option in the TUI options editor.
	locked := make(map[string]bool)
	if cmd.Flags().Changed("recursive") {
		setup.scan.Recursive = recursive
		locked["recursive"] = true
	}
	if cmd.Flags().Changed("depth") {
		setup.scan.MaxDepth = depth
		locked["max_depth"] = true
	}
	if cmd.Flags().Changed("file-signature-scan") {
		setup.scan.UseSignatureScan = signatureScan
		locked["signature_scan"] = true
	}
	if cmd.Flags().Changed("discover") {
		setup.discover = discover
		locked["auto_discover"] = true
	}
	if setup.scan.MaxDepth > 0 && !setup.scan.Recursive {
		fail(1, "Error: --depth requires --recursive")
	}
	setup.opts.LockedFlags = locked

	runTUISetup(args[0], setup)
}
