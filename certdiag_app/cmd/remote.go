package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	remoteTLSVersion   string
	remoteHostname     string
	remoteNoSNI        bool
	remoteStarttls     string
	remoteTimeout      string
	remoteIPv4         bool
	remoteIPv6         bool
	remoteProxy        string
	remoteALPN         string
	remoteOutputFormat string
	remoteClientCert   string
	remoteClientKey    string
	remoteClientP12    string
	remoteClientJKS    string
	remoteClientAlias  string
	remoteClientPass   string

	// fetch/check shared
	remoteSingleIP   bool
	remoteParallel   int
	remoteExpiryWarn int
	remoteDetails    int

	// fetch-only save flags
	remoteSaveChain  bool
	remoteSaveLeaf   bool
	remoteSaveAll    bool
	remoteSaveTo     string
	remoteOutputDir  string
	remoteOverwrite  bool
	remoteSaveFormat string

	// trust selection shared by fetch and check
	remoteTrustOpts storeSelectionFlags

	// check-only
	remoteExpiryCrit int
	remoteSeverity   string
	remoteCategory   string
	remoteStrict     bool
	remoteRevocation bool
	remoteRevMethod  string
	remoteRevRequire bool

	// http-only
	remoteHeaders      []string
	remoteFollowRedirs bool
	remoteMaxRedirects int
	remoteHeadersOnly  bool
)

var remoteCmd = &cobra.Command{
	Use:   "remote <command> [flags] <target>...",
	Short: "Connect to remote TLS endpoints and inspect certificates",
	Long: `Connect to remote TLS endpoints and inspect certificates, probe TLS capabilities,
or interact with the connection.

If no command is given and a target is provided, defaults to fetch.

Exit codes:
  0  Success
  1  WARNING-level issues found
  2  CRITICAL-level issues found
  3  Connection error`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		// Default to fetch when target is provided without subcommand
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		validateRemoteTargets(args)
		runRemoteFetch(args, settings, false)
		return nil
	},
}

var remoteFetchCmd = &cobra.Command{
	Use:   "fetch <target>...",
	Short: "Fetch and display certificates",
	Long:  "Fetch and display TLS certificates from one or more remote endpoints.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		validateRemoteTargets(args)
		runRemoteFetch(args, settings, false)
	},
}

var remoteCheckCmd = &cobra.Command{
	Use:   "check <target>...",
	Short: "Fetch and run certificate check suite",
	Long:  "Fetch certificates from remote endpoints and run the full check suite against them.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		validateRemoteTargets(args)
		runRemoteCheck(args, settings)
	},
}

var remoteProbeCmd = &cobra.Command{
	Use:   "probe <target>",
	Short: "Probe TLS versions and cipher suites",
	Long:  "Perform a comprehensive TLS probe against a target, testing supported versions, cipher suites, and features.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		validateRemoteTargets(args)
		runRemoteProbe(args[0], settings)
	},
}

var remotePipeCmd = &cobra.Command{
	Use:   "pipe <target>",
	Short: "Raw pipe mode (netcat-like, stdin/stdout)",
	Long:  "Establish a TLS connection and pipe stdin/stdout through it (netcat-like).",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		runRemotePipe(args[0], settings)
	},
}

var remoteHTTPCmd = &cobra.Command{
	Use:   "http <target>",
	Short: "HTTP/1.1 GET request over TLS",
	Long:  "Perform an HTTP/1.1 GET request over TLS, displaying the response and TLS connection details.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		settings, err := loadRemoteSettings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(err.Error()))
			os.Exit(1)
		}
		runRemoteHTTP(args[0], settings)
	},
}

func init() {
	// Shared connection flags (inherited by all subcommands)
	pf := remoteCmd.PersistentFlags()
	registerRemoteConnectionFlags(pf)
	pf.StringVarP(&remoteOutputFormat, "output", "o", "human", "Output format: human, json, yaml")

	// Fetch flags
	remoteFetchCmd.Flags().CountVarP(&remoteDetails, "details", "d", "Show extended details (-dd for PEM and full DNs)")
	remoteTrustOpts.Register(remoteFetchCmd, storeSelectionOpts{additive: true})
	registerRemoteMultiTargetFlags(remoteFetchCmd)
	remoteFetchCmd.Flags().BoolVar(&remoteSaveChain, "save-chain", false, "Save full certificate chain")
	remoteFetchCmd.Flags().BoolVar(&remoteSaveLeaf, "save-leaf", false, "Save leaf certificate only")
	remoteFetchCmd.Flags().BoolVar(&remoteSaveAll, "save-all", false, "Save each certificate as individual file")
	remoteFetchCmd.Flags().StringVar(&remoteSaveTo, "save-to", "", "Save chain to specific file path")
	remoteFetchCmd.Flags().StringVarP(&remoteOutputDir, "output-dir", "O", ".", "Directory for saved files")
	remoteFetchCmd.Flags().BoolVar(&remoteOverwrite, "overwrite", false, "Overwrite existing files")
	remoteFetchCmd.Flags().StringVar(&remoteSaveFormat, "save-format", "pem", "Save format: pem, der, p7b")

	// Check flags: --aia comes from the shared trust flags and is opt-in here too
	remoteTrustOpts.Register(remoteCheckCmd, storeSelectionOpts{additive: true})
	registerRemoteMultiTargetFlags(remoteCheckCmd)
	remoteCheckCmd.Flags().BoolVar(&remoteRevocation, "revocation", false, "Enable live revocation checking (OCSP/CRL; network, opt-in). Live OCSP discloses the inspected certificate to the CA.")
	remoteCheckCmd.Flags().StringVar(&remoteRevMethod, "revocation-method", "auto", "Revocation method: auto, ocsp, crl")
	remoteCheckCmd.Flags().BoolVar(&remoteRevRequire, "revocation-require", false, "Treat undetermined revocation status as critical")
	remoteCheckCmd.Flags().IntVar(&remoteExpiryCrit, "expiry-critical", 0, "Critical alert threshold in days (default: 7)")
	remoteCheckCmd.Flags().StringVar(&remoteSeverity, "severity", "", "Minimum severity: info, warning, critical")
	remoteCheckCmd.Flags().StringVar(&remoteCategory, "category", "", "Filter check categories (comma-separated: expiry, key_strength, algorithm, config, chain, structure, remote, info)")
	remoteCheckCmd.Flags().BoolVar(&remoteStrict, "strict", false, "Fail on WARNING or above")

	// HTTP flags
	remoteHTTPCmd.Flags().StringArrayVar(&remoteHeaders, "header", nil, "Custom HTTP header (repeatable)")
	remoteHTTPCmd.Flags().BoolVar(&remoteFollowRedirs, "follow-redirects", false, "Follow HTTP redirects")
	remoteHTTPCmd.Flags().IntVar(&remoteMaxRedirects, "max-redirects", 10, "Maximum redirects to follow")
	remoteHTTPCmd.Flags().BoolVar(&remoteHeadersOnly, "headers-only", false, "Show headers only, skip body")

	// Register subcommands
	markOpenSSLSupported(remoteFetchCmd)
	remoteCmd.AddCommand(remoteFetchCmd)
	remoteCmd.AddCommand(remoteCheckCmd)
	remoteCmd.AddCommand(remoteProbeCmd)
	remoteCmd.AddCommand(remotePipeCmd)
	remoteCmd.AddCommand(remoteHTTPCmd)

	rootCmd.AddCommand(remoteCmd)
}

func registerRemoteMultiTargetFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&remoteSingleIP, "single-ip", false, "Connect to only one resolved IP")
	cmd.Flags().IntVar(&remoteParallel, "parallel", 0, "Max concurrent connections for multi-target")
	cmd.Flags().IntVar(&remoteExpiryWarn, "expiry-warn", 0, "Warn about certs expiring within N days")
}

// remoteClientCerts loads the mTLS client certificate named by the flags, or
// exits; nil when none was given.
func remoteClientCerts() []tls.Certificate {
	if remoteClientCert == "" && remoteClientP12 == "" && remoteClientJKS == "" {
		return nil
	}
	clientCert, err := certlib.LoadClientCert(certlib.ClientCertOptions{
		CertPath: remoteClientCert,
		KeyPath:  remoteClientKey,
		P12Path:  remoteClientP12,
		JKSPath:  remoteClientJKS,
		Alias:    remoteClientAlias,
		Password: []byte(remoteClientPass),
	})
	if err != nil {
		fail(1, "Error loading client certificate: %v", err)
	}
	return []tls.Certificate{clientCert}
}

// remoteDialOptions is the TLS dial configuration the connection flags
// describe, for commands that dial through certlib directly.
func remoteDialOptions(settings remoteSettings) certlib.TLSDialOptions {
	var forced uint16
	if remoteTLSVersion != "" {
		forced, _ = certlib.TLSVersionFromString(remoteTLSVersion) // validated by loadRemoteSettings
	}
	starttls, _ := certlib.ParseStarttlsProtocol(remoteStarttls) // validated by loadRemoteSettings
	return certlib.TLSDialOptions{
		ForcedVersion: forced,
		ServerName:    remoteHostname,
		DisableSNI:    settings.disableSNI,
		Timeout:       settings.timeout,
		IPv4Only:      remoteIPv4,
		IPv6Only:      remoteIPv6,
		Starttls:      starttls,
		ProxyURL:      settings.proxy,
		ClientCerts:   remoteClientCerts(),
		ALPN:          remoteALPNList(),
	}
}

// remoteALPNList maps --alpn onto the dial option: unset is nil (the command
// picks its default), "none" offers nothing, anything else is the list.
func remoteALPNList() []string {
	switch strings.TrimSpace(remoteALPN) {
	case "":
		return nil
	case "none":
		return []string{}
	}
	var out []string
	for _, p := range strings.Split(remoteALPN, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// remoteConnectionFlagSets are the flag sets registerRemoteConnectionFlags
// bound, so a reader can ask whether a shared flag was given on the command
// line without referring to the commands themselves.
var remoteConnectionFlagSets []*pflag.FlagSet

// remoteConnectionFlagChanged reports whether a connection flag was given on
// the command line, on whichever command registered the shared set.
func remoteConnectionFlagChanged(name string) bool {
	for _, fs := range remoteConnectionFlagSets {
		if f := fs.Lookup(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}

// registerRemoteConnectionFlags binds the connection flags shared by every
// command that dials a TLS endpoint (remote *, verify <host>).
func registerRemoteConnectionFlags(pf *pflag.FlagSet) {
	remoteConnectionFlagSets = append(remoteConnectionFlagSets, pf)
	pf.StringVar(&remoteTLSVersion, "tls-version", "", "Force TLS version: tls1.0, tls1.1, tls1.2, tls1.3")
	pf.StringVar(&remoteHostname, "hostname", "", "Override SNI hostname")
	pf.BoolVar(&remoteNoSNI, "no-sni", false, "Disable SNI (omit server name in TLS ClientHello)")
	pf.StringVar(&remoteStarttls, "starttls", "", "STARTTLS protocol: smtp, imap, pop3, ftp, ldap, mysql, postgres")
	pf.StringVar(&remoteTimeout, "timeout", "", "Connection timeout (default 10s)")
	pf.BoolVarP(&remoteIPv4, "ipv4", "4", false, "Force IPv4")
	pf.BoolVarP(&remoteIPv6, "ipv6", "6", false, "Force IPv6")
	pf.StringVar(&remoteProxy, "proxy", "", "Proxy URL: socks5://host:port or http://host:port")
	pf.StringVar(&remoteALPN, "alpn", "", "ALPN protocols to offer, comma-separated (default h2,http/1.1 for fetch and check; 'none' offers nothing)")
	pf.StringVar(&remoteClientCert, "client-cert", "", "Client certificate PEM file")
	pf.StringVar(&remoteClientKey, "client-key", "", "Client private key PEM file")
	pf.StringVar(&remoteClientP12, "client-p12", "", "Client PKCS#12 file")
	pf.StringVar(&remoteClientJKS, "client-jks", "", "Client JKS keystore file")
	pf.StringVar(&remoteClientAlias, "client-alias", "", "Alias within P12/JKS for client cert")
	pf.StringVar(&remoteClientPass, "client-password", "", "Password for encrypted client key/P12/JKS")
}

// validateRemoteTargets turns a malformed target into a usage error (exit 1)
// before any connection is attempted; connection failures keep exit 3.
func validateRemoteTargets(targets []string) {
	for _, t := range targets {
		if _, err := certlib.ParseTarget(t); err != nil {
			fail(1, "Error: %v", err)
		}
	}
}

type remoteSettings struct {
	timeout           time.Duration
	parallel          int
	proxy             string
	disableSNI        bool
	fingerprintFormat certlib.FingerprintFormat

	// defaults.check from the config, applied by remote check when the flags are unset
	disabledChecks     []string
	expiryWarnDays     int
	expiryCriticalDays int
}

func loadRemoteSettings() (remoteSettings, error) {
	if remoteIPv4 && remoteIPv6 {
		return remoteSettings{}, fmt.Errorf("Error: --ipv4 (-4) and --ipv6 (-6) are mutually exclusive")
	}
	if remoteNoSNI && remoteHostname != "" {
		return remoteSettings{}, fmt.Errorf("Error: --hostname and --no-sni are mutually exclusive")
	}
	if remoteHostname == "" && remoteConnectionFlagChanged("hostname") {
		return remoteSettings{}, fmt.Errorf("Error: --hostname cannot be empty; use --no-sni to omit the server name")
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return remoteSettings{}, fmt.Errorf("Error loading config: %v", err)
	}

	timeoutStr := remoteTimeout
	if timeoutStr == "" && cfg != nil {
		timeoutStr = cfg.Defaults.Remote.Timeout
	}
	if timeoutStr == "" {
		timeoutStr = "10s"
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return remoteSettings{}, fmt.Errorf("Error: invalid timeout %q: %v", timeoutStr, err)
	}

	if remoteTLSVersion != "" {
		if _, err := certlib.TLSVersionFromString(remoteTLSVersion); err != nil {
			return remoteSettings{}, fmt.Errorf("Error: invalid --tls-version: %v", err)
		}
	}
	if remoteStarttls != "" {
		if _, err := certlib.ParseStarttlsProtocol(remoteStarttls); err != nil {
			return remoteSettings{}, fmt.Errorf("Error: invalid --starttls: %v", err)
		}
	}

	if err := cmdutil.ValidateDisplayFormat(remoteOutputFormat, cmdutil.OutputHuman, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		return remoteSettings{}, fmt.Errorf("Error: %v", err)
	}

	parallel := remoteParallel
	if parallel == 0 && cfg != nil && cfg.Defaults.Remote.Parallel > 0 {
		parallel = cfg.Defaults.Remote.Parallel
	}
	if parallel == 0 {
		parallel = 4
	}

	proxy := remoteProxy
	if proxy == "" && cfg != nil {
		proxy = cfg.Defaults.Remote.Proxy
	}
	if proxy != "" {
		u, parseErr := url.Parse(proxy)
		if parseErr != nil || (u.Scheme != "socks5" && u.Scheme != "http" && u.Scheme != "https") {
			return remoteSettings{}, fmt.Errorf("Error: invalid --proxy URL %q (expected socks5://, http://, or https://)", proxy)
		}
	}

	settings := remoteSettings{
		timeout:            timeout,
		parallel:           parallel,
		proxy:              proxy,
		disableSNI:         remoteNoSNI,
		fingerprintFormat:  resolveFingerprintFormat(cfg),
		expiryWarnDays:     remoteExpiryWarn,
		expiryCriticalDays: remoteExpiryCrit,
	}
	if cfg != nil {
		settings.disabledChecks = cfg.Defaults.Check.DisabledChecks
		settings.expiryWarnDays = resolveExpiryThreshold(remoteExpiryWarn, cfg.Defaults.Check.ExpiryWarnDays)
		settings.expiryCriticalDays = resolveExpiryThreshold(remoteExpiryCrit, cfg.Defaults.Check.ExpiryCriticalDays)
	}
	return settings, nil
}

// runRemoteFetch fetches and displays certs for the targets. rootExitConvention
// is set when reached via root autodetection (`certdiag <host>`): the root
// command documents 0/1 exit codes, so a fetch failure is 1 and everything else
// (including expired/expiring certs, which are shown) is 0 - matching how
// `certdiag <file>` behaves. The explicit `remote fetch` command passes false to
// keep its richer 0/1/2/3 codes.
func runRemoteFetch(targets []string, settings remoteSettings, rootExitConvention bool) {
	opts := certops.FetchRemoteCertOptions{
		ALPN:       remoteALPNList(),
		Targets:    targets,
		TLSVersion: remoteTLSVersion,
		Hostname:   remoteHostname,
		DisableSNI: settings.disableSNI,
		Starttls:   remoteStarttls,
		Timeout:    settings.timeout,
		IPv4Only:   remoteIPv4,
		IPv6Only:   remoteIPv6,
		SingleIP:   remoteSingleIP,
		ProxyURL:   settings.proxy,
		Parallel:   settings.parallel,
		ExpiryWarn: remoteExpiryWarn,
	}

	opts.ClientCerts = remoteClientCerts()

	if showOpenSSLFlag {
		renderOpenSSL(buildRemoteFetchOpenSSL(targets, remoteStarttls, remoteHostname, settings.disableSNI))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.FetchRemoteCert(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// The served chain goes through the same pipeline a file scan uses, so the
	// relations and chain lines come for free.
	remoteStore := certops.RemoteCertStore(result)
	relations, chains, containing := certops.RemoteStoreChains(remoteStore)
	remoteOpts := output.OutputOptions{
		DetailLevel:       remoteDetails,
		FingerprintFormat: settings.fingerprintFormat,
		RelationIndex:     relations,
		Chains:            chains,
		ChainsContaining:  containing,
		Store:             remoteStore,
	}

	var storeVerdicts map[string][]certops.RemoteStoreVerdict
	var aiaProvenance map[[32]byte]certlib.AIAFetched
	if remoteTrustOpts.Asked() {
		storeVerdicts, aiaProvenance = applyRemoteTrust(result, remoteStore, &remoteOpts)
	}
	// --save-chain --aia writes the chain a strict client will accept, with
	// each fetched certificate annotated so the file is not misread as served.
	if remoteTrustOpts.AIA && len(aiaProvenance) > 0 {
		result = appendAIAToChains(result, aiaProvenance)
	}

	remoteOpts.StoreVerdicts = storeVerdicts

	cmdutil.EmitStructured(remoteOutputFormat,
		func() string { return output.FormatRemoteHumanOptions(result, remoteOpts) },
		func() string { return output.FormatRemoteJSONOptions(result, remoteOpts) },
		func() string { return output.FormatRemoteYAMLOptions(result, remoteOpts) },
	)

	saveOpts := certops.SaveRemoteOptions{
		AIAProvenance: aiaProvenance,
		SaveChain:     remoteSaveChain,
		SaveLeaf:      remoteSaveLeaf,
		SaveAll:       remoteSaveAll,
		SaveTo:        remoteSaveTo,
		OutputDir:     remoteOutputDir,
		Overwrite:     remoteOverwrite,
		SaveFormat:    remoteSaveFormat,
	}

	if saveOpts.ShouldSave() {
		for _, tr := range result.TargetResults {
			if tr.Error != "" || len(tr.Certs) == 0 {
				continue
			}
			certs := make([]*x509.Certificate, len(tr.Certs))
			for i, ci := range tr.Certs {
				certs[i] = ci.Cert.Certificate
			}
			saveResult, err := certops.SaveRemoteCerts(tr.Target, certs, saveOpts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Save error for %s: %v", tr.Target, err)))
				continue
			}
			for _, path := range saveResult.SavedFiles {
				fmt.Fprintf(os.Stderr, "Saved: %s\n", path)
			}
		}
	}

	if rootExitConvention {
		for _, tr := range result.TargetResults {
			if tr.Error != "" {
				os.Exit(1)
			}
		}
		return
	}

	exitCode := remoteExitCode(result)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func runRemoteCheck(targets []string, settings remoteSettings) {
	opts := certops.CheckRemoteOptions{
		ALPN:           remoteALPNList(),
		Targets:        targets,
		TLSVersion:     remoteTLSVersion,
		Hostname:       remoteHostname,
		DisableSNI:     settings.disableSNI,
		Starttls:       remoteStarttls,
		Timeout:        settings.timeout,
		IPv4Only:       remoteIPv4,
		IPv6Only:       remoteIPv6,
		SingleIP:       remoteSingleIP,
		ProxyURL:       settings.proxy,
		Parallel:       settings.parallel,
		NoAIA:          !remoteTrustOpts.AIA,
		DisabledChecks: settings.disabledChecks,
	}

	if settings.expiryWarnDays > 0 {
		opts.ExpiryWarnDays = settings.expiryWarnDays
	}
	if settings.expiryCriticalDays > 0 {
		opts.ExpiryCriticalDays = settings.expiryCriticalDays
	}

	if remoteSeverity != "" {
		sev, err := cmdutil.ParseCheckSeverity(remoteSeverity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
		opts.MinSeverity = sev
	}

	if remoteCategory != "" {
		opts.Categories = strings.Split(remoteCategory, ",")
	}

	// nil cmd is safe: the cmd is only consulted for --crl-file, which remote does not expose.
	revCfg, err := buildRevocationConfig(nil, remoteRevocation, remoteRevMethod, remoteRevRequire, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
	opts.Revocation = revCfg

	opts.ClientCerts = remoteClientCerts()

	result, err := certops.CheckRemote(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Per-store verdicts (decision D2): the same flags as remote fetch, the
	// same question, answered next to the checks.
	if sel := remoteTrustOpts.Selection(); sel.Any() {
		applyRemoteCheckTrust(result, sel)
	}

	cmdutil.EmitStructured(remoteOutputFormat,
		func() string { return output.FormatRemoteCheckHuman(result) },
		func() string { return output.FormatRemoteCheckJSON(result) },
		func() string { return output.FormatRemoteCheckYAML(result) },
	)

	exitCode := remoteCheckExitCode(result)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func runRemotePipe(target string, settings remoteSettings) {
	remoteTarget, err := certlib.ParseTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	sni := remoteTarget.SNI
	if remoteHostname != "" {
		sni = remoteHostname
	}
	if settings.disableSNI {
		sni = ""
	}
	remoteTarget.SNI = sni

	var forcedVersion uint16
	if remoteTLSVersion != "" {
		v, verr := certlib.TLSVersionFromString(remoteTLSVersion)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", verr)))
			os.Exit(1)
		}
		forcedVersion = v
	}

	starttls, err := certlib.ParseStarttlsProtocol(remoteStarttls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	dialOpts := certlib.TLSDialOptions{
		ForcedVersion: forcedVersion,
		ServerName:    sni,
		DisableSNI:    settings.disableSNI,
		Timeout:       settings.timeout,
		IPv4Only:      remoteIPv4,
		IPv6Only:      remoteIPv6,
		Starttls:      starttls,
		ProxyURL:      settings.proxy,
		ALPN:          remoteALPNList(),
	}

	dialOpts.ClientCerts = remoteClientCerts()

	conn, tlsInfo, err := certlib.PipeConnection(remoteTarget, dialOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(3)
	}
	defer conn.Close()

	if tlsInfo != nil {
		fmt.Fprintf(os.Stderr, "Connected to %s (%s, %s)\n",
			remoteTarget.Address(), tlsInfo.VersionName, tlsInfo.CipherSuiteName)
	}

	serverDone := make(chan struct{})

	go func() {
		io.Copy(conn, os.Stdin)
		conn.CloseWrite()
	}()

	go func() {
		io.Copy(os.Stdout, conn)
		close(serverDone)
	}()

	<-serverDone
}

func runRemoteHTTP(target string, settings remoteSettings) {
	opts := certops.HTTPRemoteOptions{
		Target:          target,
		Hostname:        remoteHostname,
		DisableSNI:      settings.disableSNI,
		TLSVersion:      remoteTLSVersion,
		Starttls:        remoteStarttls,
		Timeout:         settings.timeout,
		IPv4Only:        remoteIPv4,
		IPv6Only:        remoteIPv6,
		ProxyURL:        settings.proxy,
		CustomHeaders:   remoteHeaders,
		FollowRedirects: remoteFollowRedirs,
		MaxRedirects:    remoteMaxRedirects,
		HeadersOnly:     remoteHeadersOnly,
	}

	opts.ClientCerts = remoteClientCerts()

	result, err := certops.HTTPRemote(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	cmdutil.EmitStructured(remoteOutputFormat,
		func() string { return output.FormatHTTPHuman(result) },
		func() string { return output.FormatHTTPJSON(result) },
		func() string { return output.FormatHTTPYAML(result) },
	)

	if result.Error != "" {
		os.Exit(3)
	}
}

func runRemoteProbe(target string, settings remoteSettings) {
	opts := certops.ProbeRemoteOptions{
		Target:     target,
		Hostname:   remoteHostname,
		DisableSNI: settings.disableSNI,
		Starttls:   remoteStarttls,
		Timeout:    settings.timeout,
		IPv4Only:   remoteIPv4,
		IPv6Only:   remoteIPv6,
	}

	result, err := certops.ProbeRemoteTLS(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	cmdutil.EmitStructured(remoteOutputFormat,
		func() string { return output.FormatProbeHuman(result) },
		func() string { return output.FormatProbeJSON(result) },
		func() string { return output.FormatProbeYAML(result) },
	)

	if result.Error != "" {
		os.Exit(3)
	}
}

func remoteCheckExitCode(result *certops.CheckRemoteResult) int {
	code := 0
	for _, tr := range result.TargetResults {
		if tr.Error != "" {
			if code < 3 {
				code = 3
			}
			continue
		}
		if tr.Summary.Critical > 0 && code < 2 {
			code = 2
		}
		if tr.Summary.Warning > 0 && code < 1 {
			if remoteStrict {
				if code < 2 {
					code = 2
				}
			} else {
				code = 1
			}
		}
	}
	return code
}

func remoteExitCode(result *certops.FetchRemoteCertResult) int {
	code := 0

	for _, tr := range result.TargetResults {
		if tr.Error != "" {
			if code < 3 {
				code = 3
			}
			continue
		}
		if tr.ExpiryWarn != nil {
			if tr.ExpiryWarn.HasExpired && code < 2 {
				code = 2
			}
			if tr.ExpiryWarn.HasWarning && code < 1 {
				code = 1
			}
		}
	}

	return code
}

// applyRemoteTrust resolves a verdict per served certificate against the OS
// store, and, when other stores were named, a verdict per store per target.
func applyRemoteTrust(result *certops.FetchRemoteCertResult, store *certlib.CertStore, opts *output.OutputOptions) (map[string][]certops.RemoteStoreVerdict, map[[32]byte]certlib.AIAFetched) {
	sel := remoteTrustOpts.Selection()
	// One read of the stores serves the TRUST column, the STORES tags and the
	// per-store verdicts alike.
	loadOpts := certops.StoreLoadAllOptions{JavaHome: sel.JavaHome}
	if sel.File != "" {
		loadOpts.IncludeFiles = []string{sel.File}
	}
	loaded, err := certops.StoreLoadAll(loadOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Warning: "+err.Error()))
		return nil, nil
	}

	// AIA is what makes certdiag agree with a browser on a chain whose issuer
	// the server did not send. It reaches the network, so only with the flag.
	var aia *certlib.AIAResult
	if remoteTrustOpts.AIA {
		res := certlib.ChaseAIA(remoteChainCerts(result), aiaOptions(nil))
		if len(res.Fetched) > 0 {
			aia = &res
			if c := certops.AIAContainer(res); c != nil {
				store.AddContainer(*c)
			}
		}
		for _, f := range res.Failures {
			fmt.Fprintf(os.Stderr, "certdiag: aia %s: %s\n", f.URL, f.Reason)
		}
	}

	if index, err := certops.EvaluateTrust(certops.TrustEvalOptions{Store: store, Stores: loaded.Stores, AIA: aia}); err == nil {
		opts.TrustIndex = index
		presence := certops.ComputeStorePresence(loaded.Stores)
		opts.StoreTags = func(cert *x509.Certificate) []string {
			return presence.TagsFor(cert)
		}
	}

	provenance := make(map[[32]byte]certlib.AIAFetched)
	if aia != nil {
		for _, f := range aia.Fetched {
			if f.Cert != nil {
				provenance[sha256.Sum256(f.Cert.Raw)] = f
			}
		}
	}

	if !sel.Any() {
		return nil, provenance
	}

	verdicts := make(map[string][]certops.RemoteStoreVerdict)
	for i := range result.TargetResults {
		tr := &result.TargetResults[i]
		certs := remoteCertsOf(tr.Certs)
		if len(certs) == 0 {
			continue
		}
		rows, _ := certops.VerifyRemoteAgainstStores(certs, remoteVerifyHostname(tr.Target, tr.Connection), sel, loaded.Stores)
		verdicts[tr.Target] = rows
	}
	return verdicts, provenance
}

// appendAIAToChains adds the fetched issuers to each target's certificate list
// so a saved chain is the complete one.
// appendAIAToChains adds to each target only the AIA certificates that were
// fetched for that target's own chain (M31 H10): a fetched certificate belongs
// to a target when the certificate that pointed at it (AIAFetched.For) is
// served by that target, or was itself fetched for it. Within a target the
// order follows the chase upwards, and the whole thing is deterministic.
func appendAIAToChains(result *certops.FetchRemoteCertResult, provenance map[[32]byte]certlib.AIAFetched) *certops.FetchRemoteCertResult {
	keys := make([][32]byte, 0, len(provenance))
	for fp := range provenance {
		keys = append(keys, fp)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })

	for i := range result.TargetResults {
		tr := &result.TargetResults[i]
		present := make(map[[32]byte]bool)
		for _, ci := range tr.Certs {
			if ci.Cert != nil && ci.Cert.Certificate != nil {
				present[sha256.Sum256(ci.Cert.Certificate.Raw)] = true
			}
		}
		// Closure over "fetched for a certificate this target has".
		for added := true; added; {
			added = false
			for _, fp := range keys {
				f := provenance[fp]
				if present[fp] || f.Cert == nil || f.For == nil || !present[sha256.Sum256(f.For.Raw)] {
					continue
				}
				present[fp] = true
				added = true
				tr.Certs = append(tr.Certs, certops.RemoteCertInfo{
					Index: len(tr.Certs),
					Role:  "aia",
					Cert:  &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: f.Cert, RawBytes: f.Cert.Raw},
				})
			}
		}
	}
	return result
}

// remoteChainCerts flattens every served certificate across targets.
func remoteChainCerts(result *certops.FetchRemoteCertResult) []*x509.Certificate {
	var out []*x509.Certificate
	for i := range result.TargetResults {
		for _, ci := range result.TargetResults[i].Certs {
			if ci.Cert != nil && ci.Cert.Certificate != nil {
				out = append(out, ci.Cert.Certificate)
			}
		}
	}
	return out
}
