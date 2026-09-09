package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	storeSel     storeSelectionFlags
	storeOutput  string
	storeDetails bool
	storeQuery   string
)

var storeCmd = &cobra.Command{
	Use:   "store",
	Short: "List certificates from OS and application trust stores",
	Long: `List certificates from system or application trust stores.

By default, reads the OS trust store. Use flags to select a different store.

Examples:
  certdiag store                          # OS trust store
  certdiag store --java                   # all detected Java cacerts
  certdiag store --java-home /opt/jdk-21  # specific JDK
  certdiag store --openssl                # OpenSSL default bundle
  certdiag store --nss                    # browser profile stores (Firefox, Chrome-Linux)
  certdiag store --mozilla                # shipped Mozilla root snapshot
  certdiag store --chrome                 # shipped Chrome root snapshot
  certdiag store --trust-file /path/to/ca.pem   # arbitrary CA bundle
  certdiag store -o json                  # JSON output
  certdiag store -q "DigiCert"            # filter by name` + "\n\n" + BundleHelpText,
	Run: runStore,
}

var storeDiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover all trust stores on the system",
	Long:  `Auto-detect all trust stores on the system and report an inventory.`,
	Run:   runStoreDiscover,
}

var storeDiffOutput string

var storeDiffCmd = &cobra.Command{
	Use:   "diff <store-a> <store-b>",
	Short: "Compare two trust stores",
	Long: `Compare the contents of two trust stores by certificate fingerprint.

Store specs: os, java, java:<home>, openssl, nss, mozilla, chrome,
file:<path>, or an existing file path (PEM, JKS, PKCS#12 bundle).
Keywords take precedence over bare paths; use file:<path> to force a path.
nss reads browser profile stores; mozilla and chrome are the shipped root
snapshots.

Reports certificates present on only one side, and "rotated" roots (same
subject on both sides but a different certificate - renewed or cross-signed).
Read-only; stores are never modified.

Examples:
  certdiag store diff os java                     # OS store vs Java cacerts
  certdiag store diff java:/opt/jdk17 java:/opt/jdk21
  certdiag store diff os /mnt/image/etc/ssl/certs/ca-certificates.crt
  certdiag store diff os mozilla                  # OS store vs Mozilla snapshot
  certdiag store diff nss chrome                  # browser profiles vs Chrome snapshot
  certdiag store diff openssl os -o json

Exit codes:
  0  Stores are identical
  1  Stores differ
  2  Error (store not found, parse error, bad spec)`,
	Args: cobra.ExactArgs(2),
	Run:  runStoreDiff,
}

func init() {
	storeSel.Register(storeCmd, storeSelectionOpts{nss: true, fileShorthand: "f"})
	storeCmd.Flags().StringVarP(&storeOutput, "output", "o", "list", "Output format: list, table, json, yaml")
	storeCmd.Flags().BoolVarP(&storeDetails, "details", "d", false, "Show detailed certificate info")
	storeCmd.Flags().StringVarP(&storeQuery, "query", "q", "", "Filter certs by substring match")
	storeCmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password(s) for encrypted files (can be repeated)")
	registerPasswordFileFlag(storeCmd)

	storeDiscoverCmd.Flags().StringVarP(&storeOutput, "output", "o", "list", "Output format: list, json, yaml")

	storeDiffCmd.Flags().StringVarP(&storeDiffOutput, "output", "o", "human", "Output format: human, json, yaml")
	storeDiffCmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password(s) for encrypted stores (can be repeated)")
	registerPasswordFileFlag(storeDiffCmd)

	storeCmd.AddCommand(storeDiscoverCmd)
	storeCmd.AddCommand(storeDiffCmd)
	rootCmd.AddCommand(storeCmd)
}

func runStoreDiff(cmd *cobra.Command, args []string) {
	if err := cmdutil.ValidateDisplayFormat(storeDiffOutput, cmdutil.OutputHuman, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 2)
	pm := cliPasswordManager(cmd, cfg, "password", passwords, 2)

	result, err := certops.StoreDiff(certops.StoreDiffOptions{
		SpecA:     args[0],
		SpecB:     args[1],
		Passwords: pm.PasswordsForFile(""),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(2)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	cmdutil.EmitStructured(storeDiffOutput,
		func() string { return output.FormatStoreDiffHuman(result, resolveFingerprintFormat(cfg)) },
		func() string { return output.FormatStoreDiffJSON(result) },
		func() string { return output.FormatStoreDiffYAML(result) },
	)

	if !result.Identical {
		os.Exit(1)
	}
}

func runStore(cmd *cobra.Command, args []string) {
	if err := cmdutil.ValidateDisplayFormat(storeOutput, cmdutil.OutputList, cmdutil.OutputTable, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	storeType, bundleID := storeSel.SingleStore()

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", passwords, 1)

	inputPasswords := pm.PasswordsForFile(storeSel.File)

	opts := certops.StoreListOptions{
		StoreType: storeType,
		JavaHome:  storeSel.JavaHome,
		FilePath:  storeSel.File,
		Passwords: inputPasswords,
		Query:     storeQuery,
		BundleID:  bundleID,
		BundleDir: bundleDirOrEmpty(),
	}

	result, err := certops.StoreList(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	switch storeOutput {
	case cmdutil.OutputJSON:
		out, err := output.FormatStoreJSON(result.Stores)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
		fmt.Print(out)
	case cmdutil.OutputYAML:
		fmt.Print(output.FormatStoreYAML(result.Stores))
	case cmdutil.OutputTable:
		fmt.Print(output.FormatStoreTable(result.Stores))
	default:
		fmt.Print(output.FormatStoreListFormat(result.Stores, storeDetails, storeQuery, resolveFingerprintFormat(cfg)))
	}
}

func runStoreDiscover(cmd *cobra.Command, args []string) {
	if err := cmdutil.ValidateDisplayFormat(storeOutput, cmdutil.OutputList, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	result, err := certops.StoreDiscover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	switch storeOutput {
	case cmdutil.OutputJSON:
		out, err := output.FormatDiscoverJSON(result.Stores)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
		fmt.Print(out)
	case cmdutil.OutputYAML:
		fmt.Print(output.FormatDiscoverYAML(result.Stores))
	default:
		fmt.Print(output.FormatDiscoverList(result.Stores))
	}
}

// bundleDirOrEmpty resolves where refreshed root snapshots are installed. An
// empty result means only the compiled-in snapshots are available, which is the
// correct behaviour rather than an error.
func bundleDirOrEmpty() string {
	dir, err := config.BundleDir()
	if err != nil {
		return ""
	}
	return dir
}
