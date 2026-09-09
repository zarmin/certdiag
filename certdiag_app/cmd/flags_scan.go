package cmd

import "github.com/spf13/cobra"

// passwordFlagOpts selects which of the shared password flags a command
// carries: -i makes no sense where the command cannot prompt (the TUI), and
// --no-try-all-passwords only where the password manager scans files.
type passwordFlagOpts struct {
	prompt   bool
	noTryAll bool
}

// registerPasswordFlags binds the password flags every scanning command
// shares. One registration site means one spelling and one help text.
func registerPasswordFlags(cmd *cobra.Command, o passwordFlagOpts) {
	cmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password(s) for encrypted files (can be repeated)")
	registerPasswordFileFlag(cmd)
	if o.prompt {
		cmd.Flags().BoolVarP(&interactivePrompt, "password-prompt", "i", false, "Interactively prompt for passwords on failure")
	}
	if o.noTryAll {
		cmd.Flags().BoolVar(&noTryAllPasswords, "no-try-all-passwords", false, "Only use filename-matched passwords from config")
	}
}

// registerPasswordFileFlag binds -P/--password-file. Every command that takes
// -p carries it, because a password on the command line lands in the shell
// history and a file does not (cmd/flag_parity_test.go).
func registerPasswordFileFlag(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&passwordFiles, "password-file", "P", nil, "File(s) containing passwords, one per line (can be repeated)")
}

// registerScanFlags binds the root scan's own flags. `list` is documented as
// an alias of the root scan and registers exactly this set, so the two can
// never drift apart again (M31 M7).
func registerScanFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&recursive, "recursive", "r", false, "Scan directories recursively")
	cmd.Flags().IntVar(&depth, "depth", 0, "Maximum recursion depth (requires --recursive)")
	cmd.Flags().BoolVar(&signatureScan, "file-signature-scan", false, "Detect certs by magic bytes, not just extension")
	cmd.Flags().BoolVarP(&tableView, "table-view", "t", false, "Show results in table format")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: list, table, yaml, json, jsonpath=EXPR")
	cmd.Flags().CountVarP(&details, "details", "d", "Show extended details (-dd for PEM and full DNs)")
	cmd.Flags().BoolVar(&aiaEnabled, "aia", false, "Fetch missing issuers over AIA (network; implies --trust)")
	cmd.Flags().BoolVar(&aiaRefresh, "aia-refresh", false, "Ignore the AIA cache for this run")
	cmd.Flags().BoolVar(&insecure, "insecure-details", false, "Also show private key values")
	cmd.Flags().StringVarP(&query, "query", "q", "", "Filter results by substring match")
	cmd.Flags().BoolVarP(&discover, "discover", "D", false, "Discover related files in same directory")
	cmd.Flags().BoolVar(&inlineCheck, "check", false, "Show inline check warnings next to each item")
	cmd.Flags().IntVar(&expiryWarn, "expiry-warn", 0, "Expiry warning threshold in days (default 30)")
	cmd.Flags().IntVar(&expiryCritical, "expiry-critical", 0, "Expiry critical threshold in days (default 7)")
	cmd.Flags().BoolVar(&relationships, "relationships", true, "Show certificate relationships in output (default)")
	cmd.Flags().BoolVar(&noRelationships, "no-relationships", false, "Hide certificate relationships; show a flat list")
	cmd.Flags().BoolVar(&trustFlag, "trust", false, "Evaluate whether this machine trusts each certificate (reads the trust stores)")
}
