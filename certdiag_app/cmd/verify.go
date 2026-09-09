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
	verifySel    storeSelectionFlags
	verifyOutput string
)

var verifyCmd = &cobra.Command{
	Use:   "verify <cert-file | host:port | https://host>",
	Short: "Verify certificate trust against a trust store",
	Long: `Verify whether a certificate, chain, or remote TLS endpoint is trusted
by a specific trust store.

The spelling of the argument decides what it is: host:port or a https:// or
tls:// URL is a remote endpoint that is dialed; anything else is a certificate
file, and a file that does not exist is an error. A bare name is never dialed.

Examples:
  certdiag verify server.crt                     # local cert vs OS store
  certdiag verify chain.pem                      # chain vs OS store
  certdiag verify example.com:443                # remote endpoint vs OS store
  certdiag verify https://example.com            # same, URL form (port 443)
  certdiag verify --java example.com:443         # "would Java trust this?"
  certdiag verify --trust-file /path/to/ca.pem server.crt`,
	Args: cobra.ExactArgs(1),
	Run:  runVerify,
}

func init() {
	verifySel.Register(verifyCmd, storeSelectionOpts{})
	verifyCmd.Flags().StringVarP(&verifyOutput, "output", "o", "human", "Output format: human, json, yaml")
	verifyCmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password(s) for encrypted files (can be repeated)")
	registerPasswordFileFlag(verifyCmd)
	registerRemoteConnectionFlags(verifyCmd.Flags())

	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) {
	if err := cmdutil.ValidateDisplayFormat(verifyOutput, cmdutil.OutputHuman, cmdutil.OutputJSON, cmdutil.OutputYAML); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	target := args[0]

	storeType, bundleID := verifySel.SingleStore()

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	pm := cliPasswordManager(cmd, cfg, "password", passwords, 1)

	// The connection flags are validated and completed from the config the
	// same way remote fetch does it; for a file target they are simply unused.
	settings, err := loadRemoteSettings()
	if err != nil {
		fail(1, "%v", err)
	}

	inputPasswords := pm.PasswordsForFile(target)

	opts := certops.VerifyOptions{
		Dial:      remoteDialOptions(settings),
		Target:    target,
		StoreType: storeType,
		BundleID:  bundleID,
		BundleDir: bundleDirOrEmpty(),
		JavaHome:  verifySel.JavaHome,
		FilePath:  verifySel.File,
		Passwords: inputPasswords,
	}

	result, err := certops.Verify(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	switch verifyOutput {
	case cmdutil.OutputJSON:
		out, err := output.FormatVerifyJSON(result.Result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
		fmt.Print(out)
	case cmdutil.OutputYAML:
		fmt.Print(output.FormatVerifyYAML(result.Result))
	default:
		fmt.Print(output.FormatVerifyHuman(result.Result))
	}

	if !result.Result.Trusted {
		os.Exit(1)
	}
}
