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
	createKeyFlags     cmdutil.KeyGenFlags
	createKeyOutput    string
	createKeyFormat    string
	createKeyEncrypt   bool
	createKeyPassword  string
	createKeyNoConfirm bool
)

var createKeyCmd = &cobra.Command{
	Use:   "create-key",
	Short: "Generate a new private key",
	Long: `Generate a new private key (RSA, ECDSA, or Ed25519).

The key is written to a file (-o) or to stdout. Output format can be PEM (default) or DER.
Algorithm, key size, and curve default to config values or built-in defaults (ECDSA P-256).

Examples:
  certdiag create-key                           # ECDSA P-256 to stdout
  certdiag create-key -a rsa -s 4096 -o key.pem # RSA-4096 to file
  certdiag create-key -a ed25519 -o ed.key      # Ed25519 to file
  certdiag create-key --encrypt-key -p pass -o k.pem # Encrypted PEM
  certdiag create-key -f der -o key.der          # DER format`,
	Args: cobra.NoArgs,
	Run:  runCreateKey,
}

func init() {
	createKeyFlags.Register(createKeyCmd, "")
	createKeyCmd.Flags().StringVarP(&createKeyOutput, "output-file", "o", "", "Output file path (default: stdout)")
	createKeyCmd.Flags().StringVarP(&createKeyFormat, "format", "f", "", "Output format: pem, der (default: pem)")
	createKeyCmd.Flags().BoolVar(&createKeyEncrypt, "encrypt-key", false, "Encrypt the private key with a password")
	createKeyCmd.Flags().StringVarP(&createKeyPassword, "password", "p", "", "Password for encryption (prompted if not given)")
	registerPasswordFileFlag(createKeyCmd)
	createKeyCmd.Flags().BoolVar(&createKeyNoConfirm, "no-confirm", false, "Overwrite output file without confirmation")

	markOpenSSLSupported(createKeyCmd)
	rootCmd.AddCommand(createKeyCmd)
}

func runCreateKey(cmd *cobra.Command, args []string) {
	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	defaults := (&config.ConfigFile{}).GetKeyDefaults()
	if cfg != nil {
		defaults = cfg.GetKeyDefaults()
	}

	var configFmt string
	if cfg != nil {
		configFmt = cfg.Defaults.Output.Format
	}
	format, err := cmdutil.ResolveOutputFormat(createKeyFormat, configFmt, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	createKeyFlags.ApplyChanged(cmd, &defaults)

	if err := cmdutil.ValidateKeyParams(cmd, defaults.Algorithm, defaults.KeySize, defaults.Curve); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	pw := mustEncryptKeyPassword(cmd, createKeyEncrypt, "password", format)

	opts := certops.GenerateKeyOptions{
		Algorithm:  defaults.Algorithm,
		KeySize:    defaults.KeySize,
		Curve:      defaults.Curve,
		OutputPath: createKeyOutput,
		Format:     format,
		Encrypt:    createKeyEncrypt,
		Password:   pw,
		Overwrite:  createKeyNoConfirm,
	}

	if showOpenSSLFlag {
		renderOpenSSL(certops.OpenSSLForGenerateKey(opts))
		if dryRunFlag {
			return
		}
	}

	result, err := certops.GenerateKey(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if !result.Written {
		os.Stdout.Write(result.KeyBytes)
	}

	encLabel := ""
	if createKeyEncrypt {
		encLabel = ", encrypted"
	}
	if result.Written {
		fmt.Fprintf(os.Stderr, "created %s private key (%s%s) -> %s\n", result.KeyType, format, encLabel, result.OutputPath)
	} else {
		fmt.Fprintf(os.Stderr, "created %s private key (%s%s)\n", result.KeyType, format, encLabel)
	}
}
