package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

var (
	reencPassword       string
	reencNewPassword    string
	reencOutput         string
	reencNoConfirm      bool
	reencLegacyPKCS12   bool
	reencRemovePassword bool
	reencEntry          string
	reencStorePassword  string
)

var reencryptCmd = &cobra.Command{
	Use:   "reencrypt <file>",
	Short: "Change the password of a certificate store",
	Long: `Change the password of a PKCS#12, JKS, or encrypted PEM file.
Reads the file with the current password and re-encodes it with a new password.

If -o is not specified, the file is overwritten in place.

For JKS files, use --entry to change a specific key entry's password
without changing the store password.

Examples:
  certdiag reencrypt server.p12 -p "oldpass" --new-password "newpass"
  certdiag reencrypt keystore.jks -p "old" --new-password "new" -o keystore-new.jks
  certdiag reencrypt server.p12 -p "oldpass" --new-password "newpass" --legacy-pkcs12
  certdiag reencrypt server.p12 -p "oldpass" --remove-password
  certdiag reencrypt keystore.jks -p "storepass" --entry mykey --new-password "newkeypass"
  certdiag reencrypt keystore.jks --store-password "storepass" -p "oldkeypass" --entry mykey --new-password "newkeypass"`,
	Args: cobra.ExactArgs(1),
	Run:  runReencrypt,
}

func init() {
	reencryptCmd.Flags().StringVarP(&reencPassword, "password", "p", "", "Current password")
	registerPasswordFileFlag(reencryptCmd)
	reencryptCmd.Flags().StringVar(&reencNewPassword, "new-password", "", "New password")
	reencryptCmd.Flags().StringVarP(&reencOutput, "output-file", "o", "", "Output file (default: overwrite in place)")
	reencryptCmd.Flags().BoolVar(&reencNoConfirm, "no-confirm", false, "Overwrite output file without confirmation")
	reencryptCmd.Flags().BoolVar(&reencLegacyPKCS12, "legacy-pkcs12", false, "Use legacy PKCS#12 algorithms for compatibility")
	reencryptCmd.Flags().BoolVar(&reencRemovePassword, "remove-password", false, "Remove password protection from the file")
	reencryptCmd.Flags().StringVar(&reencEntry, "entry", "", "Target a specific key entry by alias (JKS only)")
	reencryptCmd.Flags().StringVar(&reencStorePassword, "store-password", "", "Store password when different from -p (use with --entry)")

	rootCmd.AddCommand(reencryptCmd)
}

func runReencrypt(cmd *cobra.Command, args []string) {
	inputPath := args[0]

	info, err := os.Stat(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %s is a directory, not a file", inputPath)))
		os.Exit(1)
	}

	if reencRemovePassword && cmd.Flags().Changed("new-password") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --remove-password and --new-password are mutually exclusive"))
		os.Exit(1)
	}
	if cmd.Flags().Changed("store-password") && !cmd.Flags().Changed("entry") {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: --store-password requires --entry"))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)
	masterPw := resolveMasterPassword(false)

	// Resolve current password
	var oldPasswords []certlib.TaggedPassword
	if cmd.Flags().Changed("password") {
		oldPasswords = append(oldPasswords, certlib.TaggedPassword{
			Password: []byte(reencPassword),
			Source:   certlib.PasswordSourceCLI,
		})
	} else {
		pm, err := password.NewPasswordManager(password.PasswordManagerOpts{
			PasswordFiles:  passwordFiles,
			Config:         cfg,
			MasterPassword: masterPw,
		})
		if err != nil && len(passwordFiles) > 0 {
			fail(1, "Error: %v", err)
		}
		if err == nil {
			oldPasswords = pm.PasswordsForFile(inputPath)
		}

		if len(oldPasswords) == 0 {
			pw, err := password.PromptPassword("Enter current password: ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
				os.Exit(1)
			}
			oldPasswords = append(oldPasswords, certlib.TaggedPassword{
				Password: pw,
				Source:   certlib.PasswordSourceInteractive,
			})
		}
	}

	// When --entry is used with --store-password, add store password to candidates
	if cmd.Flags().Changed("store-password") {
		oldPasswords = append(oldPasswords, certlib.TaggedPassword{
			Password: []byte(reencStorePassword),
			Source:   certlib.PasswordSourceCLI,
		})
	}

	// Resolve new password
	var newPassword []byte
	if reencRemovePassword {
		newPassword = nil
	} else if cmd.Flags().Changed("new-password") {
		newPassword = []byte(reencNewPassword)
	} else {
		pwStr, err := cmdutil.PromptPasswordConfirm("Enter new password: ", "Confirm new password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}
		newPassword = []byte(pwStr)
	}

	opts := certops.ReencryptOptions{
		InputPath:    inputPath,
		OldPasswords: oldPasswords,
		NewPassword:  newPassword,
		OutputPath:   reencOutput,
		Overwrite:    reencNoConfirm,
		LegacyPKCS12: reencLegacyPKCS12,
		EntryAlias:   reencEntry,
	}
	if cmd.Flags().Changed("store-password") {
		opts.StorePassword = []byte(reencStorePassword)
	}

	result, err := certops.Reencrypt(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, w := range result.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	if reencEntry != "" {
		fmt.Fprintf(os.Stderr, "entry password changed: %s entry %q (%s) -> %s\n",
			inputPath, reencEntry, result.Format, result.OutputPath)
	} else if reencRemovePassword {
		fmt.Fprintf(os.Stderr, "password removed: %s (%s, %d items) -> %s\n",
			inputPath, result.Format, result.ItemCount, result.OutputPath)
	} else {
		fmt.Fprintf(os.Stderr, "password changed: %s (%s, %d items) -> %s\n",
			inputPath, result.Format, result.ItemCount, result.OutputPath)
	}

	if result.SkippedEntries > 0 {
		fmt.Fprintf(os.Stderr, "note: %d key entries use different passwords and were not changed (use --entry <alias> to change individually)\n",
			result.SkippedEntries)
	}
}
