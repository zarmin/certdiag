package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/crypto"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

var passwordChangeMasterKeyCmd = &cobra.Command{
	Use:   "change-master-key",
	Short: "Re-encrypt all config passwords with a new master key",
	Run:   runPasswordChangeMasterKey,
}

var changeMasterKeyNewPasswordFile string

func init() {
	passwordChangeMasterKeyCmd.Flags().StringVar(&changeMasterKeyNewPasswordFile, "new-master-password-file", "",
		"Read the new master password from the first line of this file instead of prompting (CERTDIAG_NEW_MASTER_KEY is also honoured)")
	passwordCmd.AddCommand(passwordChangeMasterKeyCmd)
}

func runPasswordChangeMasterKey(cmd *cobra.Command, args []string) {
	cfgPath, err := config.ResolveConfigPath(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	rawData, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error reading config: %v", err)))
		os.Exit(1)
	}

	cfg := cmdutil.LoadConfigOrExit(configFile, 1)

	if cfg == nil || !cfg.HasEncryptedPasswords() {
		fmt.Fprintln(os.Stderr, "No encrypted passwords found in config, nothing to do.")
		return
	}

	oldMasterPw := resolveOldMasterPassword()
	if len(oldMasterPw) == 0 {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: old master password is required"))
		os.Exit(1)
	}

	type encPair struct {
		oldEncrypted string
		plaintext    []byte
	}
	var pairs []encPair

	for i, enc := range cfg.Passwords.CommonEncrypted {
		dec, err := crypto.Decrypt(oldMasterPw, enc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: failed to decrypt common_encrypted[%d]: %v", i, err)))
			os.Exit(1)
		}
		pairs = append(pairs, encPair{enc, dec})
	}
	for i, fp := range cfg.Passwords.ByFilename {
		if fp.EncryptedPassword == "" {
			continue
		}
		dec, err := crypto.Decrypt(oldMasterPw, fp.EncryptedPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: failed to decrypt by_filename[%d]: %v", i, err)))
			os.Exit(1)
		}
		pairs = append(pairs, encPair{fp.EncryptedPassword, dec})
	}

	newMasterPw, err := resolveNewMasterPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	// Match the source config's mode (default 0600) so the backup and rewrite
	// never widen permissions on a file that may contain plaintext passwords.
	cfgMode := os.FileMode(0o600)
	if info, statErr := os.Stat(cfgPath); statErr == nil {
		cfgMode = info.Mode().Perm()
	}

	backupPath := cfgPath + ".bak"
	if err := os.WriteFile(backupPath, rawData, cfgMode); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error creating backup: %v", err)))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Backup created: %s (delete it after verifying the config works)\n", backupPath)

	replacements := make(map[string]string, len(pairs))
	for _, p := range pairs {
		newEnc, err := crypto.Encrypt(newMasterPw, p.plaintext)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: re-encrypt failed: %v", err)))
			os.Exit(1)
		}
		replacements[p.oldEncrypted] = newEnc
	}

	newData, err := config.RewriteEncryptedPasswords(rawData, replacements)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error rewriting config: %v", err)))
		os.Exit(1)
	}

	if err := os.WriteFile(cfgPath, newData, cfgMode); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error writing config: %v", err)))
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Master key changed successfully.")
}

func resolveOldMasterPassword() []byte {
	if masterPasswordFlag != "" {
		return []byte(masterPasswordFlag)
	}
	if env := os.Getenv("CERTDIAG_MASTER_KEY"); env != "" {
		return []byte(env)
	}
	pw, err := password.PromptPassword("Enter old master password: ")
	if err != nil {
		return nil
	}
	return pw
}

// resolveNewMasterPassword takes the new key from --new-master-password-file,
// then CERTDIAG_NEW_MASTER_KEY, and prompts only when neither is set, so the
// round trip can run unattended (M31 WP12).
func resolveNewMasterPassword() ([]byte, error) {
	var pw []byte
	switch {
	case changeMasterKeyNewPasswordFile != "":
		data, err := os.ReadFile(changeMasterKeyNewPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("new master password file: %w", err)
		}
		line, _, _ := bytes.Cut(data, []byte("\n"))
		pw = bytes.TrimRight(line, "\r")
	case os.Getenv("CERTDIAG_NEW_MASTER_KEY") != "":
		pw = []byte(os.Getenv("CERTDIAG_NEW_MASTER_KEY"))
	default:
		return promptNewMasterPassword()
	}
	if len(pw) < 6 {
		return nil, fmt.Errorf("new master password must be at least 6 characters")
	}
	return pw, nil
}

func promptNewMasterPassword() ([]byte, error) {
	for {
		pw1, err := password.PromptPassword("Enter new master password: ")
		if err != nil {
			return nil, err
		}
		if len(pw1) < 6 {
			fmt.Fprintln(os.Stderr, output.ColorizeError("Error: password must be at least 6 characters"))
			continue
		}
		pw2, err := password.PromptPassword("Confirm new master password: ")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pw1, pw2) {
			fmt.Fprintln(os.Stderr, output.ColorizeError("Error: passwords do not match, try again"))
			continue
		}
		return pw1, nil
	}
}
