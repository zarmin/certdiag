package cmdutil

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

func NewSimplePasswordManager(cliPasswords, passwordFiles []string, cfg *config.ConfigFile, masterPW []byte) (*password.PasswordManager, error) {
	return password.NewPasswordManager(password.PasswordManagerOpts{
		CLIPasswords:   cliPasswords,
		PasswordFiles:  passwordFiles,
		Config:         cfg,
		MasterPassword: masterPW,
	})
}

func PromptPasswordConfirm(prompt, confirmPrompt string) (string, error) {
	pw1, err := password.PromptPassword(prompt)
	if err != nil {
		return "", err
	}
	pw2, err := password.PromptPassword(confirmPrompt)
	if err != nil {
		return "", err
	}
	if string(pw1) != string(pw2) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(pw1), nil
}

// FlagPassword returns the value of a string password flag and whether the
// user set it at all. An explicitly empty value is a real answer (no password),
// which is why the presence bit is separate from the bytes.
func FlagPassword(cmd *cobra.Command, flagName string) ([]byte, bool) {
	if !cmd.Flags().Changed(flagName) {
		return nil, false
	}
	val, _ := cmd.Flags().GetString(flagName)
	return []byte(val), true
}

// NeedsOutputPassword reports whether a container format is always written
// under a password.
func NeedsOutputPassword(format certlib.FileFormat) bool {
	return format == certlib.FormatPKCS12 || format == certlib.FormatJKS
}

// OutputPassword resolves the password for a written PKCS#12/JKS container:
// --output-password when given, otherwise a confirmed prompt. Other formats
// need none and get nil.
func OutputPassword(cmd *cobra.Command, format certlib.FileFormat) ([]byte, error) {
	if !NeedsOutputPassword(format) {
		return nil, nil
	}
	if pw, ok := FlagPassword(cmd, "output-password"); ok {
		return pw, nil
	}
	pwStr, err := PromptPasswordConfirm("Enter output password: ", "Confirm output password: ")
	if err != nil {
		return nil, err
	}
	return []byte(pwStr), nil
}

// EncryptKeyPassword resolves the password for an encrypted generated key:
// the named flag when given, else the first password in the password files,
// otherwise a confirmed prompt. Encrypted DER is not a thing, and an empty
// password is refused.
func EncryptKeyPassword(cmd *cobra.Command, flagName string, passwordFiles []string, format certlib.FileFormat) ([]byte, error) {
	if format == certlib.FormatDER {
		return nil, fmt.Errorf("encrypted DER output is not supported, use PEM format")
	}
	var pw []byte
	if p, ok := FlagPassword(cmd, flagName); ok {
		pw = p
	} else if len(passwordFiles) > 0 {
		filePasswords, err := password.ReadPasswordFiles(passwordFiles)
		if err != nil {
			return nil, err
		}
		if len(filePasswords) == 0 {
			return nil, fmt.Errorf("no password found in %s", strings.Join(passwordFiles, ", "))
		}
		pw = filePasswords[0]
	} else {
		pwStr, err := PromptPasswordConfirm("Enter key encryption password: ", "Confirm key encryption password: ")
		if err != nil {
			return nil, err
		}
		pw = []byte(pwStr)
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("encryption password cannot be empty")
	}
	return pw, nil
}
