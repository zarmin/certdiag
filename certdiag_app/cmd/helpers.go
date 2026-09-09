package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

// warnf prints a colorized warning and continues.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeWarning(fmt.Sprintf(format, args...)))
}

// fail prints a colorized error and exits with code.
func fail(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf(format, args...)))
	os.Exit(code)
}

// cliPasswordManager builds the non-interactive password manager most write
// commands use: the config's passwords plus the command's own --password flag
// (values, taken only when flagName was set). Exits with code on failure.
func cliPasswordManager(cmd *cobra.Command, cfg *config.ConfigFile, flagName string, values []string, code int) *password.PasswordManager {
	var cliPasswords []string
	if cmd.Flags().Changed(flagName) {
		cliPasswords = values
	}
	pm, err := cmdutil.NewSimplePasswordManager(cliPasswords, passwordFiles, cfg, resolveMasterPassword(false))
	if err != nil {
		fail(code, "Error: %v", err)
	}
	return pm
}

// mustOutputPassword resolves the output container password or exits.
func mustOutputPassword(cmd *cobra.Command, format certlib.FileFormat) []byte {
	pw, err := cmdutil.OutputPassword(cmd, format)
	if err != nil {
		fail(1, "Error: %v", err)
	}
	return pw
}

// mustEncryptKeyPassword resolves the generated-key encryption password when
// encrypt is set, or exits.
func mustEncryptKeyPassword(cmd *cobra.Command, encrypt bool, flagName string, format certlib.FileFormat) []byte {
	if !encrypt {
		return nil
	}
	pw, err := cmdutil.EncryptKeyPassword(cmd, flagName, passwordFiles, format)
	if err != nil {
		fail(1, "Error: %v", err)
	}
	return pw
}

// mustKeyDestination applies decision D1 or exits.
func mustKeyDestination(certOut, keyOut string, withKey bool) string {
	dest, err := cmdutil.KeyDestination(certOut, keyOut, withKey)
	if err != nil {
		fail(1, "Error: %v", err)
	}
	return dest
}

// printSkipped tells the user what a scan passed over. Skipped files are not
// errors and do not change the exit code; the list is on stderr and detailed
// on request, so a missing file is never mistaken for an empty one.
func printSkipped(skipped []certlib.SkippedFile, detailLevel int) {
	if len(skipped) == 0 {
		return
	}
	if detailLevel > 0 {
		fmt.Fprintf(os.Stderr, "certdiag: %d file(s) skipped:\n", len(skipped))
		for _, sk := range skipped {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", sk.Path, sk.Reason)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "certdiag: %d file(s) skipped (run with -d to list them)\n", len(skipped))
}
