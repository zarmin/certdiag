package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/crypto"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"golang.org/x/term"
)

var passwordDecryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an encrypted password",
	Run:   runPasswordDecrypt,
}

func init() {
	passwordCmd.AddCommand(passwordDecryptCmd)
}

func runPasswordDecrypt(cmd *cobra.Command, args []string) {
	masterPw := resolveMasterPassword(true)
	if len(masterPw) == 0 {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: master password is required"))
		os.Exit(1)
	}

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Encrypted password: ")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	encoded := strings.TrimSpace(scanner.Text())
	if encoded == "" {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: no encrypted string provided"))
		os.Exit(1)
	}

	decrypted, err := crypto.Decrypt(masterPw, encoded)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("  String: %s", encoded)))
		os.Exit(1)
	}
	fmt.Println(string(decrypted))
}
