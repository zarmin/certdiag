package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/crypto"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
	"golang.org/x/term"
)

var passwordEncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a password for use in config file",
	Long: `Encrypt a password for use in config file.

The master password is read from --master-password flag, CERTDIAG_MASTER_KEY env var,
or interactively prompted when running in a terminal.

The password to encrypt can be supplied via -p <password> (insecure: visible in process list),
interactively when running in a terminal, or via piped stdin.

Piping examples:
  With master key in env:
    echo "mypass" | CERTDIAG_MASTER_KEY=master123 certdiag password encrypt

  With both on stdin (master password first, then password to encrypt):
    printf "master123\nmypass\n" | certdiag password encrypt`,
	Run: runPasswordEncrypt,
}

func init() {
	passwordCmd.AddCommand(passwordEncryptCmd)
	passwordEncryptCmd.Flags().StringArrayVarP(&passwords, "password", "p", nil, "Password to encrypt (insecure: visible in process list)")
}

func runPasswordEncrypt(cmd *cobra.Command, args []string) {
	isTty := term.IsTerminal(int(os.Stdin.Fd()))

	var masterPw []byte
	var plaintext []byte

	if !isTty {
		masterAvailable := masterPasswordFlag != "" || os.Getenv("CERTDIAG_MASTER_KEY") != ""
		scanner := bufio.NewScanner(os.Stdin)

		if !masterAvailable {
			if scanner.Scan() {
				masterPw = []byte(strings.TrimSpace(scanner.Text()))
			}
		}

		if len(passwords) > 0 {
			plaintext = []byte(passwords[0])
		} else if scanner.Scan() {
			plaintext = []byte(strings.TrimSpace(scanner.Text()))
		}

		if len(masterPw) == 0 {
			masterPw = resolveMasterPassword(false)
		}
	} else {
		masterPw = resolveMasterPassword(true)

		if len(passwords) > 0 {
			plaintext = []byte(passwords[0])
		} else {
			var err error
			plaintext, err = password.PromptPassword("Enter password to encrypt: ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
				os.Exit(1)
			}
		}
	}

	if len(masterPw) == 0 {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: master password is required"))
		os.Exit(1)
	}

	if plaintext == nil {
		fmt.Fprintln(os.Stderr, output.ColorizeError("Error: password to encrypt is required"))
		os.Exit(1)
	}

	encoded, err := crypto.Encrypt(masterPw, plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	fmt.Println(encoded)
}
