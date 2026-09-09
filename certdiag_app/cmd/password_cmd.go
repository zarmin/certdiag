package cmd

import (
	"github.com/spf13/cobra"
)

var passwordCmd = &cobra.Command{
	Use:   "password",
	Short: "Password management commands",
	Long:  "Encrypt and decrypt passwords for use in certdiag configuration files.",
}

func init() {
	rootCmd.AddCommand(passwordCmd)
}
