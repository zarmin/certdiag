package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var completionCmd = &cobra.Command{
	Use:       "completion [bash|zsh|fish|powershell]",
	Short:     "Generate shell completion script",
	Long:      "Generate autocompletion script for the specified shell.",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Run:       runCompletion,
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

func runCompletion(cmd *cobra.Command, args []string) {
	var err error
	switch args[0] {
	case "bash":
		err = rootCmd.GenBashCompletion(os.Stdout)
	case "zsh":
		err = rootCmd.GenZshCompletion(os.Stdout)
	case "fish":
		err = rootCmd.GenFishCompletion(os.Stdout, true)
	case "powershell":
		err = rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: unsupported shell %q (valid: bash, zsh, fish, powershell)", args[0])))
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
}
