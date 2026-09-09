package cmd

import (
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list [paths...]",
	Short: "List certificates (alias for root command)",
	Long: `Alias for the root command. Scans files and directories for certificates.

See 'certdiag --help' for information about colored output and other features.`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			args = []string{"."}
		}
		runRoot(cmd, args)
	},
}

func init() {
	registerPasswordFlags(listCmd, passwordFlagOpts{prompt: true, noTryAll: true})
	registerScanFlags(listCmd)
}
