package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	schemaConfigFlag bool
	schemaRemoteFlag bool
)

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Print JSON Schema for the structured output format",
	Long:  "Prints a JSON Schema (Draft 2020-12) describing the structured output produced by --output json and --output yaml. Use --config for the config file schema, or --remote for the remote inspection output schema.",
	Run: func(cmd *cobra.Command, args []string) {
		if schemaConfigFlag && schemaRemoteFlag {
			fmt.Fprintln(os.Stderr, "Error: --config and --remote are mutually exclusive")
			os.Exit(1)
		}
		var (
			schema string
			err    error
		)
		switch {
		case schemaConfigFlag:
			schema, err = config.GenerateJSONSchema()
		case schemaRemoteFlag:
			schema, err = output.GenerateRemoteJSONSchema()
		default:
			schema, err = output.GenerateJSONSchema()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating schema: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(schema)
	},
}

func init() {
	schemaCmd.Flags().BoolVar(&schemaConfigFlag, "config", false, "Print the config file schema instead of the output schema")
	schemaCmd.Flags().BoolVar(&schemaRemoteFlag, "remote", false, "Print the remote inspection output schema")
}
