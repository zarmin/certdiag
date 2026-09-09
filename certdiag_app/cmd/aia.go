package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/cmdutil"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var aiaCmd = &cobra.Command{
	Use:   "aia",
	Short: "Inspect the AIA certificate cache",
	Long: `Manage the cache of issuer certificates fetched over Authority Information Access.

The cache stores certificates, never trust decisions: a cached certificate is
signature-checked again on every use and the verdict is recomputed. Everywhere
certdiag uses one it says so, with the date it was fetched.

The cache is off unless defaults.aia.cache is enabled in the config.`,
}

var aiaCacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Show or clear the AIA certificate cache",
}

var aiaCacheListCmd = &cobra.Command{
	Use:   "list",
	Short: "List cached issuer certificates",
	Run: func(cmd *cobra.Command, args []string) {
		cache, err := openAIACacheForCmd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: "+err.Error()))
			os.Exit(1)
		}
		entries := cache.List()

		if aiaOutputFormat == "json" {
			data, _ := json.MarshalIndent(entries, "", "  ")
			fmt.Println(string(data))
			return
		}
		if len(entries) == 0 {
			fmt.Println("AIA cache is empty")
			return
		}
		for _, e := range entries {
			fmt.Printf("%s\n  url:     %s\n  fetched: %s\n  expires: %s\n",
				e.Subject, e.URL,
				e.FetchedAt.Format("2006-01-02 15:04"),
				e.ExpiresAt.Format("2006-01-02 15:04"))
		}
		fmt.Printf("\n%d cached certificate(s)\n", len(entries))
	},
}

var aiaCacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Remove every cached issuer certificate",
	Run: func(cmd *cobra.Command, args []string) {
		cache, err := openAIACacheForCmd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: "+err.Error()))
			os.Exit(1)
		}
		if err := cache.Clear(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError("Error: "+err.Error()))
			os.Exit(1)
		}
		fmt.Println("AIA cache cleared")
	},
}

var aiaOutputFormat string

func openAIACacheForCmd() (*certops.FileAIACache, error) {
	ttl := ""
	if cfg := cmdutil.LoadConfigOrExit(configFile, 1); cfg != nil {
		ttl = cfg.Defaults.AIA.CacheTTL
	}
	return certops.OpenAIACache(ttl)
}

func init() {
	aiaCacheListCmd.Flags().StringVarP(&aiaOutputFormat, "output", "o", "human", "Output format: human, json")
	aiaCacheCmd.AddCommand(aiaCacheListCmd, aiaCacheClearCmd)
	aiaCmd.AddCommand(aiaCacheCmd)
	rootCmd.AddCommand(aiaCmd)
}
