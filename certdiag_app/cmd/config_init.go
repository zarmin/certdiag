package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

var configInitForce bool

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write the example config file",
	Long: `Write the commented example config to the config path in effect
(-c, CERTDIAG_CONFIG, else ~/.certdiag/certdiag.yaml).

No other command creates this file: a diagnostic run leaves $HOME alone. An
existing file is never replaced unless --force is given. When only the legacy
~/.certdiag.yaml exists, run 'certdiag config migrate' instead.`,
	Args: cobra.NoArgs,
	Run:  runConfigInit,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Print the config file path in effect and whether it exists",
	Args:  cobra.NoArgs,
	Run:   runConfigPath,
}

func init() {
	configInitCmd.Flags().BoolVar(&configInitForce, "force", false, "Replace an existing config file")
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPathCmd)
}

func runConfigInit(cmd *cobra.Command, args []string) {
	if configFile == "" && os.Getenv("CERTDIAG_CONFIG") == "" && config.UsingLegacyConfig("") {
		legacy, _ := config.LegacyConfigPath()
		fail(1, "Error: the legacy config %s is in effect; run 'certdiag config migrate' to move it", legacy)
	}
	path, err := config.ResolveConfigPath(configFile)
	if err != nil {
		exitConfigError(err)
	}
	if _, statErr := os.Stat(path); statErr == nil && !configInitForce {
		fail(1, "Error: %s already exists (use --force to replace it)", path)
	}
	if err := config.WriteExampleConfig(path); err != nil {
		exitConfigError(err)
	}
	fmt.Printf("Wrote example config to %s\n", path)
}

func runConfigPath(cmd *cobra.Command, args []string) {
	path, err := config.ResolveConfigPath(configFile)
	if err != nil {
		exitConfigError(err)
	}
	fmt.Println(path)
	switch {
	case config.UsingLegacyConfig(configFile):
		fmt.Println("Status: legacy location ('certdiag config migrate' moves it)")
	case fileMissing(path):
		fmt.Println("Status: not found (using defaults; 'certdiag config init' creates the file)")
	default:
		fmt.Println("Status: exists")
	}
}

func fileMissing(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}
