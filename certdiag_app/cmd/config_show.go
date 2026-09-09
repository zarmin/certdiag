package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"gopkg.in/yaml.v3"
)

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display config file location and active settings",
	Long:  "Shows the resolved config file path and its contents with passwords redacted.",
	Run:   runConfigShow,
}

func init() {
	configCmd.AddCommand(configShowCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) {
	path, err := config.ResolveConfigPath(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error resolving config path: %v", err)))
		os.Exit(1)
	}

	fmt.Printf("Config file: %s\n", path)

	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		if configFile != "" {
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Config file not found: %s", path)))
			os.Exit(1)
		}
		fmt.Println("Status: not found (using defaults; 'certdiag config init' creates the file)")
		return
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error loading config: %v", err)))
		os.Exit(1)
	}

	if cfg == nil {
		fmt.Println("Status: not found (using defaults)")
		return
	}

	redacted := redactPasswords(cfg)

	out, err := yaml.Marshal(redacted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error marshaling config: %v", err)))
		os.Exit(1)
	}

	fmt.Println()
	fmt.Print(string(out))
}

func redactPasswords(cfg *config.ConfigFile) *config.ConfigFile {
	copy := *cfg

	pw := copy.Passwords
	pw.CommonPlaintext = make([]string, len(cfg.Passwords.CommonPlaintext))
	for i := range cfg.Passwords.CommonPlaintext {
		pw.CommonPlaintext[i] = "[redacted]"
	}

	pw.CommonEncrypted = make([]string, len(cfg.Passwords.CommonEncrypted))
	for i := range cfg.Passwords.CommonEncrypted {
		pw.CommonEncrypted[i] = "[encrypted]"
	}

	pw.ByFilename = make([]config.FilenamePassword, len(cfg.Passwords.ByFilename))
	for i, entry := range cfg.Passwords.ByFilename {
		pw.ByFilename[i] = entry
		if entry.PlaintextPassword != "" {
			pw.ByFilename[i].PlaintextPassword = "[redacted]"
		}
		if entry.EncryptedPassword != "" {
			pw.ByFilename[i].EncryptedPassword = "[encrypted]"
		}
	}

	copy.Passwords = pw
	return &copy
}
