package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var configMigrateDryRun bool

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect and maintain the certdiag configuration",
}

var configMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Move a legacy ~/.certdiag.yaml into ~/.certdiag/certdiag.yaml",
	Long: `Move the legacy config file into the current directory layout.

certdiag keeps its configuration and its installed root CA snapshots together:

  ~/.certdiag/certdiag.yaml
  ~/.certdiag/bundles/

A legacy ~/.certdiag.yaml keeps working indefinitely and is never moved
automatically: it can contain passwords, and relocating it silently during an
unrelated scan is not something a diagnostic tool should do. This command makes
the move explicit. The old file is removed only after the copy is verified to
parse at the new location.`,
	Run: runConfigMigrate,
}

func init() {
	configMigrateCmd.Flags().BoolVar(&configMigrateDryRun, "dry-run", false, "Report what would happen and change nothing")
	configCmd.AddCommand(configMigrateCmd)
	rootCmd.AddCommand(configCmd)
}

func runConfigMigrate(cmd *cobra.Command, args []string) {
	legacy, err := config.LegacyConfigPath()
	if err != nil {
		exitConfigError(err)
	}
	target, err := config.DefaultConfigPath()
	if err != nil {
		exitConfigError(err)
	}

	legacyInfo, err := os.Stat(legacy)
	if err != nil {
		fmt.Printf("No legacy config at %s; nothing to migrate.\n", legacy)
		return
	}

	if _, err := os.Stat(target); err == nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(
			fmt.Sprintf("%s already exists; refusing to overwrite it. Merge %s by hand and delete it.", target, legacy)))
		os.Exit(1)
	}

	if configMigrateDryRun {
		fmt.Printf("Would move %s -> %s (%d bytes)\n", legacy, target, legacyInfo.Size())
		return
	}

	data, err := os.ReadFile(legacy)
	if err != nil {
		exitConfigError(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		exitConfigError(err)
	}
	// Preserve the original mode: the file can hold passwords.
	if err := os.WriteFile(target, data, legacyInfo.Mode().Perm()); err != nil {
		exitConfigError(err)
	}

	// Verify the copy parses before the original is removed.
	if _, err := config.LoadConfig(target); err != nil {
		os.Remove(target)
		exitConfigError(fmt.Errorf("copy at %s did not parse, left %s untouched: %w", target, legacy, err))
	}

	if err := os.Remove(legacy); err != nil {
		fmt.Fprintf(os.Stderr, "certdiag: copied to %s but could not remove %s: %v\n", target, legacy, err)
		os.Exit(1)
	}

	fmt.Printf("Moved %s -> %s\n", legacy, target)
}

func exitConfigError(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
	os.Exit(1)
}
