package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("certdiag %s\n", Version)
		fmt.Printf("  Built:  %s\n", BuildDate)
		fmt.Printf("  Commit: %s\n", GitCommit)
		printBundleVersions()
	},
}

// printBundleVersions names the shipped root snapshots and their dates. The
// date belongs on every surface that uses a bundle, and `version` is where a
// user checks how old their binary's view of the world is.
func printBundleVersions() {
	entries, err := certops.BundleStatus(bundleDirOrEmpty())
	if err != nil || len(entries) == 0 {
		return
	}
	fmt.Println("  Root CA snapshots (not a live browser read):")
	for _, e := range entries {
		origin := "embedded"
		if e.Installed {
			origin = "installed"
		}
		stale := ""
		if e.Stale {
			stale = "  STALE, run 'certdiag store update'"
		}
		fmt.Printf("    %-20s %s  %d anchors  (%s)%s\n", e.Name, e.ExtractedAt, e.Trusted, origin, stale)
	}
}
