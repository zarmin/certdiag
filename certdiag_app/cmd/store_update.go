package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

var (
	storeUpdateSource string
	storeUpdateDryRun bool
	storeUpdateImport string
	storeUpdateStatus bool
	storeUpdateFrom   string
)

var storeUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Refresh the shipped root CA snapshots",
	Long: `Refresh the Mozilla and Chrome root CA snapshots certdiag ships.

The snapshots are compiled into the binary so an air-gapped host always has an
answer. This command installs a newer copy under ~/.certdiag/bundles/, which
then takes precedence over the compiled-in one.

Network is used only by this command, and only when --import and --from are
absent. Nothing else in certdiag reaches out for a bundle, and there is no
automatic or background update.

On a host with no route out, refresh on a connected machine and carry the
resulting ~/.certdiag/bundles directory across:

  certdiag store update --import /media/usb/bundles

An imported bundle is validated exactly like a downloaded one.` + "\n\n" + BundleHelpText,
	Run: runStoreUpdate,
}

func init() {
	storeUpdateCmd.Flags().StringVar(&storeUpdateSource, "source", "all", "Which snapshot to refresh: mozilla, chrome or all")
	storeUpdateCmd.Flags().BoolVar(&storeUpdateDryRun, "dry-run", false, "Report what would change and write nothing")
	storeUpdateCmd.Flags().StringVar(&storeUpdateImport, "import", "", "Install a bundle prepared elsewhere (directory, or a manifest .json)")
	storeUpdateCmd.Flags().BoolVar(&storeUpdateStatus, "status", false, "Show snapshot dates and origin, then exit")
	storeUpdateCmd.Flags().StringVar(&storeUpdateFrom, "from", "", "Read the upstream vendor files from this directory instead of the network")
	storeCmd.AddCommand(storeUpdateCmd)
}

func runStoreUpdate(cmd *cobra.Command, args []string) {
	dir := bundleDirOrEmpty()

	if storeUpdateStatus {
		printBundleStatus(dir)
		return
	}

	var ids []string
	switch strings.ToLower(storeUpdateSource) {
	case "", "all":
		ids = nil
	case truststore.BundleMozilla, truststore.BundleChrome:
		ids = []string{strings.ToLower(storeUpdateSource)}
	default:
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("unknown --source %q (mozilla, chrome or all)", storeUpdateSource)))
		os.Exit(1)
	}

	result, err := certops.BundleUpdate(certops.BundleUpdateOptions{
		IDs:        ids,
		Dir:        dir,
		FromDir:    storeUpdateFrom,
		ImportPath: storeUpdateImport,
		DryRun:     storeUpdateDryRun,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	failed := false
	for _, e := range result.Entries {
		if e.Err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("%s: %v", e.ID, e.Err)))
			continue
		}

		switch {
		case e.Skipped != "":
			fmt.Printf("%s: %d -> %d trust anchors (%s, nothing written)\n", e.ID, e.Before, e.After, e.Skipped)
		case e.Written:
			fmt.Printf("%s: installed %d trust anchors (snapshot %s) in %s\n",
				e.ID, e.After, e.Manifest.ExtractedAt, result.Dir)
		}
		printAnchorDiff(e)
	}

	if failed {
		os.Exit(1)
	}
}

func printAnchorDiff(e certops.BundleUpdateEntry) {
	for _, n := range e.Added {
		fmt.Println("  + " + n)
	}
	for _, n := range e.Removed {
		fmt.Println("  - " + n)
	}
}

func printBundleStatus(dir string) {
	entries, err := certops.BundleStatus(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", output.ColorizeError(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	for _, e := range entries {
		fmt.Printf("%s (%s)\n", e.Name, e.ID)
		fmt.Printf("  snapshot:  %s (%d days old)\n", e.ExtractedAt, e.AgeDays)
		fmt.Printf("  origin:    %s\n", e.Origin)
		fmt.Printf("  source:    %s\n", e.SourceURL)
		fmt.Printf("  license:   %s\n", e.License)
		fmt.Printf("  anchors:   %d trusted, %d distrusted\n", e.Trusted, e.Distrusted)
		if e.Stale {
			fmt.Printf("  %s\n", output.ColorizeTrust("STALE")+" run 'certdiag store update' to refresh")
		}
		for _, c := range e.Caveats {
			fmt.Printf("  caveat:    %s\n", c)
		}
		fmt.Println()
	}
}
