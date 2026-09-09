package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/opensslcmd"
)

var (
	showOpenSSLFlag bool
	dryRunFlag      bool
)

// annotationOpenSSL marks commands that implement --show-openssl / --dry-run.
// The persistent flags exist on every command, so this is how the pre-run guard
// tells a supported command from one where the flags would be silently ignored.
const annotationOpenSSL = "supports_openssl"

func markOpenSSLSupported(c *cobra.Command) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[annotationOpenSSL] = "1"
}

func supportsOpenSSL(c *cobra.Command) bool {
	return c != nil && c.Annotations[annotationOpenSSL] == "1"
}

// validateOpenSSLFlags rejects --show-openssl / --dry-run on commands that do
// not implement them, and enforces that --dry-run is only meaningful together
// with --show-openssl. Without this, both flags are silently ignored (files are
// still written), which for a write-avoidance flag is dangerous.
func validateOpenSSLFlags(cmd *cobra.Command) error {
	if (showOpenSSLFlag || dryRunFlag) && !supportsOpenSSL(cmd) {
		return fmt.Errorf("--show-openssl/--dry-run is not supported for %q", cmd.CommandPath())
	}
	if dryRunFlag && !showOpenSSLFlag {
		return fmt.Errorf("--dry-run requires --show-openssl")
	}
	return nil
}

// renderOpenSSL prints the labelled equivalent block. In --dry-run mode the
// command is the output, so it goes to stdout; otherwise it is auxiliary to the
// real artifact and goes to stderr.
func renderOpenSSL(cmds []opensslcmd.Command) {
	w := os.Stderr
	if dryRunFlag {
		w = os.Stdout
	}
	fmt.Fprintln(w, opensslcmd.Render(cmds...))
}

func buildInspectOpenSSL(store *certlib.CertStore) []opensslcmd.Command {
	var cmds []opensslcmd.Command
	for i := range store.Containers {
		c := &store.Containers[i]
		if c.RelationsOnly || c.FilePath == "" {
			continue
		}
		// Bundle containers (PKCS#12/JKS/PKCS#7) map to a single listing command
		// regardless of how many items they hold.
		if c.Format.IsBundleFormat() {
			cmds = append(cmds, opensslcmd.Inspect(c.FilePath, "", c.Format))
			continue
		}
		seen := make(map[certlib.ContentType]bool)
		for _, item := range c.Items {
			// One inspect command per distinct content type per file.
			if seen[item.Type] {
				continue
			}
			seen[item.Type] = true
			cmds = append(cmds, opensslcmd.Inspect(c.FilePath, item.Type, c.Format))
		}
	}
	return cmds
}

func buildRemoteFetchOpenSSL(targets []string, starttls, hostname string, disableSNI bool) []opensslcmd.Command {
	var cmds []opensslcmd.Command
	for _, t := range targets {
		rt, err := certlib.ParseTarget(t)
		if err != nil {
			cmds = append(cmds, opensslcmd.Command{Notes: []string{fmt.Sprintf("could not parse target %q: %v", t, err)}})
			continue
		}
		sni := rt.SNI
		if hostname != "" {
			sni = hostname
		}
		cmds = append(cmds, opensslcmd.RemoteFetch(opensslcmd.RemoteSpec{
			Host:       rt.Host,
			Port:       rt.Port,
			SNI:        sni,
			DisableSNI: disableSNI,
			Starttls:   starttls,
			ShowCerts:  true,
		}))
	}
	return cmds
}
