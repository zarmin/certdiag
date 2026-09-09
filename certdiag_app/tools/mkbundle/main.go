// Command mkbundle refreshes the embedded browser root bundles.
//
// It is a maintainer tool, run deliberately through `task update-bundles` and
// committed. It is never part of the normal build: the build stays offline and
// reproducible.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

const (
	defaultMinAnchor = certops.MinTrustAnchors
	defaultMaxDrop   = certops.MaxAnchorDropFraction
)

func main() {
	source := flag.String("source", "all", "which bundle to refresh: mozilla, chrome or all")
	out := flag.String("out", "internal/certlib/truststore/bundles", "output directory")
	diffOnly := flag.Bool("diff", false, "report the difference against the committed bundles and exit")
	minAnchors := flag.Int("min", defaultMinAnchor, "refuse to write fewer than this many trust anchors")
	maxDrop := flag.Float64("max-drop", defaultMaxDrop, "refuse a drop larger than this fraction of the committed anchor count")
	fromDir := flag.String("from", "", "read the upstream files from this directory instead of the network")
	flag.Parse()

	if err := run(*source, *out, *fromDir, *diffOnly, *minAnchors, *maxDrop); err != nil {
		fmt.Fprintln(os.Stderr, "mkbundle:", err)
		os.Exit(1)
	}
}

func run(source, outDir, fromDir string, diffOnly bool, minAnchors int, maxDrop float64) error {
	targets := []string{}
	switch source {
	case "all":
		targets = []string{truststore.BundleMozilla, truststore.BundleChrome}
	case truststore.BundleMozilla, truststore.BundleChrome:
		targets = []string{source}
	default:
		return fmt.Errorf("unknown source %q", source)
	}

	for _, id := range targets {
		if err := refresh(id, outDir, fromDir, diffOnly, minAnchors, maxDrop); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return nil
}

func refresh(id, outDir, fromDir string, diffOnly bool, minAnchors int, maxDrop float64) error {
	parsed, manifest, err := certops.FetchBundle(id, fromDir)
	if err != nil {
		return err
	}

	// A truncated download that silently replaces a good bundle is the worst
	// outcome this tool can produce, so both guards are hard failures.
	if len(parsed.Trusted) < minAnchors {
		return fmt.Errorf("only %d trust anchors parsed, below the floor of %d; refusing to write",
			len(parsed.Trusted), minAnchors)
	}

	previous, prevErr := readManifest(filepath.Join(outDir, id+".json"))
	if prevErr == nil && previous.TrustedCount > 0 {
		drop := float64(previous.TrustedCount-len(parsed.Trusted)) / float64(previous.TrustedCount)
		if drop > maxDrop {
			return fmt.Errorf("anchor count fell from %d to %d (%.0f%%), above the %.0f%% limit; refusing to write",
				previous.TrustedCount, len(parsed.Trusted), drop*100, maxDrop*100)
		}
	}

	printDiff(id, outDir, parsed)
	if diffOnly {
		return nil
	}

	files, err := truststore.RenderBundle(manifest, parsed, truststore.LicenceHeader(id))
	if err != nil {
		return err
	}
	if err := truststore.WriteBundleFiles(outDir, id, files); err != nil {
		return err
	}
	if err := writeLicence(outDir, id); err != nil {
		return err
	}

	fmt.Printf("%s: wrote %d trusted, %d distrusted to %s\n",
		id, len(parsed.Trusted), len(parsed.Distrusted), outDir)
	return nil
}

func readManifest(path string) (truststore.BundleManifest, error) {
	var m truststore.BundleManifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

// printDiff reports what changed against the committed bundle, so the resulting
// commit is reviewable rather than an opaque blob change.
func printDiff(id, outDir string, parsed *truststore.ParsedBundle) {
	existing, err := truststore.LoadBundle(id, outDir)
	if err != nil {
		fmt.Printf("%s: no committed bundle to compare against\n", id)
		return
	}

	before := subjectSet(existing.Trusted)
	after := make(map[string]string)
	for _, c := range parsed.Trusted {
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(c.DER)
		after[hex.EncodeToString(sum[:])] = subjectName(cert)
	}

	var added, removed []string
	for fp, name := range after {
		if _, ok := before[fp]; !ok {
			added = append(added, name)
		}
	}
	for fp, name := range before {
		if _, ok := after[fp]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	fmt.Printf("%s: %d -> %d trust anchors (%d added, %d removed)\n",
		id, len(before), len(after), len(added), len(removed))
	for _, n := range added {
		fmt.Println("  + " + n)
	}
	for _, n := range removed {
		fmt.Println("  - " + n)
	}
}

func subjectSet(certs []*x509.Certificate) map[string]string {
	out := make(map[string]string, len(certs))
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		out[hex.EncodeToString(sum[:])] = subjectName(c)
	}
	return out
}

func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

// writeLicence keeps the licence text beside the data it covers. MPL-2.0 is
// file-level copyleft, so the notice travelling with the file is a condition of
// redistribution, not a courtesy.
func writeLicence(outDir, id string) error {
	name := "LICENSE-Chromium-BSD"
	body := chromiumLicence
	if id == truststore.BundleMozilla {
		name = "LICENSE-MPL-2.0"
		body = mplNotice
	}
	target := filepath.Join(outDir, name)
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	return os.WriteFile(target, []byte(body), 0o644)
}
