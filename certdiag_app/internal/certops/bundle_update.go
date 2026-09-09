package certops

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

const (
	MozillaCertdataURL = "https://raw.githubusercontent.com/nss-dev/nss/master/lib/ckfw/builtins/certdata.txt"
	ChromeCertsURL     = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT"
	ChromeProtoURL     = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT"
	chromeStoreURL     = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/"

	// MinTrustAnchors is the floor below which a parse is treated as a failed
	// download rather than a real shrinking of the vendor's list. A truncated
	// fetch silently replacing a good bundle is the worst outcome here.
	MinTrustAnchors = 50
	// MaxAnchorDropFraction bounds how much the anchor count may fall in one
	// update before it needs a human decision.
	MaxAnchorDropFraction = 0.15

	bundleFetchTimeout = 60 * time.Second
)

// FetchBundle downloads and parses one vendor root list. When fromDir is set the
// upstream files are read from disk instead, so the same code path serves the
// build-time generator, an offline re-run, and `certdiag store update`.
func FetchBundle(id, fromDir string) (*truststore.ParsedBundle, truststore.BundleManifest, error) {
	today := time.Now().UTC().Format("2006-01-02")

	switch id {
	case truststore.BundleMozilla:
		data, err := fetchUpstream(MozillaCertdataURL, fromDir, "certdata.txt", false)
		if err != nil {
			return nil, truststore.BundleManifest{}, err
		}
		parsed, err := truststore.ParseCertdata(data)
		if err != nil {
			return nil, truststore.BundleManifest{}, err
		}
		sum := sha256.Sum256(data)
		return parsed, truststore.BundleManifest{
			ID:               truststore.BundleMozilla,
			Name:             "Mozilla CA bundle",
			SourceURL:        MozillaCertdataURL,
			UpstreamRevision: parsed.Revision,
			ExtractedAt:      today,
			License:          "MPL-2.0",
			PurposeScope:     []string{"server_auth"},
			SHA256:           hex.EncodeToString(sum[:]),
		}, nil

	case truststore.BundleChrome:
		certs, err := fetchUpstream(ChromeCertsURL, fromDir, "root_store.certs", true)
		if err != nil {
			return nil, truststore.BundleManifest{}, err
		}
		proto, err := fetchUpstream(ChromeProtoURL, fromDir, "root_store.textproto", true)
		if err != nil {
			return nil, truststore.BundleManifest{}, err
		}
		parsed, err := truststore.ParseChromeRootStore(proto, certs)
		if err != nil {
			return nil, truststore.BundleManifest{}, err
		}
		sum := sha256.Sum256(append(append([]byte{}, proto...), certs...))
		return parsed, truststore.BundleManifest{
			ID:               truststore.BundleChrome,
			Name:             "Chrome Root Store",
			SourceURL:        chromeStoreURL,
			UpstreamRevision: parsed.Revision,
			ExtractedAt:      today,
			License:          "BSD-3-Clause",
			PurposeScope:     []string{"server_auth"},
			SHA256:           hex.EncodeToString(sum[:]),
		}, nil
	}
	return nil, truststore.BundleManifest{}, &OperationError{Op: "store update", Message: fmt.Sprintf("unknown bundle %q", id)}
}

func fetchUpstream(url, fromDir, name string, base64Encoded bool) ([]byte, error) {
	if fromDir != "" {
		return os.ReadFile(filepath.Join(fromDir, name))
	}

	client := &http.Client{Timeout: bundleFetchTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if base64Encoded {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, string(data))
		return base64.StdEncoding.DecodeString(clean)
	}
	return data, nil
}

// ValidateParsed applies the guards that stop a truncated or partially parsed
// download from replacing a good bundle. previous may be a zero manifest.
func ValidateParsed(parsed *truststore.ParsedBundle, previous truststore.BundleManifest) error {
	if len(parsed.Trusted) < MinTrustAnchors {
		return fmt.Errorf("only %d trust anchors parsed, below the floor of %d; refusing to install",
			len(parsed.Trusted), MinTrustAnchors)
	}
	if previous.TrustedCount > 0 {
		drop := float64(previous.TrustedCount-len(parsed.Trusted)) / float64(previous.TrustedCount)
		if drop > MaxAnchorDropFraction {
			return fmt.Errorf("anchor count fell from %d to %d (%.0f%%), above the %.0f%% limit; refusing to install",
				previous.TrustedCount, len(parsed.Trusted), drop*100, MaxAnchorDropFraction*100)
		}
	}
	return nil
}

type BundleUpdateOptions struct {
	// IDs to refresh; empty means every known bundle.
	IDs []string
	// Dir is where refreshed bundles are installed.
	Dir string
	// FromDir reads the upstream files from disk instead of the network.
	FromDir string
	// ImportPath installs a bundle prepared elsewhere: a directory of bundle
	// files, or one manifest .json with its PEMs beside it. For air-gapped
	// hosts, where the download path is not available.
	ImportPath string
	// DryRun reports what would change and writes nothing.
	DryRun bool
}

type BundleUpdateEntry struct {
	ID       string
	Before   int
	After    int
	Added    []string
	Removed  []string
	Written  bool
	Skipped  string
	Err      error
	Manifest truststore.BundleManifest
}

type BundleUpdateResult struct {
	Entries []BundleUpdateEntry
	Dir     string
}

// BundleUpdate refreshes the installed root snapshots. Network is used only
// here, and only when ImportPath and FromDir are both empty.
func BundleUpdate(opts BundleUpdateOptions) (*BundleUpdateResult, error) {
	if opts.Dir == "" {
		return nil, &OperationError{Op: "store update", Message: "no bundle directory available"}
	}
	if opts.ImportPath != "" {
		return importBundles(opts)
	}

	ids := opts.IDs
	if len(ids) == 0 {
		ids = truststore.BundleIDs()
	}

	res := &BundleUpdateResult{Dir: opts.Dir}
	for _, id := range ids {
		res.Entries = append(res.Entries, refreshOne(id, opts))
	}
	return res, nil
}

func refreshOne(id string, opts BundleUpdateOptions) BundleUpdateEntry {
	entry := BundleUpdateEntry{ID: id}

	parsed, manifest, err := FetchBundle(id, opts.FromDir)
	if err != nil {
		entry.Err = err
		return entry
	}
	entry.Manifest = manifest
	entry.After = len(parsed.Trusted)

	current, _ := truststore.LoadBundle(id, opts.Dir)
	var previous truststore.BundleManifest
	if current != nil {
		previous = current.Manifest
		entry.Before = len(current.Trusted)
		entry.Added, entry.Removed = diffAnchors(current.Trusted, parsedCerts(parsed.Trusted))
	}

	if err := ValidateParsed(parsed, previous); err != nil {
		entry.Err = err
		return entry
	}

	if opts.DryRun {
		entry.Skipped = "dry run"
		return entry
	}

	files, err := truststore.RenderBundle(manifest, parsed, truststore.LicenceHeader(id))
	if err != nil {
		entry.Err = err
		return entry
	}
	if err := truststore.WriteBundleFiles(opts.Dir, id, files); err != nil {
		entry.Err = err
		return entry
	}
	entry.Written = true
	return entry
}

func importBundles(opts BundleUpdateOptions) (*BundleUpdateResult, error) {
	dir := opts.ImportPath
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, &OperationError{Op: "store update", Message: err.Error()}
	}
	if !fi.IsDir() {
		dir = filepath.Dir(opts.ImportPath)
	}

	ids, err := bundleIDsInDir(dir)
	if err != nil {
		return nil, &OperationError{Op: "store update", Message: err.Error()}
	}
	if !fi.IsDir() {
		base := filepath.Base(opts.ImportPath)
		ids = []string{strings.TrimSuffix(base, filepath.Ext(base))}
	}
	if len(ids) == 0 {
		return nil, &OperationError{Op: "store update", Message: fmt.Sprintf("no bundle manifests found in %s", dir)}
	}

	res := &BundleUpdateResult{Dir: opts.Dir}
	for _, id := range ids {
		entry := BundleUpdateEntry{ID: id}

		incoming, err := truststore.LoadBundle(id, dir)
		if err != nil || incoming == nil || !incoming.Installed {
			entry.Err = fmt.Errorf("could not read bundle %q from %s", id, dir)
			res.Entries = append(res.Entries, entry)
			continue
		}
		entry.Manifest = incoming.Manifest
		entry.After = len(incoming.Trusted)

		// An imported bundle gets the same validation as a downloaded one: a
		// hand-carried file is no more trustworthy than a fetched one.
		parsed := &truststore.ParsedBundle{}
		for _, c := range incoming.Trusted {
			parsed.Trusted = append(parsed.Trusted, truststore.BundleCert{DER: c.Raw})
		}
		for _, c := range incoming.Distrusted {
			parsed.Distrusted = append(parsed.Distrusted, truststore.BundleCert{DER: c.Raw})
		}

		current, _ := truststore.LoadBundle(id, opts.Dir)
		var previous truststore.BundleManifest
		if current != nil {
			previous = current.Manifest
			entry.Before = len(current.Trusted)
			entry.Added, entry.Removed = diffAnchors(current.Trusted, incoming.Trusted)
		}
		if err := ValidateParsed(parsed, previous); err != nil {
			entry.Err = err
			res.Entries = append(res.Entries, entry)
			continue
		}
		if opts.DryRun {
			entry.Skipped = "dry run"
			res.Entries = append(res.Entries, entry)
			continue
		}

		files, err := truststore.RenderBundle(incoming.Manifest, parsed, truststore.LicenceHeader(id))
		if err != nil {
			entry.Err = err
			res.Entries = append(res.Entries, entry)
			continue
		}
		if err := truststore.WriteBundleFiles(opts.Dir, id, files); err != nil {
			entry.Err = err
			res.Entries = append(res.Entries, entry)
			continue
		}
		entry.Written = true
		res.Entries = append(res.Entries, entry)
	}
	return res, nil
}

func bundleIDsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var m truststore.BundleManifest
		if json.Unmarshal(data, &m) == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// diffAnchors reports which trust anchors an update adds and removes, so the
// change is reviewable instead of an opaque swap of a large file.
func diffAnchors(before, after []*x509.Certificate) (added, removed []string) {
	beforeSet := anchorNames(before)
	afterSet := anchorNames(after)

	for fp, name := range afterSet {
		if _, ok := beforeSet[fp]; !ok {
			added = append(added, name)
		}
	}
	for fp, name := range beforeSet {
		if _, ok := afterSet[fp]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func anchorNames(certs []*x509.Certificate) map[string]string {
	out := make(map[string]string, len(certs))
	for _, c := range certs {
		out[truststore.CertFingerprint(c)] = anchorName(c)
	}
	return out
}

func anchorName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if len(c.Subject.Organization) > 0 {
		return c.Subject.Organization[0]
	}
	return c.Subject.String()
}

func parsedCerts(certs []truststore.BundleCert) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, bc := range certs {
		if c, err := x509.ParseCertificate(bc.DER); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// BundleStatusEntry describes one snapshot as it stands right now.
type BundleStatusEntry struct {
	ID          string
	Name        string
	ExtractedAt string
	AgeDays     int
	Stale       bool
	Installed   bool
	Origin      string
	SourceURL   string
	License     string
	Trusted     int
	Distrusted  int
	Caveats     []string
}

// BundleStatus reports the snapshot in effect for each bundle.
func BundleStatus(dir string) ([]BundleStatusEntry, error) {
	bundles, err := truststore.LoadBundles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]BundleStatusEntry, 0, len(bundles))
	for i := range bundles {
		b := &bundles[i]
		e := BundleStatusEntry{
			ID:          b.Manifest.ID,
			Name:        b.Manifest.Name,
			ExtractedAt: b.Manifest.ExtractedAt,
			Stale:       b.Stale(),
			Installed:   b.Installed,
			Origin:      b.Origin(),
			SourceURL:   b.Manifest.SourceURL,
			License:     b.Manifest.License,
			Trusted:     len(b.Trusted),
			Distrusted:  len(b.Distrusted),
			Caveats:     b.Manifest.Caveats,
		}
		if age, ok := b.Age(); ok {
			e.AgeDays = int(age.Hours() / 24)
		}
		out = append(out, e)
	}
	return out, nil
}
