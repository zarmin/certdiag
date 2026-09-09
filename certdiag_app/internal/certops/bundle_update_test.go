package certops

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// No test in this file reaches the network. Upstream input comes from a
// generated directory via FetchBundle's fromDir path, which is the same code
// path `certdiag store update --from` uses.
//
// testBundleID has no compiled-in counterpart on purpose. LoadBundle falls back
// to the embedded snapshot when nothing is installed, so using a real id would
// compare test data against the ~121 real Mozilla anchors and trip the drop
// guard. That fallback is the right production behaviour -- the guard should
// compare against the bundle actually in effect -- it just is not what these
// cases are exercising.
const testBundleID = "testbundle"

func bundleCertsOf(certs ...*x509.Certificate) []truststore.BundleCert {
	out := make([]truststore.BundleCert, 0, len(certs))
	for _, c := range certs {
		out = append(out, truststore.BundleCert{Label: c.Subject.CommonName, DER: c.Raw})
	}
	return out
}

func manyRoots(t *testing.T, n int, prefix string) []*x509.Certificate {
	t.Helper()
	out := make([]*x509.Certificate, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, storeTestCert(t, prefix+itoa(i)))
	}
	return out
}

// installBundle writes a bundle into dir the way store update would.
func installBundle(t *testing.T, dir, id string, certs []*x509.Certificate, extracted string) {
	t.Helper()
	m := truststore.BundleManifest{
		ID:          id,
		Name:        "Test " + id,
		SourceURL:   "https://example.test/" + id,
		ExtractedAt: extracted,
		License:     "MPL-2.0",
	}
	files, err := truststore.RenderBundle(m, &truststore.ParsedBundle{Trusted: bundleCertsOf(certs...)},
		truststore.LicenceHeader(id))
	if err != nil {
		t.Fatal(err)
	}
	if err := truststore.WriteBundleFiles(dir, id, files); err != nil {
		t.Fatal(err)
	}
}

// --- validation guards ------------------------------------------------------

// TestValidateParsed_Floor: a truncated download that silently replaces a good
// bundle is the worst outcome this code can produce.
func TestValidateParsed_Floor(t *testing.T) {
	few := &truststore.ParsedBundle{Trusted: bundleCertsOf(manyRoots(t, MinTrustAnchors-1, "Few ")...)}
	if err := ValidateParsed(few, truststore.BundleManifest{}); err == nil {
		t.Error("expected a parse below the floor to be rejected")
	} else if !strings.Contains(err.Error(), "below the floor") {
		t.Errorf("expected the floor named in the error, got %v", err)
	}

	enough := &truststore.ParsedBundle{Trusted: bundleCertsOf(manyRoots(t, MinTrustAnchors, "Enough ")...)}
	if err := ValidateParsed(enough, truststore.BundleManifest{}); err != nil {
		t.Errorf("exactly the floor must be accepted: %v", err)
	}
}

func TestValidateParsed_DropFraction(t *testing.T) {
	cases := []struct {
		name     string
		previous int
		now      int
		reject   bool
	}{
		{"unchanged", 100, 100, false},
		{"growth", 100, 130, false},
		{"small drop", 100, 90, false},
		{"at the limit", 100, 85, false},
		{"past the limit", 100, 80, true},
		{"collapse", 200, 60, true},
		{"no previous count", 0, 60, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed := &truststore.ParsedBundle{Trusted: bundleCertsOf(manyRoots(t, tc.now, "Root ")...)}
			prev := truststore.BundleManifest{TrustedCount: tc.previous}

			err := ValidateParsed(parsed, prev)
			if tc.reject && err == nil {
				t.Errorf("expected %d -> %d to be rejected", tc.previous, tc.now)
			}
			if !tc.reject && err != nil {
				t.Errorf("expected %d -> %d to be accepted: %v", tc.previous, tc.now, err)
			}
		})
	}
}

// --- update ----------------------------------------------------------------

func TestBundleUpdate_NoDirectory(t *testing.T) {
	if _, err := BundleUpdate(BundleUpdateOptions{}); err == nil {
		t.Error("expected an error with no bundle directory")
	}
}

func TestBundleUpdate_ImportInstalls(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	roots := manyRoots(t, 60, "Import Root ")
	installBundle(t, src, testBundleID, roots, "2026-05-05")

	result, err := BundleUpdate(BundleUpdateOptions{Dir: dst, ImportPath: src})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(result.Entries))
	}
	e := result.Entries[0]
	if e.Err != nil {
		t.Fatalf("import failed: %v", e.Err)
	}
	if !e.Written {
		t.Error("expected the bundle to be written")
	}
	if e.After != 60 {
		t.Errorf("expected 60 anchors, got %d", e.After)
	}

	// It must now load as installed, taking precedence over the embedded copy.
	b, err := truststore.LoadBundle(testBundleID, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Installed {
		t.Error("expected the imported bundle to be the installed one")
	}
	if b.Manifest.ExtractedAt != "2026-05-05" {
		t.Errorf("expected the imported snapshot date, got %q", b.Manifest.ExtractedAt)
	}
}

// TestBundleUpdate_ImportRejectsTruncated: a hand-carried file gets exactly the
// same validation as a downloaded one. The air-gapped path is not a trust
// shortcut.
func TestBundleUpdate_ImportRejectsTruncated(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	good := manyRoots(t, 60, "Good Root ")
	installBundle(t, dst, testBundleID, good, "2026-01-01")

	// The incoming bundle has too few anchors.
	installBundle(t, src, testBundleID, manyRoots(t, 5, "Truncated Root "), "2026-06-06")

	result, err := BundleUpdate(BundleUpdateOptions{Dir: dst, ImportPath: src})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Err == nil {
		t.Fatalf("expected the truncated import to be rejected, got %+v", result.Entries)
	}
	if !strings.Contains(result.Entries[0].Err.Error(), "below the floor") {
		t.Errorf("expected the floor error, got %v", result.Entries[0].Err)
	}

	// The previous bundle must survive a rejected update.
	b, err := truststore.LoadBundle(testBundleID, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Installed || b.Manifest.ExtractedAt != "2026-01-01" {
		t.Error("a rejected update must leave the previous bundle in place")
	}
	if len(b.Trusted) != 60 {
		t.Errorf("expected the previous 60 anchors, got %d", len(b.Trusted))
	}
}

func TestBundleUpdate_DryRunWritesNothing(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	installBundle(t, src, testBundleID, manyRoots(t, 60, "Dry Root "), "2026-07-07")

	result, err := BundleUpdate(BundleUpdateOptions{Dir: dst, ImportPath: src, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Written {
		t.Error("a dry run must not write")
	}
	if result.Entries[0].Skipped == "" {
		t.Error("a dry run must say why nothing was written")
	}
	if entries, _ := os.ReadDir(dst); len(entries) != 0 {
		t.Errorf("expected an untouched directory, got %v", entries)
	}
}

func TestBundleUpdate_ImportSingleManifest(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	installBundle(t, src, testBundleID, manyRoots(t, 60, "Single Root "), "2026-08-08")

	// Pointing at the manifest file rather than the directory must work too.
	result, err := BundleUpdate(BundleUpdateOptions{
		Dir:        dst,
		ImportPath: filepath.Join(src, testBundleID+".json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || !result.Entries[0].Written {
		t.Fatalf("expected the single bundle to install, got %+v", result.Entries)
	}
	if result.Entries[0].ID != testBundleID {
		t.Errorf("expected the chrome bundle, got %q", result.Entries[0].ID)
	}
}

func TestBundleUpdate_ImportMissingPath(t *testing.T) {
	if _, err := BundleUpdate(BundleUpdateOptions{
		Dir:        t.TempDir(),
		ImportPath: filepath.Join(t.TempDir(), "nope"),
	}); err == nil {
		t.Error("expected an error for a missing import path")
	}
}

func TestBundleUpdate_ImportEmptyDirectory(t *testing.T) {
	if _, err := BundleUpdate(BundleUpdateOptions{
		Dir:        t.TempDir(),
		ImportPath: t.TempDir(),
	}); err == nil {
		t.Error("expected an error when the import directory has no manifests")
	}
}

// TestBundleUpdate_ImportReportsDiff: the added/removed list is what makes an
// update reviewable rather than an opaque swap of a large file.
func TestBundleUpdate_ImportReportsDiff(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	shared := manyRoots(t, 58, "Shared Root ")
	removed := storeTestCert(t, "Removed Root")
	added := storeTestCert(t, "Added Root")

	installBundle(t, dst, testBundleID, append(append([]*x509.Certificate{}, shared...), removed), "2026-01-01")
	installBundle(t, src, testBundleID, append(append([]*x509.Certificate{}, shared...), added), "2026-02-02")

	result, err := BundleUpdate(BundleUpdateOptions{Dir: dst, ImportPath: src, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	e := result.Entries[0]
	if len(e.Added) != 1 || e.Added[0] != "Added Root" {
		t.Errorf("expected exactly the added root, got %v", e.Added)
	}
	if len(e.Removed) != 1 || e.Removed[0] != "Removed Root" {
		t.Errorf("expected exactly the removed root, got %v", e.Removed)
	}
	if e.Before != 59 || e.After != 59 {
		t.Errorf("expected 59 -> 59, got %d -> %d", e.Before, e.After)
	}
}

func TestDiffAnchors(t *testing.T) {
	a := storeTestCert(t, "A")
	b := storeTestCert(t, "B")
	c := storeTestCert(t, "C")

	added, removed := diffAnchors(
		[]*x509.Certificate{a, b},
		[]*x509.Certificate{b, c},
	)
	if len(added) != 1 || added[0] != "C" {
		t.Errorf("expected C added, got %v", added)
	}
	if len(removed) != 1 || removed[0] != "A" {
		t.Errorf("expected A removed, got %v", removed)
	}

	// Identical sets produce nothing, which is what an unchanged refresh must
	// print.
	added, removed = diffAnchors([]*x509.Certificate{a, b}, []*x509.Certificate{b, a})
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("expected no difference, got +%v -%v", added, removed)
	}
}

func TestDiffAnchors_Sorted(t *testing.T) {
	certs := []*x509.Certificate{
		storeTestCert(t, "Zulu"), storeTestCert(t, "Alpha"), storeTestCert(t, "Mike"),
	}
	added, _ := diffAnchors(nil, certs)
	if len(added) != 3 {
		t.Fatalf("expected 3 added, got %d", len(added))
	}
	for i := 1; i < len(added); i++ {
		if added[i-1] > added[i] {
			t.Errorf("expected sorted output, got %v", added)
			break
		}
	}
}

// --- status -----------------------------------------------------------------

func TestBundleStatus_Embedded(t *testing.T) {
	entries, err := BundleStatus("")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected the compiled-in snapshots to be reported")
	}
	for _, e := range entries {
		if e.Installed {
			t.Errorf("%s: expected embedded with no directory", e.ID)
		}
		if !strings.Contains(e.Origin, "embedded") {
			t.Errorf("%s: expected an embedded origin, got %q", e.ID, e.Origin)
		}
		if e.ExtractedAt == "" || e.SourceURL == "" || e.License == "" {
			t.Errorf("%s: provenance must be complete, got %+v", e.ID, e)
		}
		if e.Trusted < MinTrustAnchors {
			t.Errorf("%s: expected a plausible anchor count, got %d", e.ID, e.Trusted)
		}
	}
}

func TestBundleStatus_Installed(t *testing.T) {
	dir := t.TempDir()
	installBundle(t, dir, truststore.BundleMozilla, manyRoots(t, 60, "Status Root "), "2026-09-09")

	entries, err := BundleStatus(dir)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, e := range entries {
		if e.ID != truststore.BundleMozilla {
			continue
		}
		found = true
		if !e.Installed {
			t.Error("expected the installed copy to be reported as installed")
		}
		if e.ExtractedAt != "2026-09-09" {
			t.Errorf("expected the installed date, got %q", e.ExtractedAt)
		}
		if !strings.Contains(e.Origin, dir) {
			t.Errorf("expected the install path in the origin, got %q", e.Origin)
		}
	}
	if !found {
		t.Error("expected the installed bundle among the status entries")
	}
}

// --- FetchBundle ------------------------------------------------------------

func TestFetchBundle_UnknownID(t *testing.T) {
	if _, _, err := FetchBundle("nosuchbundle", t.TempDir()); err == nil {
		t.Error("expected an error for an unknown bundle id")
	}
}

func TestFetchBundle_FromDirMissingFile(t *testing.T) {
	// The offline path must fail clearly rather than falling back to the
	// network.
	if _, _, err := FetchBundle(truststore.BundleMozilla, t.TempDir()); err == nil {
		t.Error("expected an error when the upstream file is absent from --from")
	}
}

func TestBundleIDsInDir(t *testing.T) {
	dir := t.TempDir()
	installBundle(t, dir, truststore.BundleMozilla, manyRoots(t, 60, "A "), "2026-01-01")
	installBundle(t, dir, truststore.BundleChrome, manyRoots(t, 60, "B "), "2026-01-01")

	// A stray non-manifest JSON must not be taken for a bundle.
	if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte("[1,2,3]"), 0o600); err != nil {
		t.Fatal(err)
	}

	ids, err := bundleIDsInDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found[truststore.BundleMozilla] || !found[truststore.BundleChrome] {
		t.Errorf("expected both bundles, got %v", ids)
	}
}

func TestBundleManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	installBundle(t, dir, testBundleID, manyRoots(t, 60, "RT "), "2026-04-04")

	data, err := os.ReadFile(filepath.Join(dir, testBundleID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var m truststore.BundleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("the manifest must be valid JSON: %v", err)
	}
	if m.TrustedCount != 60 {
		t.Errorf("expected 60 in the manifest, got %d", m.TrustedCount)
	}
}

// TestBundleUpdate_DropGuardComparesAgainstBundleInEffect documents the
// behaviour these tests had to work around: with nothing installed, the guard
// compares against the compiled-in snapshot, because that is the bundle the
// import would actually be replacing from the user's point of view.
func TestBundleUpdate_DropGuardComparesAgainstBundleInEffect(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	installBundle(t, src, truststore.BundleMozilla, manyRoots(t, 60, "Small "), "2026-06-06")

	result, err := BundleUpdate(BundleUpdateOptions{Dir: dst, ImportPath: src})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Err == nil {
		t.Fatalf("expected a large drop against the embedded snapshot to be rejected, got %+v", result.Entries)
	}
	if !strings.Contains(result.Entries[0].Err.Error(), "above the") {
		t.Errorf("expected the drop-limit error, got %v", result.Entries[0].Err)
	}
}
