package truststore

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freezeClock pins the staleness clock so thresholds are testable without
// sleeping or back-dating fixtures.
func freezeClock(t *testing.T, at time.Time) {
	t.Helper()
	prev := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = prev })
}

func testManifest(id, name, extracted string) BundleManifest {
	return BundleManifest{
		ID:          id,
		Name:        name,
		SourceURL:   "https://example.test/" + id,
		ExtractedAt: extracted,
		License:     "MPL-2.0",
	}
}

func writeTestBundle(t *testing.T, dir, id string, m BundleManifest, trusted, distrusted []BundleCert) {
	t.Helper()
	parsed := &ParsedBundle{Trusted: trusted, Distrusted: distrusted}
	files, err := RenderBundle(m, parsed, LicenceHeader(id))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := WriteBundleFiles(dir, id, files); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func bundleCerts(cas ...testCA) []BundleCert {
	out := make([]BundleCert, 0, len(cas))
	for _, ca := range cas {
		out = append(out, BundleCert{Label: ca.cert.Subject.CommonName, DER: ca.cert.Raw})
	}
	return out
}

// --- embedded bundle invariants ---
//
// These assert only what stays true across a `task update-bundles` refresh.
// Naming a specific CA here would be a scheduled failure: the vendors add and
// remove roots, which is the whole reason the snapshot has a date.

func TestEmbeddedBundles_Invariants(t *testing.T) {
	ids := BundleIDs()
	if len(ids) == 0 {
		t.Fatal("expected at least one compiled-in snapshot")
	}

	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			b, err := LoadBundle(id, "")
			if err != nil {
				t.Fatalf("embedded bundle %s must load: %v", id, err)
			}
			if b.Installed {
				t.Error("expected the embedded copy when no directory is given")
			}
			if len(b.Trusted) < 50 {
				t.Errorf("expected a plausible anchor count, got %d", len(b.Trusted))
			}
			for _, c := range b.Trusted {
				if !c.IsCA {
					t.Errorf("non-CA certificate in the trusted set: %s", c.Subject.CommonName)
					break
				}
			}
			if _, ok := b.Manifest.ExtractedTime(); !ok {
				t.Errorf("manifest needs a parseable extracted_at, got %q", b.Manifest.ExtractedAt)
			}
			if b.Manifest.SourceURL == "" || b.Manifest.License == "" {
				t.Errorf("manifest must name its source and licence: %+v", b.Manifest)
			}
			if b.Manifest.TrustedCount != len(b.Trusted) {
				t.Errorf("manifest count %d does not match %d loaded anchors",
					b.Manifest.TrustedCount, len(b.Trusted))
			}
		})
	}
}

// TestEmbeddedBundles_LicenceFilesPresent guards a redistribution condition,
// not a cosmetic: MPL-2.0 is file-level copyleft.
func TestEmbeddedBundles_LicenceFilesPresent(t *testing.T) {
	for _, name := range []string{"LICENSE-MPL-2.0", "LICENSE-Chromium-BSD"} {
		data, err := bundleFS.ReadFile(bundleDirName + "/" + name)
		if err != nil {
			t.Errorf("%s must ship beside the bundles: %v", name, err)
			continue
		}
		if len(data) < 200 {
			t.Errorf("%s looks truncated (%d bytes)", name, len(data))
		}
	}
}

func TestEmbeddedBundles_MPLHeaderSurvives(t *testing.T) {
	data, err := bundleFS.ReadFile(bundleDirName + "/" + BundleMozilla + "-trusted.pem")
	if err != nil {
		t.Skipf("mozilla bundle not present: %v", err)
	}
	if !bytes.Contains(data, []byte("Mozilla Public")) {
		t.Error("the MPL notice must survive into the generated PEM")
	}
}

// --- naming and provenance ---

func TestBundle_DisplayNameNeverClaimsTheBrowser(t *testing.T) {
	b := &Bundle{Manifest: testManifest(BundleMozilla, "Mozilla CA bundle", "2026-01-15")}

	name := b.DisplayName()
	if !strings.Contains(name, "snapshot") || !strings.Contains(name, "2026-01-15") {
		t.Errorf("the display name must carry the word snapshot and the date, got %q", name)
	}
	// The bundle is the vendor's published list as of a date, not a read of the
	// browser on this machine.
	for _, banned := range []string{"Firefox", "Chrome"} {
		if strings.Contains(name, banned) {
			t.Errorf("a bundle must never be named %q on its own, got %q", banned, name)
		}
	}

	undated := &Bundle{Manifest: BundleManifest{ID: "x", Name: "X"}}
	if !strings.Contains(undated.DisplayName(), "date unknown") {
		t.Errorf("a snapshot with no date must say so, got %q", undated.DisplayName())
	}
}

func TestBundle_Origin(t *testing.T) {
	embedded := &Bundle{Path: "embedded:mozilla"}
	if !strings.Contains(embedded.Origin(), "embedded") {
		t.Errorf("expected an embedded origin, got %q", embedded.Origin())
	}
	installed := &Bundle{Installed: true, Path: "/home/u/.certdiag/bundles/mozilla.json"}
	if !strings.Contains(installed.Origin(), "installed") {
		t.Errorf("expected an installed origin, got %q", installed.Origin())
	}
}

func TestBundleManifest_ExtractedTime(t *testing.T) {
	cases := map[string]bool{
		"2026-01-15":           true,
		"2026-01-15T10:00:00Z": true,
		"":                     false,
		"15/01/2026":           false,
		"not a date":           false,
	}
	for in, ok := range cases {
		_, got := BundleManifest{ExtractedAt: in}.ExtractedTime()
		if got != ok {
			t.Errorf("ExtractedAt %q: expected parseable=%v", in, ok)
		}
	}
}

func TestBundle_Staleness(t *testing.T) {
	taken := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := &Bundle{Manifest: testManifest("x", "X", "2026-01-01")}

	cases := []struct {
		name  string
		at    time.Time
		stale bool
	}{
		{"fresh", taken.Add(24 * time.Hour), false},
		{"just inside the window", taken.Add(BundleStaleAfter - time.Hour), false},
		{"exactly at the window", taken.Add(BundleStaleAfter), false},
		{"past the window", taken.Add(BundleStaleAfter + time.Hour), true},
		{"long past", taken.Add(365 * 24 * time.Hour), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			freezeClock(t, tc.at)
			if got := b.Stale(); got != tc.stale {
				t.Errorf("expected stale=%v at %s", tc.stale, tc.at.Format("2006-01-02"))
			}
			age, ok := b.Age()
			if !ok {
				t.Fatal("expected a computable age")
			}
			if want := tc.at.Sub(taken); age != want {
				t.Errorf("expected age %v, got %v", want, age)
			}
		})
	}

	// An unparseable date is treated as stale: better to over-warn than to
	// present an unknown-age snapshot as current.
	undated := &Bundle{Manifest: BundleManifest{ID: "x"}}
	if !undated.Stale() {
		t.Error("a snapshot with no usable date must be treated as stale")
	}
	if _, ok := undated.Age(); ok {
		t.Error("expected no computable age without a date")
	}
}

// --- StoreContents ---

func TestBundle_StoreContents(t *testing.T) {
	freezeClock(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))

	good := newTestCA(t, "Bundle Good Root")
	bad := newTestCA(t, "Bundle Bad Root")

	b := &Bundle{
		Manifest:   testManifest(BundleMozilla, "Mozilla CA bundle", "2026-01-01"),
		Trusted:    []*x509.Certificate{good.cert},
		Distrusted: []*x509.Certificate{bad.cert},
		Path:       "embedded:mozilla",
	}

	sc := b.StoreContents()
	if sc.Info.Type != StoreTypeBundle {
		t.Errorf("expected the bundle store type, got %q", sc.Info.Type)
	}
	if sc.Info.ID != BundleMozilla {
		t.Errorf("expected the bundle id on the store info, got %q", sc.Info.ID)
	}
	if len(sc.Certificates) != 2 {
		t.Fatalf("expected trusted and distrusted certificates, got %d", len(sc.Certificates))
	}

	// Distrust records are kept deliberately: they are what makes a distrust
	// event visible.
	if got := sc.GetTrust(bad.cert).Overall; got != TrustDenied {
		t.Errorf("expected the distrusted root to read Denied, got %q", got)
	}
	if got := sc.GetTrust(good.cert).Overall; got != TrustTrusted {
		t.Errorf("expected the trusted root to read Trusted, got %q", got)
	}

	if len(sc.Info.Warnings) == 0 || !strings.Contains(sc.Info.Warnings[0], "SNAPSHOT") {
		t.Errorf("the snapshot disclosure must lead the warnings, got %v", sc.Info.Warnings)
	}
	if !strings.Contains(sc.Info.Warnings[0], "store update") {
		t.Errorf("the disclosure must say how to refresh, got %q", sc.Info.Warnings[0])
	}
}

func TestBundle_StoreContentsStaleWarning(t *testing.T) {
	ca := newTestCA(t, "Stale Root")
	b := &Bundle{
		Manifest: testManifest("x", "X", "2026-01-01"),
		Trusted:  []*x509.Certificate{ca.cert},
	}

	freezeClock(t, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if joined := strings.Join(b.StoreContents().Info.Warnings, " "); strings.Contains(joined, "days old") {
		t.Errorf("a fresh snapshot must not warn about age, got %q", joined)
	}

	freezeClock(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(BundleStaleAfter+48*time.Hour))
	joined := strings.Join(b.StoreContents().Info.Warnings, " ")
	if !strings.Contains(joined, "days old") {
		t.Errorf("a stale snapshot must say how old it is, got %q", joined)
	}
}

// --- load precedence ---

func TestLoadBundle_InstalledBeatsEmbedded(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, "Installed Root")
	writeTestBundle(t, dir, BundleMozilla,
		testManifest(BundleMozilla, "Mozilla CA bundle", "2026-06-01"),
		bundleCerts(ca), nil)

	b, err := LoadBundle(BundleMozilla, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !b.Installed {
		t.Error("expected the installed copy to win")
	}
	if len(b.Trusted) != 1 || b.Trusted[0].Subject.CommonName != "Installed Root" {
		t.Errorf("expected the installed content, got %d certs", len(b.Trusted))
	}
	if b.Manifest.ExtractedAt != "2026-06-01" {
		t.Errorf("expected the installed manifest, got %q", b.Manifest.ExtractedAt)
	}
}

func TestLoadBundle_FallsBackToEmbedded(t *testing.T) {
	// An empty directory is simply "nothing installed".
	b, err := LoadBundle(BundleMozilla, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Installed {
		t.Error("expected the embedded copy when nothing is installed")
	}
}

// TestLoadBundle_CorruptInstalledFallsBack: a broken installed copy must never
// leave certdiag with no bundle at all, and must say why.
func TestLoadBundle_CorruptInstalledFallsBack(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, BundleMozilla+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBundle(BundleMozilla, dir)
	if err != nil {
		t.Fatalf("expected a fallback, got error: %v", err)
	}
	if b.Installed {
		t.Error("expected the embedded copy after a corrupt installed one")
	}
	joined := strings.Join(b.Manifest.Caveats, " ")
	if !strings.Contains(joined, "could not be read") {
		t.Errorf("expected the failure recorded as a caveat, got %v", b.Manifest.Caveats)
	}
}

func TestLoadBundle_UnknownID(t *testing.T) {
	if _, err := LoadBundle("nosuchbundle", ""); err == nil {
		t.Error("expected an error for an unknown bundle id")
	}
}

func TestLoadBundles_All(t *testing.T) {
	bundles, err := LoadBundles("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bundles) != len(BundleIDs()) {
		t.Errorf("expected every known bundle to load, got %d of %d", len(bundles), len(BundleIDs()))
	}
}

// --- render and write ---

// TestRenderBundle_Deterministic is what makes the review diff on
// `task update-bundles` meaningful: unchanged input must produce an unchanged
// file, or every refresh looks like a rewrite.
func TestRenderBundle_Deterministic(t *testing.T) {
	certs := bundleCerts(
		newTestCA(t, "Root C"),
		newTestCA(t, "Root A"),
		newTestCA(t, "Root B"),
	)
	m := testManifest(BundleMozilla, "Mozilla CA bundle", "2026-01-01")

	first, err := RenderBundle(m, &ParsedBundle{Trusted: certs}, LicenceHeader(BundleMozilla))
	if err != nil {
		t.Fatal(err)
	}

	// Same certificates, different input order.
	shuffled := []BundleCert{certs[2], certs[0], certs[1]}
	second, err := RenderBundle(m, &ParsedBundle{Trusted: shuffled}, LicenceHeader(BundleMozilla))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first.Trusted, second.Trusted) {
		t.Error("render must be order-independent, or every refresh produces a spurious diff")
	}
	if !bytes.Equal(first.Manifest, second.Manifest) {
		t.Error("the manifest must be deterministic too")
	}
}

func TestRenderBundle_ManifestCounts(t *testing.T) {
	trusted := bundleCerts(newTestCA(t, "T1"), newTestCA(t, "T2"))
	distrusted := bundleCerts(newTestCA(t, "D1"))

	files, err := RenderBundle(
		testManifest("x", "X", "2026-01-01"),
		&ParsedBundle{Trusted: trusted, Distrusted: distrusted, Caveats: []string{"a caveat"}},
		"")
	if err != nil {
		t.Fatal(err)
	}

	var m BundleManifest
	if err := json.Unmarshal(files.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	if m.TrustedCount != 2 || m.DistrustedCount != 1 {
		t.Errorf("expected 2 trusted and 1 distrusted, got %d and %d", m.TrustedCount, m.DistrustedCount)
	}
	if len(m.Caveats) != 1 || m.Caveats[0] != "a caveat" {
		t.Errorf("expected the parse caveats to reach the manifest, got %v", m.Caveats)
	}
	if len(files.Distrusted) == 0 {
		t.Error("expected a distrusted PEM when there are distrusted entries")
	}
}

func TestRenderBundle_NoDistrustedFile(t *testing.T) {
	files, err := RenderBundle(
		testManifest("x", "X", "2026-01-01"),
		&ParsedBundle{Trusted: bundleCerts(newTestCA(t, "T1"))}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files.Distrusted) != 0 {
		t.Error("expected no distrusted PEM when there is nothing to distrust")
	}
}

func TestRenderBundle_HeaderAndProvenance(t *testing.T) {
	m := testManifest(BundleMozilla, "Mozilla CA bundle", "2026-03-04")
	m.UpstreamRevision = "rev-123"

	files, err := RenderBundle(m, &ParsedBundle{Trusted: bundleCerts(newTestCA(t, "Root"))},
		LicenceHeader(BundleMozilla))
	if err != nil {
		t.Fatal(err)
	}

	body := string(files.Trusted)
	for _, want := range []string{
		"Mozilla Public",    // the licence notice
		"2026-03-04",        // the snapshot date
		"rev-123",           // upstream revision
		"MPL-2.0",           // the licence name
		"not a live read",   // the standing disclaimer
		"BEGIN CERTIFICATE", // and the data itself
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered PEM must contain %q", want)
		}
	}

	// Comments must not break PEM decoding.
	block, _ := pem.Decode(files.Trusted)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("the rendered PEM must still decode")
	}
}

func TestLicenceHeader(t *testing.T) {
	if !strings.Contains(LicenceHeader(BundleMozilla), "Mozilla Public") {
		t.Error("the Mozilla bundle needs the MPL notice")
	}
	if !strings.Contains(LicenceHeader(BundleChrome), "Chromium") {
		t.Error("the Chrome bundle needs the Chromium notice")
	}
	if LicenceHeader("unknown") != "" {
		t.Error("expected no header for an unknown bundle")
	}
}

func TestWriteBundleFiles_RemovesStaleDistrusted(t *testing.T) {
	dir := t.TempDir()
	m := testManifest("x", "X", "2026-01-01")

	// First write has distrusted entries.
	writeTestBundle(t, dir, "x", m, bundleCerts(newTestCA(t, "T")), bundleCerts(newTestCA(t, "D")))
	distrustPath := filepath.Join(dir, "x-distrusted.pem")
	if _, err := os.Stat(distrustPath); err != nil {
		t.Fatalf("expected the distrusted file to exist: %v", err)
	}

	// A later refresh with none must not leave the old file behind, or the
	// bundle would keep distrusting something the vendor has re-admitted.
	writeTestBundle(t, dir, "x", m, bundleCerts(newTestCA(t, "T2")), nil)
	if _, err := os.Stat(distrustPath); !os.IsNotExist(err) {
		t.Error("a stale distrusted file must be removed on refresh")
	}
}

func TestWriteBundleFiles_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "bundles")
	writeTestBundle(t, dir, "x", testManifest("x", "X", "2026-01-01"),
		bundleCerts(newTestCA(t, "T")), nil)

	for _, name := range []string{"x.json", "x-trusted.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}
}

func TestBundleIDs(t *testing.T) {
	ids := BundleIDs()
	want := map[string]bool{BundleMozilla: false, BundleChrome: false}
	for _, id := range ids {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected %q among the compiled-in bundles, got %v", id, ids)
		}
	}
	// Sorted, so output order is stable.
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Errorf("expected sorted ids, got %v", ids)
			break
		}
	}
}
