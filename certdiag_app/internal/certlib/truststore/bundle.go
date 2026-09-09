package truststore

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// StoreTypeBundle is a shipped snapshot of a browser vendor's published root
// list. It is never a live read, and every surface that shows it says so.
const StoreTypeBundle StoreType = "bundle"

// Bundle identifiers.
const (
	BundleMozilla = "mozilla"
	BundleChrome  = "chrome"
)

// BundleStaleAfter is how old a snapshot may get before it is called out. It is
// a warning, not a refusal: on an air-gapped host an old bundle is still the
// best answer available.
const BundleStaleAfter = 90 * 24 * time.Hour

// bundleFS carries the compiled-in snapshots so certdiag has an answer on a
// host with no route to the internet.
//
//go:embed bundles
var bundleFS embed.FS

const bundleDirName = "bundles"

// now is the clock used for snapshot staleness. Indirected so tests can pin it
// instead of back-dating fixtures or sleeping.
var now = time.Now

// BundleManifest records where a snapshot came from and when, so a verdict from
// it is never mistaken for a live browser read.
type BundleManifest struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	SourceURL        string   `json:"source_url"`
	UpstreamRevision string   `json:"upstream_revision,omitempty"`
	ExtractedAt      string   `json:"extracted_at"`
	License          string   `json:"license"`
	PurposeScope     []string `json:"purpose_scope,omitempty"`
	TrustedCount     int      `json:"trusted_count"`
	DistrustedCount  int      `json:"distrusted_count"`
	SHA256           string   `json:"sha256,omitempty"`
	Caveats          []string `json:"caveats,omitempty"`
}

// ExtractedTime parses ExtractedAt, reporting whether it was usable.
func (m BundleManifest) ExtractedTime() (time.Time, bool) {
	if m.ExtractedAt == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, m.ExtractedAt); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Bundle is a loaded snapshot.
type Bundle struct {
	Manifest   BundleManifest
	Trusted    []*x509.Certificate
	Distrusted []*x509.Certificate

	// Installed reports that the bundle came from the user's bundle directory
	// rather than the compiled-in copy.
	Installed bool
	Path      string
}

// DisplayName is the store name shown everywhere. It deliberately never says
// "Firefox" or "Chrome": the bundle is the vendor's published list as of a
// date, not a read of the browser on this machine.
func (b *Bundle) DisplayName() string {
	name := b.Manifest.Name
	if name == "" {
		name = b.Manifest.ID
	}
	if b.Manifest.ExtractedAt != "" {
		return fmt.Sprintf("%s (snapshot %s)", name, b.Manifest.ExtractedAt)
	}
	return fmt.Sprintf("%s (snapshot, date unknown)", name)
}

// Age returns how long ago the snapshot was taken.
func (b *Bundle) Age() (time.Duration, bool) {
	t, ok := b.Manifest.ExtractedTime()
	if !ok {
		return 0, false
	}
	return now().Sub(t), true
}

// Stale reports whether the snapshot is old enough to warn about.
func (b *Bundle) Stale() bool {
	age, ok := b.Age()
	if !ok {
		return true
	}
	return age > BundleStaleAfter
}

// Origin describes where this copy was loaded from.
func (b *Bundle) Origin() string {
	if b.Installed {
		return "installed: " + b.Path
	}
	return "embedded in this binary"
}

// StoreContents renders the bundle as a trust store so the whole existing
// store pipeline can display it. Distrusted entries are included with an
// explicit denial so a distrust event stays visible.
func (b *Bundle) StoreContents() StoreContents {
	certs := make([]*x509.Certificate, 0, len(b.Trusted)+len(b.Distrusted))
	certs = append(certs, b.Trusted...)
	certs = append(certs, b.Distrusted...)

	trustMap := make(map[string]CertTrust, len(certs))
	for _, c := range b.Trusted {
		trustMap[CertFingerprint(c)] = CertTrust{
			Overall:  TrustTrusted,
			Policies: []TrustPolicy{{Purpose: purposeServerAuth, Status: TrustTrusted}},
		}
	}
	for _, c := range b.Distrusted {
		trustMap[CertFingerprint(c)] = CertTrust{
			Overall:  TrustDenied,
			Policies: []TrustPolicy{{Purpose: purposeServerAuth, Status: TrustDenied}},
		}
	}

	warnings := []string{
		fmt.Sprintf("SNAPSHOT, not a live read: taken %s from %s. Browsers change their root stores between certdiag releases; run 'certdiag store update' to refresh.",
			b.Manifest.ExtractedAt, b.Manifest.SourceURL),
	}
	if age, ok := b.Age(); ok && age > BundleStaleAfter {
		warnings = append(warnings, fmt.Sprintf("snapshot is %d days old", int(age.Hours()/24)))
	} else if !ok {
		warnings = append(warnings, "snapshot date is unknown")
	}
	warnings = append(warnings, b.Manifest.Caveats...)

	return StoreContents{
		Info: StoreInfo{
			Type:      StoreTypeBundle,
			Name:      b.DisplayName(),
			Path:      b.Path,
			CertCount: len(certs),
			Warnings:  warnings,
			ID:        b.Manifest.ID,
		},
		Certificates: certs,
		TrustMap:     trustMap,
	}
}

// BundleIDs lists the snapshots compiled into this binary.
func BundleIDs() []string {
	entries, err := bundleFS.ReadDir(bundleDirName)
	if err != nil {
		return nil
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			ids = append(ids, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(ids)
	return ids
}

// LoadBundle loads one snapshot, preferring an installed copy in dir over the
// compiled-in one. An installed copy that fails to load falls back to the
// embedded one rather than leaving certdiag with no bundle at all.
func LoadBundle(id, dir string) (*Bundle, error) {
	if dir != "" {
		b, err := loadBundleFromDir(id, os.DirFS(dir), ".")
		if err == nil {
			b.Installed = true
			b.Path = filepath.Join(dir, id+".json")
			return b, nil
		}
		if !os.IsNotExist(err) && !errIsMissing(err) {
			// A corrupt installed bundle is worth reporting, but the embedded
			// copy still answers.
			if eb, embErr := loadEmbedded(id); embErr == nil {
				eb.Manifest.Caveats = append(eb.Manifest.Caveats,
					fmt.Sprintf("installed bundle at %s could not be read (%v); using the embedded snapshot", dir, err))
				return eb, nil
			}
		}
	}
	return loadEmbedded(id)
}

// LoadBundles loads every known snapshot.
func LoadBundles(dir string) ([]Bundle, error) {
	ids := BundleIDs()
	if len(ids) == 0 {
		return nil, nil
	}
	var out []Bundle
	var firstErr error
	for _, id := range ids {
		b, err := LoadBundle(id, dir)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, *b)
	}
	if len(out) == 0 {
		return nil, firstErr
	}
	return out, nil
}

func loadEmbedded(id string) (*Bundle, error) {
	b, err := loadBundleFromDir(id, bundleFS, bundleDirName)
	if err != nil {
		return nil, err
	}
	b.Path = "embedded:" + id
	return b, nil
}

func loadBundleFromDir(id string, fsys fs.FS, dir string) (*Bundle, error) {
	manifestData, err := fs.ReadFile(fsys, path(dir, id+".json"))
	if err != nil {
		return nil, err
	}

	var m BundleManifest
	if err := json.Unmarshal(manifestData, &m); err != nil {
		return nil, fmt.Errorf("bundle %s: manifest: %w", id, err)
	}
	if m.ID == "" {
		m.ID = id
	}

	trusted, err := readBundlePEM(fsys, path(dir, id+"-trusted.pem"))
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", id, err)
	}

	distrusted, err := readBundlePEM(fsys, path(dir, id+"-distrusted.pem"))
	if err != nil && !errIsMissing(err) {
		return nil, fmt.Errorf("bundle %s: %w", id, err)
	}

	return &Bundle{Manifest: m, Trusted: trusted, Distrusted: distrusted}, nil
}

func path(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

func readBundlePEM(fsys fs.FS, name string) ([]*x509.Certificate, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func errIsMissing(err error) bool {
	return err != nil && (os.IsNotExist(err) || strings.Contains(err.Error(), "file does not exist"))
}

// --- writing ---

// BundleFiles is the rendered form of a snapshot, ready to be written either
// into the repository by the build-time generator or into the user's bundle
// directory by `certdiag store update`.
type BundleFiles struct {
	Manifest   []byte
	Trusted    []byte
	Distrusted []byte
}

// RenderBundle turns a parsed vendor list into the on-disk files. The MPL
// header must survive into the Mozilla PEM, so licenceHeader is prepended
// verbatim.
func RenderBundle(m BundleManifest, parsed *ParsedBundle, licenceHeader string) (*BundleFiles, error) {
	m.TrustedCount = len(parsed.Trusted)
	m.DistrustedCount = len(parsed.Distrusted)
	if len(parsed.Caveats) > 0 {
		m.Caveats = append(m.Caveats, parsed.Caveats...)
	}

	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestJSON = append(manifestJSON, '\n')

	files := &BundleFiles{
		Manifest: manifestJSON,
		Trusted:  renderPEM(parsed.Trusted, licenceHeader, m, "trusted for TLS server authentication"),
	}
	if len(parsed.Distrusted) > 0 {
		files.Distrusted = renderPEM(parsed.Distrusted, licenceHeader, m, "EXPLICITLY DISTRUSTED by the vendor")
	}
	return files, nil
}

func renderPEM(certs []BundleCert, licenceHeader string, m BundleManifest, kind string) []byte {
	var buf bytes.Buffer
	if licenceHeader != "" {
		buf.WriteString(licenceHeader)
		if !strings.HasSuffix(licenceHeader, "\n") {
			buf.WriteByte('\n')
		}
		buf.WriteString("#\n")
	}
	fmt.Fprintf(&buf, "# %s -- %s\n", m.Name, kind)
	fmt.Fprintf(&buf, "# Snapshot taken %s from %s\n", m.ExtractedAt, m.SourceURL)
	if m.UpstreamRevision != "" {
		fmt.Fprintf(&buf, "# Upstream revision: %s\n", m.UpstreamRevision)
	}
	fmt.Fprintf(&buf, "# License: %s\n", m.License)
	buf.WriteString("#\n# This is a point-in-time snapshot, not a live read of any browser.\n#\n\n")

	// Stable ordering so an unchanged upstream produces a byte-identical file.
	sorted := make([]BundleCert, len(certs))
	copy(sorted, certs)
	sort.SliceStable(sorted, func(i, j int) bool {
		si := sha1.Sum(sorted[i].DER)
		sj := sha1.Sum(sorted[j].DER)
		return bytes.Compare(si[:], sj[:]) < 0
	})

	for _, c := range sorted {
		if c.Label != "" {
			fmt.Fprintf(&buf, "# %s\n", strings.ReplaceAll(c.Label, "\n", " "))
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.DER})
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// WriteBundleFiles writes a rendered snapshot into dir atomically.
func WriteBundleFiles(dir, id string, files *BundleFiles) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, id+"-trusted.pem"), files.Trusted); err != nil {
		return err
	}
	distrustPath := filepath.Join(dir, id+"-distrusted.pem")
	if len(files.Distrusted) > 0 {
		if err := writeFileAtomic(distrustPath, files.Distrusted); err != nil {
			return err
		}
	} else {
		_ = os.Remove(distrustPath)
	}
	return writeFileAtomic(filepath.Join(dir, id+".json"), files.Manifest)
}

func writeFileAtomic(target string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".certdiag-bundle-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, target); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}

// Licence notices that must travel with the data. MPL-2.0 is file-level
// copyleft, so the notice in the generated Mozilla PEM is a condition of
// redistribution rather than a courtesy; the Chromium notice preserves the
// BSD-3-Clause copyright line.
const (
	mplBundleHeader = `# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Derived from the NSS builtin trust list (certdata.txt). This derived file
# remains under MPL-2.0.`

	chromiumBundleHeader = `# Derived from the Chrome Root Store published in the Chromium source tree.
# Copyright 2015 The Chromium Authors. Redistributed under the Chromium
# BSD-3-Clause licence.`
)

// LicenceHeader returns the notice that must be prepended to a bundle's PEM.
func LicenceHeader(id string) string {
	switch id {
	case BundleMozilla:
		return mplBundleHeader
	case BundleChrome:
		return chromiumBundleHeader
	}
	return ""
}
