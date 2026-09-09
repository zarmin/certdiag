package truststore

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/pkg/sqliteread"
)

// StoreTypeNSS covers Firefox, Thunderbird and Chrome-on-Linux profile
// databases (cert9.db).
const StoreTypeNSS StoreType = "nss"

// nssScopeWarning is attached to every NSS store. A profile database holds only
// the certificates that were added to or overridden in that profile; the
// vendor's built-in root list is compiled into libnssckbi and is not in the
// file. Without this note a short list reads as "the browser trusts nothing".
const nssScopeWarning = "profile store: user-added and overridden certificates only; " +
	"built-in roots live in libnssckbi and are not in cert9.db"

// PKCS#11 object classes found in nssPublic.
const (
	ckoCertificate uint32 = 0x00000001
	ckoTrust       uint32 = 0x0000000B // PKCS#11 3.x CKO_TRUST
	ckoNSSTrust    uint32 = 0xCE534353 // legacy vendor CKO_NSS_TRUST
)

// Column names are "a" + lowercase hex of the PKCS#11 attribute id.
const (
	colClass        = "a0"  // CKA_CLASS
	colLabel        = "a3"  // CKA_LABEL
	colValue        = "a11" // CKA_VALUE, the certificate DER
	colIssuer       = "a81" // CKA_ISSUER
	colSerialNumber = "a82" // CKA_SERIAL_NUMBER

	// Modern (PKCS#11 3.x) trust object columns.
	colTrustServerAuth = "a62c"
	colTrustClientAuth = "a62d"
	colTrustCodeSign   = "a62e"
	colTrustEmail      = "a62f"
	colCertSHA256      = "a635"

	// Legacy (CKO_NSS_TRUST) trust object columns.
	colLegacyServerAuth = "ace536358"
	colLegacyClientAuth = "ace536359"
	colLegacyCodeSign   = "ace53635a"
	colLegacyEmail      = "ace53635b"
	colLegacyCertSHA1   = "ace5363b4"
)

// Modern CKT_* trust values, derived empirically by diffing databases built
// with known `certutil -t` flags. See design_m29 nss_findings.md §3.2.
const (
	cktModernTrustAnchor uint32 = 2
	cktModernNotTrusted  uint32 = 3
	cktModernMustVerify  uint32 = 4
)

// Legacy CKT_NSS_* trust values (CKT_NSS = 0xCE534350).
const (
	cktNSSTrusted          uint32 = 0xCE534351
	cktNSSTrustedDelegator uint32 = 0xCE534352
	cktNSSMustVerify       uint32 = 0xCE534353
	cktNSSTrustUnknown     uint32 = 0xCE534355
	cktNSSNotTrusted       uint32 = 0xCE53435A
	cktNSSValidDelegator   uint32 = 0xCE53435B
)

// nssProfile is one discovered profile database.
type nssProfile struct {
	name string
	path string // path to cert9.db
}

// DiscoverNSSStores lists every NSS profile database on the machine without
// reading its contents beyond a cert count.
func DiscoverNSSStores() []StoreInfo {
	var out []StoreInfo
	for _, p := range discoverNSSProfiles() {
		info := StoreInfo{
			Type:     StoreTypeNSS,
			Name:     p.name,
			Path:     p.path,
			Warnings: []string{nssScopeWarning},
		}
		if certs, _, warns, err := readNSSDatabase(p.path); err == nil {
			info.CertCount = len(certs)
			info.Warnings = append(info.Warnings, warns...)
		}
		out = append(out, info)
	}
	return out
}

// ReadNSSStores reads every discovered NSS profile database. A profile that
// cannot be read is returned as an empty store carrying the failure, so the
// caller can render it rather than silently dropping it.
func ReadNSSStores() ([]StoreContents, error) {
	profiles := discoverNSSProfiles()
	if len(profiles) == 0 {
		return nil, nil
	}

	var out []StoreContents
	for _, p := range profiles {
		sc := StoreContents{
			Info: StoreInfo{
				Type:     StoreTypeNSS,
				Name:     p.name,
				Path:     p.path,
				Warnings: []string{nssScopeWarning},
			},
		}

		certs, trust, warns, err := readNSSDatabase(p.path)
		if err != nil {
			sc.Info.Warnings = append(sc.Info.Warnings, fmt.Sprintf("read error: %v", err))
			out = append(out, sc)
			continue
		}

		sc.Certificates = certs
		sc.TrustMap = trust
		sc.Info.CertCount = len(certs)
		sc.Info.Warnings = append(sc.Info.Warnings, warns...)
		out = append(out, sc)
	}

	return out, nil
}

// readNSSDatabase opens one cert9.db and returns its certificates, the trust
// map keyed by the same SHA-256 fingerprint the rest of certdiag uses, and any
// warnings about the read.
func readNSSDatabase(path string) ([]*x509.Certificate, map[string]CertTrust, []string, error) {
	db, err := sqliteread.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer db.Close()

	var certs []*x509.Certificate
	// Trust rows may appear before or after their certificate, so collect them
	// by hash and resolve afterwards.
	bySHA256 := make(map[string]CertTrust)
	bySHA1 := make(map[string]CertTrust)

	scanErr := db.Scan("nssPublic", func(r sqliteread.Row) error {
		class, ok := r.Uint32BE(colClass)
		if !ok {
			return nil
		}

		switch class {
		case ckoCertificate:
			der := r.Blob(colValue)
			if len(der) == 0 {
				return nil
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil
			}
			certs = append(certs, cert)

		case ckoTrust:
			t, ok := modernTrust(r)
			if !ok {
				return nil
			}
			if h := r.Blob(colCertSHA256); len(h) == sha256.Size {
				bySHA256[hex.EncodeToString(h)] = t
			}

		case ckoNSSTrust:
			t, ok := legacyTrust(r)
			if !ok {
				return nil
			}
			if h := r.Blob(colLegacyCertSHA1); len(h) == sha1.Size {
				bySHA1[hex.EncodeToString(h)] = t
			}
		}
		return nil
	})
	if scanErr != nil {
		return nil, nil, nil, scanErr
	}

	trustMap := make(map[string]CertTrust)
	for _, cert := range certs {
		fp := CertFingerprint(cert)
		if t, ok := bySHA256[fp]; ok {
			trustMap[fp] = t
			continue
		}
		sum := sha1.Sum(cert.Raw)
		if t, ok := bySHA1[hex.EncodeToString(sum[:])]; ok {
			trustMap[fp] = t
		}
	}

	// Content committed to a -wal or -journal sidecar is not replayed by the
	// reader, so a live browser can leave the main file behind. Never silent.
	var warnings []string
	for _, s := range db.Sidecars() {
		warnings = append(warnings, fmt.Sprintf(
			"%s present: the profile has uncommitted content this reader does not replay; close the application for an exact view",
			filepath.Base(s)))
	}

	return certs, trustMap, warnings, nil
}

func modernTrust(r sqliteread.Row) (CertTrust, bool) {
	purposes := []struct {
		name string
		col  string
	}{
		{purposeServerAuth, colTrustServerAuth},
		{purposeClientAuth, colTrustClientAuth},
		{purposeCodeSigning, colTrustCodeSign},
		{purposeEmail, colTrustEmail},
	}

	var policies []TrustPolicy
	for _, p := range purposes {
		v, ok := r.Uint32BE(p.col)
		if !ok {
			continue
		}
		status, known := modernStatus(v)
		if !known {
			continue
		}
		policies = append(policies, TrustPolicy{Purpose: p.name, Status: status})
	}
	if len(policies) == 0 {
		return CertTrust{}, false
	}
	return CertTrust{Overall: overallStatus(policies), Policies: policies}, true
}

func legacyTrust(r sqliteread.Row) (CertTrust, bool) {
	purposes := []struct {
		name string
		col  string
	}{
		{purposeServerAuth, colLegacyServerAuth},
		{purposeClientAuth, colLegacyClientAuth},
		{purposeCodeSigning, colLegacyCodeSign},
		{purposeEmail, colLegacyEmail},
	}

	var policies []TrustPolicy
	for _, p := range purposes {
		v, ok := r.Uint32BE(p.col)
		if !ok {
			continue
		}
		status, known := legacyStatus(v)
		if !known {
			continue
		}
		policies = append(policies, TrustPolicy{Purpose: p.name, Status: status})
	}
	if len(policies) == 0 {
		return CertTrust{}, false
	}
	return CertTrust{Overall: overallStatus(policies), Policies: policies}, true
}

const (
	purposeServerAuth  = "Server Auth"
	purposeClientAuth  = "Client Auth"
	purposeCodeSigning = "Code Signing"
	purposeEmail       = "Email Protection"
)

func modernStatus(v uint32) (TrustStatus, bool) {
	switch v {
	case cktModernTrustAnchor:
		return TrustTrusted, true
	case cktModernNotTrusted:
		return TrustDenied, true
	case cktModernMustVerify:
		return TrustUnset, true
	}
	return TrustUnset, false
}

func legacyStatus(v uint32) (TrustStatus, bool) {
	switch v {
	case cktNSSTrusted, cktNSSTrustedDelegator, cktNSSValidDelegator:
		return TrustTrusted, true
	case cktNSSNotTrusted:
		return TrustDenied, true
	case cktNSSMustVerify, cktNSSTrustUnknown:
		return TrustUnset, true
	}
	return TrustUnset, false
}

// overallStatus collapses per-purpose settings: an explicit denial anywhere
// wins, then any trusted purpose, else unset.
func overallStatus(policies []TrustPolicy) TrustStatus {
	overall := TrustUnset
	for _, p := range policies {
		if p.Status == TrustDenied {
			return TrustDenied
		}
		if p.Status == TrustTrusted {
			overall = TrustTrusted
		}
	}
	return overall
}

// --- profile discovery ---

// nssProfileRoots is indirected so tests can point discovery at a fixture tree
// instead of the user's real home directory.
var nssProfileRoots = defaultNSSProfileRoots

func discoverNSSProfiles() []nssProfile {
	var out []nssProfile
	seen := make(map[string]bool)

	for _, root := range nssProfileRoots() {
		for _, p := range profilesFromRoot(root) {
			abs, err := filepath.Abs(p.path)
			if err != nil {
				abs = p.path
			}
			if seen[abs] {
				continue
			}
			seen[abs] = true
			out = append(out, p)
		}
	}
	return out
}

// nssRoot describes one place profiles can live.
type nssRoot struct {
	label string
	dir   string
	// direct means dir itself holds a cert9.db, with no profiles.ini.
	direct bool
}

func defaultNSSProfileRoots() []nssRoot {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	var roots []nssRoot
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots,
			nssRoot{label: "Firefox", dir: filepath.Join(home, "Library", "Application Support", "Firefox")},
			nssRoot{label: "Thunderbird", dir: filepath.Join(home, "Library", "Thunderbird")},
		)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		roots = append(roots,
			nssRoot{label: "Firefox", dir: filepath.Join(appData, "Mozilla", "Firefox")},
			nssRoot{label: "Thunderbird", dir: filepath.Join(appData, "Thunderbird")},
		)
	default:
		roots = append(roots,
			nssRoot{label: "Firefox", dir: filepath.Join(home, ".mozilla", "firefox")},
			nssRoot{label: "Thunderbird", dir: filepath.Join(home, ".thunderbird")},
			// Chrome and Chromium on Linux share one NSS database with no
			// profiles.ini beside it.
			nssRoot{label: "Chrome/Chromium NSS", dir: filepath.Join(home, ".pki", "nssdb"), direct: true},
		)
	}
	return roots
}

func profilesFromRoot(root nssRoot) []nssProfile {
	if root.direct {
		db := filepath.Join(root.dir, "cert9.db")
		if !fileExists(db) {
			return nil
		}
		return []nssProfile{{name: root.label, path: db}}
	}

	iniPath := filepath.Join(root.dir, "profiles.ini")
	entries := parseProfilesINI(iniPath)
	if len(entries) == 0 {
		return nil
	}

	var out []nssProfile
	for _, e := range entries {
		dir := e.path
		if e.relative {
			dir = filepath.Join(root.dir, dir)
		}
		db := filepath.Join(dir, "cert9.db")
		if !fileExists(db) {
			continue
		}
		name := root.label
		if e.name != "" {
			name = fmt.Sprintf("%s (%s)", root.label, e.name)
		}
		out = append(out, nssProfile{name: name, path: db})
	}
	return out
}

type profileEntry struct {
	section   string
	name      string
	path      string
	relative  bool
	isDefault bool
}

// parseProfilesINI reads the [ProfileN] sections of a Mozilla profiles.ini.
// Default profiles are returned first so the most relevant store leads.
func parseProfilesINI(path string) []profileEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var entries []profileEntry
	var cur *profileEntry

	flush := func() {
		if cur != nil && cur.path != "" {
			entries = append(entries, *cur)
		}
		cur = nil
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			flush()
			section := line[1 : len(line)-1]
			if strings.HasPrefix(section, "Profile") {
				cur = &profileEntry{section: section, relative: true}
			}
			continue
		}

		if cur == nil {
			continue
		}

		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch strings.ToLower(key) {
		case "name":
			cur.name = val
		case "path":
			cur.path = filepath.FromSlash(val)
		case "isrelative":
			cur.relative = val != "0"
		case "default":
			cur.isDefault = val == "1"
		}
	}
	flush()

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].isDefault && !entries[j].isDefault
	})
	return entries
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
