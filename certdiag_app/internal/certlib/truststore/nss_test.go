package truststore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nssFixtures is the committed corpus. Regenerate with
// tools/testing/gen_nss_fixtures.sh; nothing is needed to run these tests.
//
// It lives in testdata rather than tools/testing/edgecases/fixtures because
// that tree is gitignored and regenerated wholesale by the CLI harness.
const nssFixtures = "testdata/nss"

func nssFixture(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{nssFixtures}, parts...)...)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("NSS fixture %s missing; run tools/testing/gen_nss_fixtures.sh", path)
	}
	return path
}

// withProfileRoots points discovery at fixtures. No test may ever name a real
// profile directory.
func withProfileRoots(t *testing.T, roots ...nssRoot) {
	t.Helper()
	prev := nssProfileRoots
	nssProfileRoots = func() []nssRoot { return roots }
	t.Cleanup(func() { nssProfileRoots = prev })
}

func directRoot(t *testing.T, label, dir string) nssRoot {
	return nssRoot{label: label, dir: nssFixture(t, dir), direct: true}
}

func TestReadNSS_CertificatesAndAlias(t *testing.T) {
	withProfileRoots(t, directRoot(t, "Fixture", "profile-trusted"))

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("expected 1 store, got %d", len(stores))
	}

	s := stores[0]
	if len(s.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(s.Certificates))
	}
	cert := s.Certificates[0]
	if !strings.Contains(cert.Subject.CommonName, "NSS Fixture") {
		t.Errorf("unexpected subject %q", cert.Subject.CommonName)
	}
	if s.Info.Type != StoreTypeNSS {
		t.Errorf("expected the nss store type, got %q", s.Info.Type)
	}
	if s.Info.CertCount != 1 {
		t.Errorf("expected CertCount 1, got %d", s.Info.CertCount)
	}
}

// TestReadNSS_TrustFlags is the table the encoding was reverse-engineered from:
// certutil flags in, CertTrust out. See nss_findings.md §3.2.
func TestReadNSS_TrustFlags(t *testing.T) {
	cases := []struct {
		dir        string
		certutil   string
		overall    TrustStatus
		serverAuth TrustStatus
		otherFirst TrustStatus
		policies   int
	}{
		{"profile-trusted", "CT,C,C", TrustTrusted, TrustTrusted, TrustTrusted, 4},
		{"profile-distrusted", "p,p,p", TrustDenied, TrustDenied, TrustDenied, 4},
		{"profile-serverauth", "C,,", TrustTrusted, TrustTrusted, TrustUnset, 4},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			withProfileRoots(t, directRoot(t, "Fixture", tc.dir))

			stores, err := ReadNSSStores()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(stores) != 1 || len(stores[0].Certificates) != 1 {
				t.Fatalf("expected exactly one certificate in one store")
			}

			trust := stores[0].GetTrust(stores[0].Certificates[0])
			if trust.Overall != tc.overall {
				t.Errorf("certutil -t %q: expected overall %q, got %q", tc.certutil, tc.overall, trust.Overall)
			}
			if len(trust.Policies) != tc.policies {
				t.Fatalf("expected %d per-purpose policies, got %v", tc.policies, trust.Policies)
			}

			var serverAuth, other TrustStatus
			for _, p := range trust.Policies {
				if p.Purpose == purposeServerAuth {
					serverAuth = p.Status
				} else if other == "" {
					other = p.Status
				}
			}
			if serverAuth != tc.serverAuth {
				t.Errorf("expected server auth %q, got %q", tc.serverAuth, serverAuth)
			}
			if other != tc.otherFirst {
				t.Errorf("expected the other purposes %q, got %q", tc.otherFirst, other)
			}
		})
	}
}

// TestReadNSS_NoTrustRow: `certutil -t ",,"` writes no trust object at all.
// The certificate must still be listed, with no fabricated verdict.
func TestReadNSS_NoTrustRow(t *testing.T) {
	withProfileRoots(t, directRoot(t, "Fixture", "profile-notrust"))

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stores) != 1 || len(stores[0].Certificates) != 1 {
		t.Fatalf("expected the certificate to be listed without a trust record")
	}
	if len(stores[0].TrustMap) != 0 {
		t.Errorf("expected no trust records, got %v", stores[0].TrustMap)
	}
	if got := stores[0].GetTrust(stores[0].Certificates[0]).Overall; got != TrustUnset {
		t.Errorf("expected Unset, got %q", got)
	}
}

func TestReadNSS_EmptyProfile(t *testing.T) {
	withProfileRoots(t, directRoot(t, "Fixture", "profile-empty"))

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatalf("an empty profile must not be an error: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("expected the empty store to still be reported, got %d", len(stores))
	}
	if len(stores[0].Certificates) != 0 {
		t.Errorf("expected no certificates, got %d", len(stores[0].Certificates))
	}
}

// TestReadNSS_ScopeWarning guards the claim the UI makes. A profile database
// holds only what was added to or overridden in that profile; without this note
// a short list reads as "the browser trusts nothing".
func TestReadNSS_ScopeWarning(t *testing.T) {
	withProfileRoots(t, directRoot(t, "Fixture", "profile-trusted"))

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(stores[0].Info.Warnings, " ")
	if !strings.Contains(joined, "libnssckbi") {
		t.Errorf("every NSS store must carry the built-in-roots note, got %v", stores[0].Info.Warnings)
	}
	if !strings.Contains(joined, "user-added") {
		t.Errorf("the scope note must say what the store actually contains, got %v", stores[0].Info.Warnings)
	}
}

func TestReadNSS_NoProfiles(t *testing.T) {
	withProfileRoots(t)

	stores, err := ReadNSSStores()
	if err != nil {
		t.Errorf("no profiles is not an error: %v", err)
	}
	if len(stores) != 0 {
		t.Errorf("expected no stores, got %d", len(stores))
	}
}

func TestReadNSS_UnreadableProfileIsKept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert9.db"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	withProfileRoots(t, nssRoot{label: "Broken", dir: dir, direct: true})

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatalf("a broken profile must not abort the read: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("expected the broken profile to still be reported, got %d", len(stores))
	}
	joined := strings.Join(stores[0].Info.Warnings, " ")
	if !strings.Contains(joined, "read error") {
		t.Errorf("expected the failure in the warnings, got %v", stores[0].Info.Warnings)
	}
}

func TestReadNSS_SidecarWarning(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(nssFixture(t, "profile-trusted", "cert9.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "cert9.db")
	if err := os.WriteFile(db, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db+"-wal", []byte("uncommitted"), 0o600); err != nil {
		t.Fatal(err)
	}
	withProfileRoots(t, nssRoot{label: "Live", dir: dir, direct: true})

	stores, err := ReadNSSStores()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(stores[0].Info.Warnings, " ")
	if !strings.Contains(joined, "uncommitted content") {
		t.Errorf("a non-empty -wal must be reported, got %v", stores[0].Info.Warnings)
	}
	// The certificates still read; the warning is disclosure, not a refusal.
	if len(stores[0].Certificates) != 1 {
		t.Errorf("expected the certificate to still be read, got %d", len(stores[0].Certificates))
	}
}

func TestDiscoverNSS_ProfilesINI(t *testing.T) {
	withProfileRoots(t, nssRoot{label: "Firefox", dir: nssFixture(t, "firefox-root")})

	infos := DiscoverNSSStores()
	if len(infos) != 2 {
		t.Fatalf("expected the 2 profiles that exist (the third is missing), got %d: %+v", len(infos), infos)
	}

	// Default=1 sorts first, so the most relevant store leads.
	if !strings.Contains(infos[0].Name, "default-release") {
		t.Errorf("expected the default profile first, got %q", infos[0].Name)
	}
	if !strings.Contains(infos[1].Name, "other") {
		t.Errorf("expected the second profile, got %q", infos[1].Name)
	}
	for _, i := range infos {
		if !strings.HasPrefix(i.Name, "Firefox (") {
			t.Errorf("expected the root label in the name, got %q", i.Name)
		}
		if i.CertCount != 1 {
			t.Errorf("%s: expected 1 certificate, got %d", i.Name, i.CertCount)
		}
	}
}

func TestParseProfilesINI(t *testing.T) {
	dir := t.TempDir()
	ini := filepath.Join(dir, "profiles.ini")
	// CRLF, comments, an absolute path and a section that is not a profile.
	content := "; a comment\r\n" +
		"[General]\r\nStartWithLastProfile=1\r\n\r\n" +
		"[Profile0]\r\nName=one\r\nIsRelative=1\r\nPath=Profiles/one\r\n\r\n" +
		"[Profile1]\r\nName=two\r\nIsRelative=0\r\nPath=/absolute/two\r\nDefault=1\r\n\r\n" +
		"[Profile2]\r\nName=nopath\r\n"
	if err := os.WriteFile(ini, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := parseProfilesINI(ini)
	if len(entries) != 2 {
		t.Fatalf("expected 2 usable entries (the third has no Path), got %d: %+v", len(entries), entries)
	}
	if entries[0].name != "two" || !entries[0].isDefault {
		t.Errorf("expected the default profile first, got %+v", entries[0])
	}
	if entries[0].relative {
		t.Error("IsRelative=0 must be honoured")
	}
	if entries[1].name != "one" || !entries[1].relative {
		t.Errorf("expected the relative profile second, got %+v", entries[1])
	}
}

func TestParseProfilesINI_Missing(t *testing.T) {
	if entries := parseProfilesINI(filepath.Join(t.TempDir(), "nope.ini")); entries != nil {
		t.Errorf("expected nil for a missing file, got %v", entries)
	}
}

func TestDiscoverNSS_Dedup(t *testing.T) {
	root := directRoot(t, "Fixture", "profile-trusted")
	withProfileRoots(t, root, root)

	if infos := DiscoverNSSStores(); len(infos) != 1 {
		t.Errorf("the same profile reached twice must appear once, got %d", len(infos))
	}
}

func TestTrustStatusMapping(t *testing.T) {
	// Modern PKCS#11 3.x values, derived empirically (nss_findings.md §3.2).
	for value, want := range map[uint32]TrustStatus{
		cktModernTrustAnchor: TrustTrusted,
		cktModernNotTrusted:  TrustDenied,
		cktModernMustVerify:  TrustUnset,
	} {
		got, known := modernStatus(value)
		if !known || got != want {
			t.Errorf("modern %d: expected %q (known), got %q known=%v", value, want, got, known)
		}
	}
	if _, known := modernStatus(99); known {
		t.Error("an unrecognised modern value must be reported as unknown, not guessed")
	}

	// Legacy vendor values.
	for value, want := range map[uint32]TrustStatus{
		cktNSSTrusted:          TrustTrusted,
		cktNSSTrustedDelegator: TrustTrusted,
		cktNSSValidDelegator:   TrustTrusted,
		cktNSSNotTrusted:       TrustDenied,
		cktNSSMustVerify:       TrustUnset,
		cktNSSTrustUnknown:     TrustUnset,
	} {
		got, known := legacyStatus(value)
		if !known || got != want {
			t.Errorf("legacy %#x: expected %q (known), got %q known=%v", value, want, got, known)
		}
	}
	if _, known := legacyStatus(0xDEADBEEF); known {
		t.Error("an unrecognised legacy value must be reported as unknown")
	}
}

func TestOverallStatus(t *testing.T) {
	cases := []struct {
		name string
		in   []TrustPolicy
		want TrustStatus
	}{
		{"empty", nil, TrustUnset},
		{"all unset", []TrustPolicy{{Status: TrustUnset}, {Status: TrustUnset}}, TrustUnset},
		{"one trusted", []TrustPolicy{{Status: TrustUnset}, {Status: TrustTrusted}}, TrustTrusted},
		{"denial wins over trust", []TrustPolicy{{Status: TrustTrusted}, {Status: TrustDenied}}, TrustDenied},
		{"denial first", []TrustPolicy{{Status: TrustDenied}, {Status: TrustTrusted}}, TrustDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := overallStatus(tc.in); got != tc.want {
				t.Errorf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
