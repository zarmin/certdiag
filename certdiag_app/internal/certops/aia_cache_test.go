package certops

import (
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// The cache stores bytes, never verdicts. These tests pin that: a hit is
// re-parsed and re-checked, an expired or damaged entry counts as absent, and
// nothing is written unless caching was asked for.

func testCache(t *testing.T, now time.Time) *FileAIACache {
	t.Helper()
	return &FileAIACache{
		Dir: t.TempDir(),
		TTL: DefaultAIACacheTTL,
		Now: func() time.Time { return now },
	}
}

func TestAIACache_WriteThenRead(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	cache := testCache(t, now)
	root, _ := verifyTestCert(t, "Cache Root", true, nil, nil, nil)

	err := cache.Put(certlib.AIAFetched{Cert: root, URL: "http://ca.example/root.crt", FetchedAt: now})
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	got, ok := cache.Get("http://ca.example/root.crt")
	if !ok {
		t.Fatal("expected a hit")
	}
	if !got.Cert.Equal(root) {
		t.Error("the cached certificate must come back unchanged")
	}
	if got.Source != certlib.AIASourceCached {
		t.Error("a hit must be labelled as coming from the cache")
	}
	if !got.FetchedAt.Equal(now) {
		t.Errorf("the original fetch time must survive, got %v", got.FetchedAt)
	}
}

// TestAIACache_ExpiresAfterTTL: a fixed lifetime, not an HTTP cache header.
func TestAIACache_ExpiresAfterTTL(t *testing.T) {
	now := time.Now()
	cache := testCache(t, now)
	// A TTL well inside the fixture's own validity, so this exercises the TTL
	// rather than the NotAfter cap that TestAIACache_ExpiryNeverOutlivesThe-
	// Certificate covers.
	cache.TTL = time.Hour
	root, _ := verifyTestCert(t, "TTL Root", true, nil, nil, nil)
	cache.Put(certlib.AIAFetched{Cert: root, URL: "http://ca.example/root.crt", FetchedAt: now})

	cache.Now = func() time.Time { return now.Add(30 * time.Minute) }
	if _, ok := cache.Get("http://ca.example/root.crt"); !ok {
		t.Error("inside the TTL the entry must still be there")
	}

	cache.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, ok := cache.Get("http://ca.example/root.crt"); ok {
		t.Error("past the TTL the entry must be gone")
	}
}

// TestAIACache_ExpiryNeverOutlivesTheCertificate: remembering a certificate
// past its own validity would only produce a confusing answer later.
func TestAIACache_ExpiryNeverOutlivesTheCertificate(t *testing.T) {
	now := time.Now()
	cache := testCache(t, now)
	root, _ := verifyTestCert(t, "Short Root", true, nil, nil, nil) // valid 24h

	cache.Put(certlib.AIAFetched{Cert: root, URL: "http://ca.example/root.crt", FetchedAt: now})

	entries := cache.List()
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	if entries[0].ExpiresAt.After(root.NotAfter) {
		t.Errorf("cache expiry %v outlives the certificate %v", entries[0].ExpiresAt, root.NotAfter)
	}
}

// TestAIACache_DamagedEntryIsAbsent: a file that no longer parses must be
// treated as missing rather than crashing or returning nonsense.
func TestAIACache_DamagedEntryIsAbsent(t *testing.T) {
	now := time.Now()
	cache := testCache(t, now)
	root, _ := verifyTestCert(t, "Damaged Root", true, nil, nil, nil)
	cache.Put(certlib.AIAFetched{Cert: root, URL: "http://ca.example/root.crt", FetchedAt: now})

	entries := cache.List()
	path := filepath.Join(cache.Dir, entries[0].SHA256+".der")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, ok := cache.Get("http://ca.example/root.crt"); ok {
		t.Error("a damaged entry must count as absent")
	}
}

func TestAIACache_MissingURLIsAMiss(t *testing.T) {
	cache := testCache(t, time.Now())
	if _, ok := cache.Get("http://ca.example/never-seen.crt"); ok {
		t.Error("an unknown URL must be a miss")
	}
}

func TestAIACache_Clear(t *testing.T) {
	now := time.Now()
	cache := testCache(t, now)
	root, _ := verifyTestCert(t, "Clear Root", true, nil, nil, nil)
	cache.Put(certlib.AIAFetched{Cert: root, URL: "http://ca.example/root.crt", FetchedAt: now})

	if err := cache.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(cache.List()) != 0 {
		t.Error("the cache must be empty after clearing")
	}
	if _, ok := cache.Get("http://ca.example/root.crt"); ok {
		t.Error("nothing must survive a clear")
	}
}

func TestOpenAIACache_RejectsBadTTL(t *testing.T) {
	if _, err := OpenAIACache("not-a-duration"); err == nil {
		t.Error("a mistyped TTL must be an error, not a silent default")
	}
	c, err := OpenAIACache("")
	if err != nil {
		t.Fatalf("an empty TTL must fall back to the default: %v", err)
	}
	if c.TTL != DefaultAIACacheTTL {
		t.Errorf("expected the 30-day default, got %v", c.TTL)
	}
}

// TestAIAContainer_ProvenanceLabel: "fetched just now" and "remembered from
// three weeks ago" are different claims and the label must say which.
func TestAIAContainer_ProvenanceLabel(t *testing.T) {
	root, _ := verifyTestCert(t, "Label Root", true, nil, nil, nil)
	when := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	fresh := AIAContainer(certlib.AIAResult{Fetched: []certlib.AIAFetched{
		{Cert: root, URL: "u", Source: certlib.AIASourceFetched, FetchedAt: time.Now()},
	}})
	if fresh.Label != AIAContainerLabel {
		t.Errorf("a live fetch reads %q, got %q", AIAContainerLabel, fresh.Label)
	}

	cached := AIAContainer(certlib.AIAResult{Fetched: []certlib.AIAFetched{
		{Cert: root, URL: "u", Source: certlib.AIASourceCached, FetchedAt: when},
	}})
	if cached.Label != "AIA cache (fetched 2026-09-01)" {
		t.Errorf("a cached certificate must carry its date, got %q", cached.Label)
	}
	if cached.Source != certlib.SourceAIA {
		t.Errorf("expected SourceAIA, got %q", cached.Source)
	}
}

// TestAIAContainer_FailuresSurvive: a CA whose server is down is worth saying,
// not silently dropping.
func TestAIAContainer_FailuresSurvive(t *testing.T) {
	root, _ := verifyTestCert(t, "Fail Root", true, nil, nil, nil)
	c := AIAContainer(certlib.AIAResult{
		Fetched:  []certlib.AIAFetched{{Cert: root, URL: "u", FetchedAt: time.Now()}},
		Failures: []certlib.AIAFailure{{URL: "http://ca.example/down.crt", Reason: "http 503"}},
	})
	if len(c.ParseErrors) != 1 {
		t.Fatalf("expected the failure to be recorded, got %v", c.ParseErrors)
	}
}

func TestAIAContainer_EmptyIsNil(t *testing.T) {
	if c := AIAContainer(certlib.AIAResult{}); c != nil {
		t.Error("nothing fetched means no container")
	}
}

// TestSaveRemoteCerts_AIAProvenance: a saved chain that quietly contains
// certificates the server never sent would be misread. Each fetched one is
// annotated, and the file must still parse everywhere.
func TestSaveRemoteCerts_AIAProvenance(t *testing.T) {
	root, rootKey := verifyTestCert(t, "Save Root", true, nil, nil, nil)
	leaf, _ := verifyTestCert(t, "leaf.example", false, root, rootKey, nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "chain.pem")
	when := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	_, err := SaveRemoteCerts("leaf.example:443", []*x509.Certificate{leaf, root}, SaveRemoteOptions{
		SaveTo:     path,
		Overwrite:  true,
		SaveFormat: "pem",
		AIAProvenance: map[[32]byte]certlib.AIAFetched{
			sha256.Sum256(root.Raw): {
				Cert: root, URL: "http://ca.example/root.crt",
				Source: certlib.AIASourceFetched, FetchedAt: when,
			},
		},
	})
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "# AIA:") {
		t.Errorf("the fetched certificate must be annotated:\n%s", text)
	}
	if !strings.Contains(text, "http://ca.example/root.crt") {
		t.Error("the annotation must name where it came from")
	}
	if !strings.Contains(text, "2026-09-01") {
		t.Error("the annotation must carry the date")
	}

	// The comment must not stop certdiag, or anything else, reading the file.
	container, err := certlib.ReadFile(path, nil)
	if err != nil {
		t.Fatalf("an annotated chain must still parse: %v", err)
	}
	if len(container.Items) != 2 {
		t.Errorf("expected both certificates back, got %d", len(container.Items))
	}
}
