package certops

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

// The AIA cache stores bytes, never verdicts. A cached certificate is
// signature-checked again on every use and the trust decision is recomputed
// from scratch, so caching cannot make certdiag report something stale as
// current. Every surface that used a cached certificate says so, with the date
// it was fetched.

// DefaultAIACacheTTL is deliberately long and fixed. Issuer certificates change
// rarely, and a fixed lifetime is easier to reason about than HTTP cache
// headers when an answer looks wrong.
const DefaultAIACacheTTL = 30 * 24 * time.Hour

type aiaCacheIndex struct {
	Kind    string          `yaml:"kind"`
	Version string          `yaml:"version"`
	Entries []aiaCacheEntry `yaml:"entries"`
}

// AIACacheEntry is one remembered fetch.
type AIACacheEntry struct {
	SHA256    string    `yaml:"sha256" json:"sha256"`
	URL       string    `yaml:"url" json:"url"`
	Subject   string    `yaml:"subject" json:"subject"`
	FetchedAt time.Time `yaml:"fetched_at" json:"fetched_at"`
	ExpiresAt time.Time `yaml:"expires_at" json:"expires_at"`
}

type aiaCacheEntry = AIACacheEntry

// FileAIACache remembers fetched issuers under ~/.certdiag/aia.
type FileAIACache struct {
	Dir string
	TTL time.Duration
	Now func() time.Time

	index *aiaCacheIndex
}

// OpenAIACache opens the per-user cache. An unparseable TTL is an error rather
// than a silent default, since a mistyped duration should not quietly change
// how long answers are remembered.
func OpenAIACache(ttl string) (*FileAIACache, error) {
	dir, err := config.AIACacheDir()
	if err != nil {
		return nil, err
	}
	d := DefaultAIACacheTTL
	if ttl != "" {
		parsed, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid aia cache_ttl %q: %w", ttl, err)
		}
		d = parsed
	}
	return &FileAIACache{Dir: dir, TTL: d}, nil
}

func (c *FileAIACache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *FileAIACache) indexPath() string { return filepath.Join(c.Dir, "index.yaml") }

func (c *FileAIACache) load() *aiaCacheIndex {
	if c.index != nil {
		return c.index
	}
	c.index = &aiaCacheIndex{Kind: "certdiag-aia-cache", Version: "1"}
	data, err := os.ReadFile(c.indexPath())
	if err != nil {
		return c.index
	}
	var parsed aiaCacheIndex
	if err := yaml.Unmarshal(data, &parsed); err == nil {
		c.index = &parsed
	}
	return c.index
}

// Get returns a remembered certificate for a URL, if one is present and still
// within its lifetime. A file that no longer parses counts as absent.
func (c *FileAIACache) Get(url string) (certlib.AIAFetched, bool) {
	idx := c.load()
	for _, e := range idx.Entries {
		if e.URL != url {
			continue
		}
		if c.now().After(e.ExpiresAt) {
			return certlib.AIAFetched{}, false
		}
		der, err := os.ReadFile(filepath.Join(c.Dir, e.SHA256+".der"))
		if err != nil {
			return certlib.AIAFetched{}, false
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return certlib.AIAFetched{}, false
		}
		return certlib.AIAFetched{
			Cert:      cert,
			URL:       e.URL,
			Source:    certlib.AIASourceCached,
			FetchedAt: e.FetchedAt,
		}, true
	}
	return certlib.AIAFetched{}, false
}

// Put remembers a fetched certificate. It expires at the earlier of the TTL and
// the certificate's own NotAfter: remembering a certificate past its validity
// would only produce a confusing answer later.
func (c *FileAIACache) Put(f certlib.AIAFetched) error {
	if f.Cert == nil {
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}

	sum := sha256.Sum256(f.Cert.Raw)
	id := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(c.Dir, id+".der"), f.Cert.Raw, 0o600); err != nil {
		return err
	}

	fetchedAt := f.FetchedAt
	if fetchedAt.IsZero() {
		fetchedAt = c.now()
	}
	expires := fetchedAt.Add(c.TTL)
	if f.Cert.NotAfter.Before(expires) {
		expires = f.Cert.NotAfter
	}

	idx := c.load()
	entry := AIACacheEntry{
		SHA256:    id,
		URL:       f.URL,
		Subject:   certlib.FormatDNName(f.Cert.Subject),
		FetchedAt: fetchedAt,
		ExpiresAt: expires,
	}
	replaced := false
	for i := range idx.Entries {
		if idx.Entries[i].URL == f.URL {
			idx.Entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		idx.Entries = append(idx.Entries, entry)
	}
	return c.save()
}

func (c *FileAIACache) save() error {
	data, err := yaml.Marshal(c.load())
	if err != nil {
		return err
	}
	return os.WriteFile(c.indexPath(), data, 0o600)
}

// List returns what the cache holds, for `certdiag aia cache list`.
func (c *FileAIACache) List() []AIACacheEntry {
	return c.load().Entries
}

// Clear empties the cache.
func (c *FileAIACache) Clear() error {
	c.index = nil
	if err := os.RemoveAll(c.Dir); err != nil {
		return err
	}
	return nil
}
