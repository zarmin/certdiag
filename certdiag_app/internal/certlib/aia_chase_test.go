package certlib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// No test may reach a real CA's web server. The fetcher is an interface for
// exactly that reason, and TestNoRealAIAFetchGuard fails if the production one
// is ever used from the test binary.

type stubFetcher struct {
	mu      sync.Mutex
	byURL   map[string][]*x509.Certificate
	errs    map[string]error
	calls   []string
	fetched int
}

func newStubFetcher() *stubFetcher {
	return &stubFetcher{byURL: map[string][]*x509.Certificate{}, errs: map[string]error{}}
}

func (s *stubFetcher) serve(url string, certs ...*x509.Certificate) { s.byURL[url] = certs }
func (s *stubFetcher) fail(url string, err error)                   { s.errs[url] = err }

func (s *stubFetcher) Fetch(_ context.Context, url string) ([]*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, url)
	s.fetched++
	if err, ok := s.errs[url]; ok {
		return nil, err
	}
	certs, ok := s.byURL[url]
	if !ok {
		return nil, errors.New("http 404")
	}
	return certs, nil
}

// aiaCert issues a certificate carrying the CA Issuers URLs given.
func aiaCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, urls ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	cert, key := chainCertWithAIA(t, cn, isCA, parent, parentKey, urls)
	return cert, key
}

// TestChaseAIA_CollectsAllCandidates is the cross-sign case: one hop, two URLs,
// two valid copies of the same issuer. Taking only the first is what made a
// chain fail to complete even though a browser completed it.
func TestChaseAIA_CollectsAllCandidates(t *testing.T) {
	oldRoot, oldKey := aiaCert(t, "Old Root", true, nil, nil)
	newRootSelf, newKey := aiaCert(t, "New Root", true, nil, nil)
	newRootCross := crossSign(t, newRootSelf, newKey, oldRoot, oldKey)

	inter, _ := aiaCert(t, "Issuing CA", true, newRootSelf, newKey,
		"http://ca.example/self.crt", "http://ca.example/cross.crt")

	f := newStubFetcher()
	f.serve("http://ca.example/self.crt", newRootSelf)
	f.serve("http://ca.example/cross.crt", newRootCross)

	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: f})

	if len(got.Fetched) != 2 {
		t.Fatalf("expected both copies of the issuer, got %d", len(got.Fetched))
	}
	var sawSelf, sawCross bool
	for _, entry := range got.Fetched {
		if entry.Cert.Equal(newRootSelf) {
			sawSelf = true
		}
		if entry.Cert.Equal(newRootCross) {
			sawCross = true
		}
	}
	if !sawSelf || !sawCross {
		t.Errorf("expected both copies, self=%v cross=%v", sawSelf, sawCross)
	}
}

// TestChaseAIA_FromEveryInput: a scan of a lone intermediate must chase from it,
// not silently do nothing because it is not a leaf.
func TestChaseAIA_FromEveryInput(t *testing.T) {
	root, rootKey := aiaCert(t, "Chase Root", true, nil, nil)
	inter, _ := aiaCert(t, "Chase Intermediate", true, root, rootKey, "http://ca.example/root.crt")

	f := newStubFetcher()
	f.serve("http://ca.example/root.crt", root)

	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: f})
	if len(got.Fetched) != 1 || !got.Fetched[0].Cert.Equal(root) {
		t.Errorf("expected the root to be fetched for a lone intermediate, got %+v", got.Fetched)
	}
}

// TestChaseAIA_ReturnsWholeBundle: a p7b at a CA Issuers URL can carry the
// whole path, and returning only the first certificate threw the rest away.
func TestChaseAIA_ReturnsWholeBundle(t *testing.T) {
	root, rootKey := aiaCert(t, "Bundle Root", true, nil, nil)
	inter, interKey := aiaCert(t, "Bundle Intermediate", true, root, rootKey)
	leaf, _ := aiaCert(t, "leaf.example", false, inter, interKey, "http://ca.example/bundle.p7c")

	f := newStubFetcher()
	f.serve("http://ca.example/bundle.p7c", inter, root)

	got := ChaseAIA([]*x509.Certificate{leaf}, AIAOptions{Fetcher: f})
	if len(got.Fetched) != 1 {
		t.Fatalf("only the certificate that signed the leaf belongs to this hop, got %d", len(got.Fetched))
	}
	if !got.Fetched[0].Cert.Equal(inter) {
		t.Error("expected the leaf's own issuer from the bundle")
	}
}

// TestChaseAIA_RecordsFailures: "the CA's server is down" and "the CA published
// the wrong certificate" call for different responses, so both are reported.
func TestChaseAIA_RecordsFailures(t *testing.T) {
	root, rootKey := aiaCert(t, "Fail Root", true, nil, nil)
	unrelated, _ := aiaCert(t, "Unrelated CA", true, nil, nil)
	inter, _ := aiaCert(t, "Fail Intermediate", true, root, rootKey,
		"http://ca.example/missing.crt", "http://ca.example/wrong.crt")

	f := newStubFetcher()
	f.fail("http://ca.example/missing.crt", errors.New("http 404"))
	f.serve("http://ca.example/wrong.crt", unrelated)

	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: f})

	if len(got.Fetched) != 0 {
		t.Errorf("nothing usable was served, got %d certificates", len(got.Fetched))
	}
	if len(got.Failures) != 2 {
		t.Fatalf("both URLs failed and both must be reported, got %+v", got.Failures)
	}
	reasons := got.Failures[0].Reason + " " + got.Failures[1].Reason
	if !strings.Contains(reasons, "404") {
		t.Errorf("the transport failure must keep its reason: %q", reasons)
	}
	if !strings.Contains(reasons, "signature") {
		t.Errorf("a certificate that did not sign the requester must say so: %q", reasons)
	}
}

// TestChaseAIA_DepthCap stops a chain of issuers from being followed forever.
func TestChaseAIA_DepthCap(t *testing.T) {
	root, key := aiaCert(t, "Depth 0", true, nil, nil)
	f := newStubFetcher()

	current, currentKey := root, key
	for i := 1; i <= 8; i++ {
		url := "http://ca.example/" + strings.Repeat("x", i) + ".crt"
		child, childKey := aiaCert(t, "Depth "+strings.Repeat("x", i), true, current, currentKey, url)
		f.serve(url, current)
		current, currentKey = child, childKey
	}

	got := ChaseAIA([]*x509.Certificate{current}, AIAOptions{Fetcher: f, MaxDepth: 3})
	if len(got.Fetched) > 3 {
		t.Errorf("the depth cap must hold, got %d hops", len(got.Fetched))
	}
}

func TestChaseAIA_SelfSignedIsNotChased(t *testing.T) {
	root, _ := aiaCert(t, "Terminal Root", true, nil, nil, "http://ca.example/pointless.crt")
	f := newStubFetcher()

	got := ChaseAIA([]*x509.Certificate{root}, AIAOptions{Fetcher: f})
	if f.fetched != 0 {
		t.Errorf("a self-signed root has no issuer to fetch, but %d requests were made", f.fetched)
	}
	if len(got.Fetched) != 0 {
		t.Errorf("expected nothing fetched, got %d", len(got.Fetched))
	}
}

func TestChaseAIA_EachURLFetchedOnce(t *testing.T) {
	root, rootKey := aiaCert(t, "Once Root", true, nil, nil)
	interA, _ := aiaCert(t, "A", true, root, rootKey, "http://ca.example/root.crt")
	interB, _ := aiaCert(t, "B", true, root, rootKey, "http://ca.example/root.crt")

	f := newStubFetcher()
	f.serve("http://ca.example/root.crt", root)

	ChaseAIA([]*x509.Certificate{interA, interB}, AIAOptions{Fetcher: f})
	if f.fetched != 1 {
		t.Errorf("the same URL must be fetched once per chase, got %d requests", f.fetched)
	}
}

// TestChaseAIA_UsesCacheWithoutFetching: a cache hit must not reach the network,
// and must still be signature-checked.
func TestChaseAIA_UsesCacheWithoutFetching(t *testing.T) {
	root, rootKey := aiaCert(t, "Cached Root", true, nil, nil)
	inter, _ := aiaCert(t, "Cached Intermediate", true, root, rootKey, "http://ca.example/root.crt")

	f := newStubFetcher() // serves nothing: a fetch would fail
	cache := &stubCache{entries: map[string]AIAFetched{
		"http://ca.example/root.crt": {Cert: root, URL: "http://ca.example/root.crt"},
	}}

	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: f, Cache: cache})
	if f.fetched != 0 {
		t.Errorf("a cache hit must not reach the network, %d requests made", f.fetched)
	}
	if len(got.Fetched) != 1 || got.Fetched[0].Source != AIASourceCached {
		t.Fatalf("expected one cached certificate, got %+v", got.Fetched)
	}
}

// TestChaseAIA_IgnoresTamperedCacheEntry: the cache stores bytes, never a
// verdict, so a corrupted entry is refetched rather than trusted.
func TestChaseAIA_IgnoresTamperedCacheEntry(t *testing.T) {
	root, rootKey := aiaCert(t, "Tamper Root", true, nil, nil)
	unrelated, _ := aiaCert(t, "Unrelated", true, nil, nil)
	inter, _ := aiaCert(t, "Tamper Intermediate", true, root, rootKey, "http://ca.example/root.crt")

	f := newStubFetcher()
	f.serve("http://ca.example/root.crt", root)
	cache := &stubCache{entries: map[string]AIAFetched{
		"http://ca.example/root.crt": {Cert: unrelated, URL: "http://ca.example/root.crt"},
	}}

	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: f, Cache: cache})
	if f.fetched != 1 {
		t.Error("a cache entry that does not verify must be refetched")
	}
	if len(got.Fetched) != 1 || !got.Fetched[0].Cert.Equal(root) {
		t.Errorf("expected the real issuer, got %+v", got.Fetched)
	}
}

type stubCache struct {
	entries map[string]AIAFetched
	puts    int
}

func (c *stubCache) Get(url string) (AIAFetched, bool) {
	f, ok := c.entries[url]
	return f, ok
}

func (c *stubCache) Put(f AIAFetched) error {
	c.puts++
	if c.entries == nil {
		c.entries = map[string]AIAFetched{}
	}
	c.entries[f.URL] = f
	return nil
}

// TestNoRealAIAFetchGuard: the production fetcher must never run in a test.
// This is the M29 NoRealReads lesson applied to the network.
func TestNoRealAIAFetchGuard(t *testing.T) {
	if _, ok := DefaultAIAFetcher.(httpAIAFetcher); !ok {
		t.Fatal("DefaultAIAFetcher was replaced globally; a test would leak into others")
	}

	root, rootKey := aiaCert(t, "Guard Root", true, nil, nil)
	inter, _ := aiaCert(t, "Guard Intermediate", true, root, rootKey, "http://127.0.0.1:1/root.crt")

	guard := &guardFetcher{t: t}
	got := ChaseAIA([]*x509.Certificate{inter}, AIAOptions{Fetcher: guard})
	if len(got.Failures) != 1 {
		t.Errorf("expected the refusal to be recorded, got %+v", got.Failures)
	}
}

type guardFetcher struct{ t *testing.T }

func (g *guardFetcher) Fetch(context.Context, string) ([]*x509.Certificate, error) {
	return nil, errors.New("network access refused in tests")
}

func TestParseAIAPayload_Formats(t *testing.T) {
	root, _ := aiaCert(t, "Payload Root", true, nil, nil)

	certs, err := ParseAIAPayload(root.Raw)
	if err != nil || len(certs) != 1 {
		t.Errorf("bare DER must parse: %v %d", err, len(certs))
	}

	if _, err := ParseAIAPayload([]byte("not a certificate at all")); err == nil {
		t.Error("garbage must be an error, not an empty success")
	}
}

// chainCertWithAIA issues a certificate carrying CA Issuers URLs.
func chainCertWithAIA(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, urls []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: urls,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
