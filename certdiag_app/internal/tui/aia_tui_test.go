package tui

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// AIA reaches the network, so it never happens on its own. These tests pin that
// it happens only on A, that the wait says how to avoid repeating it, and that
// what comes back becomes ordinary rows.

func aiaTestModel(t *testing.T, certs ...*x509.Certificate) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	store := certlib.NewCertStore()
	c := certlib.CertContainer{FilePath: "/tmp/chain.pem", Format: certlib.FormatPEM, Source: certlib.SourceFile}
	for _, cert := range certs {
		c.Items = append(c.Items, certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)

	m := makeTestRootModel()
	m.width, m.height = 120, 40
	m.store = store
	m.opts = output.OutputOptions{Store: store}
	m.allNodes = ConvertStore(store, m.opts, m.pathDisplay)
	m.recomputeVisible()
	m.state = stateTree
	return m
}

// TestAIA_LoadingHintOffersTheCache: the moment the user is waiting is when
// telling them the wait is avoidable is useful.
func TestAIA_LoadingHintOffersTheCache(t *testing.T) {
	_, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)

	m.startAIAFetch()
	if m.state != stateLoading {
		t.Fatalf("expected the loading state, got %d", m.state)
	}
	if !strings.Contains(m.loadingMessage, "AIA") {
		t.Errorf("the wait must say what it is waiting for: %q", m.loadingMessage)
	}
	if !strings.Contains(m.loadingMessage, "defaults.aia.cache") {
		t.Errorf("with no cache configured the wait must say it can be avoided: %q", m.loadingMessage)
	}
}

func TestAIA_LoadingHintQuietWhenCached(t *testing.T) {
	_, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)
	m.aiaCache = &noopAIACache{}

	m.startAIAFetch()
	if strings.Contains(m.loadingMessage, "defaults.aia.cache") {
		t.Errorf("the hint is pointless once caching is on: %q", m.loadingMessage)
	}
}

func TestAIA_NothingToFetchExplains(t *testing.T) {
	m := aiaTestModel(t)
	m.startAIAFetch()
	if m.state == stateLoading {
		t.Error("an empty scan must not start a fetch")
	}
}

// TestAIA_FetchedCertificatesBecomeRows: a fetched issuer is an ordinary row,
// which is what lets the user inspect it, see its relations and save it.
func TestAIA_FetchedCertificatesBecomeRows(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)
	before := len(m.visible)

	model, _ := m.handleAIAFetched(AIAFetchedMsg{Result: certlib.AIAResult{
		Fetched: []certlib.AIAFetched{{Cert: ca, URL: "http://ca.example/ca.crt", For: leaf}},
	}})
	got := model.(RootModel)

	if len(got.visible) <= before {
		t.Errorf("the fetched certificate must appear as a row: %d -> %d", before, len(got.visible))
	}
	if got.state != stateTree {
		t.Errorf("expected to return to the tree, got state %d", got.state)
	}

	var found bool
	for _, n := range got.allNodes {
		if n.Container != nil && n.Container.Source == certlib.SourceAIA {
			found = true
		}
	}
	if !found {
		t.Error("fetched certificates must live in a SourceAIA container")
	}
}

// TestAIA_FetchedRowsCarryRelations: the point of adding them as rows is that
// the chain now completes visibly.
func TestAIA_FetchedRowsCarryRelations(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)

	model, _ := m.handleAIAFetched(AIAFetchedMsg{Result: certlib.AIAResult{
		Fetched: []certlib.AIAFetched{{Cert: ca, URL: "http://ca.example/ca.crt", For: leaf}},
	}})
	got := model.(RootModel)

	if len(got.opts.RelationIndex) == 0 {
		t.Error("relations must be recomputed with the fetched certificate in hand")
	}
	if len(got.opts.Chains) == 0 {
		t.Error("the chain must complete once the issuer is present")
	}
}

// TestAIA_FailuresAreReported: a CA whose server is down is worth saying.
func TestAIA_FailuresAreReported(t *testing.T) {
	_, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)

	model, _ := m.handleAIAFetched(AIAFetchedMsg{Result: certlib.AIAResult{
		Failures: []certlib.AIAFailure{{URL: "http://ca.example/down.crt", Reason: "http 503"}},
	}})
	got := model.(RootModel)
	// Failures are raised as a popup, not a transient status line.
	if !strings.Contains(got.popup.message, "failed") {
		t.Errorf("a failed fetch must say so, got %q", got.popup.message)
	}
}

func TestAIA_NoURLsIsSaidPlainly(t *testing.T) {
	_, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)

	model, _ := m.handleAIAFetched(AIAFetchedMsg{Result: certlib.AIAResult{}})
	if got := model.(RootModel); !strings.Contains(got.statusMessage, "No AIA URLs") {
		t.Errorf("expected a plain explanation, got %q", got.statusMessage)
	}
}

func TestAIA_HintBarAdvertisesTheKey(t *testing.T) {
	_, leaf := makeSignedPair(t)
	m := aiaTestModel(t, leaf)
	hints, _ := m.treeFooterHints()
	if !hintsContain(hints, "A") {
		t.Error("the lister must advertise A")
	}
}

type noopAIACache struct{}

func (noopAIACache) Get(string) (certlib.AIAFetched, bool) { return certlib.AIAFetched{}, false }
func (noopAIACache) Put(certlib.AIAFetched) error          { return nil }

// AIA from the remote side: a server that does not send its full chain is the
// case AIA exists for, so the option belongs on the fetch form, and the result
// tree keeps the same A key the lister has.

// TestRemoteResult_FetchedIssuersBecomeRows: the completed chain has to be
// visible, not an invisible aid to the verdict.
func TestRemoteResult_FetchedIssuersBecomeRows(t *testing.T) {
	ca, leaf := makeSignedPair(t)

	m := makeTestRootModel()
	m.width, m.height = 120, 40
	m.remoteResult = &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
		remoteTargetResult("example.com:443", []string{"leaf"}, []*x509.Certificate{leaf}),
	}}
	m.remoteHasResult = true
	m.currentRoot = rootRemoteFetch
	m.remoteAIA = &certlib.AIAResult{Fetched: []certlib.AIAFetched{
		{Cert: ca, URL: "http://ca.example/ca.crt", For: leaf},
	}}
	m.rebuildRemoteTree()

	var sawAIA bool
	for _, n := range m.allNodes {
		if n.Container != nil && n.Container.Source == certlib.SourceAIA {
			sawAIA = true
		}
	}
	if !sawAIA {
		t.Error("an issuer fetched for a remote chain must appear as a row")
	}
	if len(m.opts.Chains) == 0 {
		t.Error("with the issuer present the served chain must complete")
	}
}

// TestRemoteResult_AKeyStillFetches: the remote result is the shared tree, so
// the lister's key works there too, and the remote-only marks survive it.
func TestRemoteResult_AKeyStillFetches(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	stranger, _ := makeSignedPair(t)
	m := remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate"}, []*x509.Certificate{leaf, stranger}))

	handled, _, _ := m.remoteKey(runes("A"), stateTree)
	if handled {
		t.Fatal("A must fall through to the shared handler, not be intercepted")
	}

	model, _ := m.handleAIAFetched(AIAFetchedMsg{Result: certlib.AIAResult{
		Fetched: []certlib.AIAFetched{{Cert: ca, URL: "http://ca.example/ca.crt", For: leaf}},
	}})
	got := model.(RootModel)

	var marked bool
	for _, n := range got.visible {
		for _, w := range n.Warnings {
			if strings.Contains(w, "not in chain") {
				marked = true
			}
		}
	}
	if !marked {
		t.Error("the stranger the server sent is still not in the chain; the mark must survive the fetch")
	}
	if got.remoteAIA == nil {
		t.Error("the fetched issuers must be remembered so a rebuild keeps them")
	}
}

// TestRemoteTree_HintBarShowsFetchAIA: a key that works but is not advertised
// may as well not exist.
func TestRemoteTree_HintBarShowsFetchAIA(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	m := remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate"}, []*x509.Certificate{leaf, ca}))

	hints, _ := m.treeFooterHints()
	if !hintsContain(hints, "A") {
		t.Error("the remote result bar must advertise A")
	}

	m.width = 400 // wide enough that nothing is elided
	m.detail = newDetailModel(m.visible[1], m.structured, m.store, m.opts, m.width, m.height)
	m.state = stateSplit
	bar, _ := m.splitInfoBar()
	if !strings.Contains(bar, "Fetch AIA") {
		t.Errorf("the split view over a remote result must advertise A too:\n%s", bar)
	}
	// The lister's write actions are all refused on a served chain.
	for _, label := range []string{"Multi-select", "Delete", "Actions"} {
		if strings.Contains(bar, label) {
			t.Errorf("the split bar over a remote result must not offer %q:\n%s", label, bar)
		}
	}
}

// TestAIA_NotOfferedForTrustStores: a trust store is the answer, not a chain
// with something missing, so chasing from its certificates makes no sense.
func TestAIA_NotOfferedForTrustStores(t *testing.T) {
	m := newStoreTestModel(t, tsStore("OS Trust Store", truststore.StoreTypeOS, "/os", tsCert(t, "Root A")))
	m.width, m.height = 120, 40

	cmd := m.startAIAFetch()
	if m.state == stateLoading {
		t.Error("AIA must not run over a trust store")
	}
	if cmd == nil && m.statusMessage == "" {
		t.Error("the refusal must be explained")
	}

	hints, _ := m.treeFooterHints()
	if hintsContain(hints, "A") {
		t.Error("the trust store bar must not advertise a key that refuses")
	}
}
