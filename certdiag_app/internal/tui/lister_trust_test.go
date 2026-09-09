package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// --- helpers ----------------------------------------------------------------

type listerCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func listerRoot(t *testing.T, cn string) listerCA {
	t.Helper()
	return listerSign(t, listerCA{}, cn, true)
}

func listerSign(t *testing.T, parent listerCA, cn string, isCA bool) listerCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.DNSNames = []string{cn}
	}

	signerCert, signerKey := tmpl, any(key)
	if parent.cert != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return listerCA{cert: cert, key: key}
}

// newListerTestModel builds a RootModel in the Cert Lister with a scanned
// store, a stubbed trust loader and no trust data loaded yet.
func newListerTestModel(t *testing.T, stub *loaderStub, certs ...*x509.Certificate) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	store := certlib.NewCertStore()
	items := make([]certlib.CertItem, 0, len(certs))
	for _, c := range certs {
		items = append(items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Alias:       c.Subject.CommonName,
			Certificate: c,
			RawBytes:    c.Raw,
		})
	}
	store.AddContainer(certlib.CertContainer{
		FilePath: "/scan/chain.pem",
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items:    items,
	})

	m := makeTestRootModel()
	m.currentRoot = rootCertLister
	m.store = store
	m.tuiOpts.TrustStoreLoader = stub.load
	m.tree.activeCols = []string{"subject"}
	m.allNodes = ConvertStore(store, m.opts, m.pathDisplay)
	m.recomputeVisible()
	return m
}

func listerNodeFor(m RootModel, cn string) *TreeNode {
	for i := range m.allNodes {
		if m.allNodes[i].Item != nil && m.allNodes[i].Item.Certificate != nil &&
			m.allNodes[i].Item.Certificate.Subject.CommonName == cn {
			return &m.allNodes[i]
		}
	}
	return nil
}

// --- lazy load --------------------------------------------------------------

// TestListerTrust_NotLoadedUntilAColumnIsOn is the whole point of the lazy
// path: a plain browse must never pay for reading the OS trust store.
func TestListerTrust_NotLoadedUntilAColumnIsOn(t *testing.T) {
	root := listerRoot(t, "Lazy Root")
	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert),
	}}

	m := newListerTestModel(t, stub, root.cert)

	if cmd := m.ensureListerTrust(); cmd != nil {
		t.Error("no trust column is active, so nothing must be scheduled")
	}
	if stub.calls != 0 {
		t.Errorf("expected no store read, got %d", stub.calls)
	}
	if m.trustIndex != nil {
		t.Error("expected no trust index before a column is enabled")
	}
}

func TestListerTrust_ColumnTriggersLoad(t *testing.T) {
	for _, col := range []string{colIDTrust, colIDStores} {
		t.Run(col, func(t *testing.T) {
			root := listerRoot(t, "Trigger Root")
			stub := &loaderStub{stores: []truststore.StoreContents{
				tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert),
			}}

			m := newListerTestModel(t, stub, root.cert)
			m.tree.activeCols = []string{"subject", col}

			cmd := m.ensureListerTrust()
			if cmd == nil {
				t.Fatal("expected a load command once a trust column is active")
			}
			// The command carries the actual read; running it is what a
			// Bubble Tea runtime would do.
			drainCmd(t, cmd)
			if stub.calls != 1 {
				t.Errorf("expected exactly one store read, got %d", stub.calls)
			}
		})
	}
}

// drainCmd runs a tea.Cmd (including a Batch) and returns the messages.
func drainCmd(t *testing.T, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range batch {
			out = append(out, drainCmd(t, c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func TestListerTrust_LoadsOnlyOnce(t *testing.T) {
	root := listerRoot(t, "Once Root")
	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert),
	}}

	m := newListerTestModel(t, stub, root.cert)
	m.tree.activeCols = []string{colIDTrust}

	drainCmd(t, m.ensureListerTrust())
	for _, msg := range drainCmd(t, m.listerTrustLoadCmd()) {
		if lm, ok := msg.(ListerTrustLoadedMsg); ok {
			updated, _ := m.handleListerTrustLoaded(lm)
			m = updated.(RootModel)
		}
	}

	before := stub.calls
	// Switching the second column on must reuse what is already loaded.
	m.tree.activeCols = []string{colIDTrust, colIDStores}
	if cmd := m.ensureListerTrust(); cmd != nil {
		drainCmd(t, cmd)
	}
	if stub.calls != before {
		t.Errorf("expected no second store read, got %d then %d", before, stub.calls)
	}
}

func TestListerTrust_CachedStoresSkipTheCommand(t *testing.T) {
	root := listerRoot(t, "Cached Root")
	stub := &loaderStub{}

	m := newListerTestModel(t, stub, root.cert)
	m.tree.activeCols = []string{colIDTrust}
	// Stores already in hand, e.g. from a visit to the Trust Stores view.
	m.trustStores = []truststore.StoreContents{tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert)}

	if cmd := m.ensureListerTrust(); cmd != nil {
		t.Error("expected cached stores to be applied without a new read")
	}
	if stub.calls != 0 {
		t.Errorf("expected no loader call, got %d", stub.calls)
	}
	if m.trustIndex == nil {
		t.Fatal("expected the cached stores to produce a trust index")
	}
}

func TestListerTrust_NotInStoreView(t *testing.T) {
	root := listerRoot(t, "StoreView Root")
	stub := &loaderStub{}

	m := newListerTestModel(t, stub, root.cert)
	m.currentRoot = rootTrustStore
	m.tree.activeCols = []string{colIDTrust}

	if cmd := m.ensureListerTrust(); cmd != nil {
		t.Error("the trust store view has its own load path; the lister one must stay out")
	}
}

// --- applying the result ----------------------------------------------------

func TestListerTrust_PopulatesNodes(t *testing.T) {
	root := listerRoot(t, "Populate Root")
	leaf := listerSign(t, root, "leaf.populate.test", false)

	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("macOS Roots", truststore.StoreTypeOS, "/kc", root.cert),
		tsStore("Java 21", truststore.StoreTypeJava, "/jdk", root.cert),
	}}

	m := newListerTestModel(t, stub, leaf.cert, root.cert)
	m.tree.activeCols = []string{"subject", colIDTrust, colIDStores}
	m.trustStores = stub.stores
	m.applyListerTrust()

	rootNode := listerNodeFor(m, "Populate Root")
	if rootNode == nil {
		t.Fatal("expected the root node")
	}
	if rootNode.Trust != truststore.VerdictAnchor.Display() {
		t.Errorf("a root in the OS store must read ANCHOR, got %q", rootNode.Trust)
	}
	if len(rootNode.Stores) != 2 {
		t.Errorf("expected tags for both stores holding it, got %v", rootNode.Stores)
	}

	leafNode := listerNodeFor(m, "leaf.populate.test")
	if leafNode == nil {
		t.Fatal("expected the leaf node")
	}
	if leafNode.Trust != truststore.VerdictTrusted.Display() {
		t.Errorf("a leaf chaining to a store root must read TRUSTED, got %q", leafNode.Trust)
	}
	if len(leafNode.Stores) != 0 {
		t.Errorf("the leaf is in no store, so it must have no tags, got %v", leafNode.Stores)
	}
	if len(leafNode.TrustPolicies) == 0 || !strings.Contains(leafNode.TrustPolicies[0], "Anchor:") {
		t.Errorf("expected the anchor in the detail lines, got %v", leafNode.TrustPolicies)
	}
}

func TestListerTrust_SearchableIncludesVerdict(t *testing.T) {
	root := listerRoot(t, "Search Root")
	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert),
	}}

	m := newListerTestModel(t, stub, root.cert)
	m.trustStores = stub.stores
	m.applyListerTrust()

	node := listerNodeFor(m, "Search Root")
	if node == nil {
		t.Fatal("expected the node")
	}
	if !strings.Contains(node.Searchable, "anchor") {
		t.Errorf("the verdict must be searchable, got %q", node.Searchable)
	}
}

// TestListerTrust_RebuildsChains: after the load, the relation graph reaches
// the store root, which is the visible payoff of the anchor container.
func TestListerTrust_RebuildsChains(t *testing.T) {
	root := listerRoot(t, "Chain Root")
	inter := listerSign(t, root, "Chain Intermediate", true)
	leaf := listerSign(t, inter, "leaf.chain.test", false)

	stub := &loaderStub{stores: []truststore.StoreContents{
		tsStore("OS", truststore.StoreTypeOS, "/kc", root.cert),
	}}

	m := newListerTestModel(t, stub, leaf.cert, inter.cert)

	before := len(m.store.Containers)
	m.trustStores = stub.stores
	m.applyListerTrust()

	if len(m.store.Containers) != before+1 {
		t.Fatalf("expected the anchor container to be added, got %d containers", len(m.store.Containers))
	}
	added := m.store.Containers[len(m.store.Containers)-1]
	if !added.RelationsOnly {
		t.Error("the injected container must be RelationsOnly so it never renders")
	}

	// The injected anchor must not become a visible row.
	for _, n := range m.allNodes {
		if n.Container != nil && n.Container.RelationsOnly {
			t.Error("a RelationsOnly container must not produce tree rows")
		}
	}

	leafRef := certlib.ItemRef{
		ContainerIdx: 0, ItemIdx: 0,
		FilePath: "/scan/chain.pem", Alias: leaf.cert.Subject.CommonName,
	}
	if got := len(m.opts.Chains[leafRef]); got != 3 {
		t.Errorf("expected the chain to reach the store root (3 links), got %d", got)
	}
}

func TestListerTrust_LoadFailureNotifies(t *testing.T) {
	root := listerRoot(t, "Failure Root")
	stub := &loaderStub{err: errors.New("keychain unreadable")}

	m := newListerTestModel(t, stub, root.cert)
	m.tree.activeCols = []string{colIDTrust}

	updated, _ := m.handleListerTrustLoaded(ListerTrustLoadedMsg{Err: stub.err})
	got := updated.(RootModel)

	// notify(notifyError) surfaces through the popup rather than a command.
	if got.popup.kind != popupError {
		t.Error("a failed load must surface to the user, not fail silently")
	}
	if !strings.Contains(got.popup.message, "keychain unreadable") {
		t.Errorf("the notification must carry the cause, got %q", got.popup.message)
	}
	if got.trustIndex != nil {
		t.Error("a failed load must not leave a partial index")
	}
	// The tree must still be usable.
	if len(got.allNodes) == 0 {
		t.Error("a failed trust load must not empty the tree")
	}
}

func TestListerTrust_ApplyWithNoStores(t *testing.T) {
	root := listerRoot(t, "Empty Root")
	m := newListerTestModel(t, &loaderStub{}, root.cert)

	m.trustStores = nil
	m.applyListerTrust()

	// No stores means no anchors, but the index still exists so the column
	// renders a verdict rather than staying blank.
	if m.trustIndex == nil {
		t.Fatal("expected an index even with no stores")
	}
	node := listerNodeFor(m, "Empty Root")
	if node == nil || node.Trust != truststore.VerdictUntrusted.Display() {
		t.Errorf("expected UNTRUSTED with no stores, got %+v", node)
	}
}

func TestTrustColumnsActive(t *testing.T) {
	cases := []struct {
		cols []string
		want bool
	}{
		{nil, false},
		{[]string{"subject", "issuer"}, false},
		{[]string{colIDTrust}, true},
		{[]string{colIDStores}, true},
		{[]string{"subject", colIDStores, "expiry"}, true},
	}
	for _, tc := range cases {
		if got := trustColumnsActive(tc.cols); got != tc.want {
			t.Errorf("%v: expected %v, got %v", tc.cols, tc.want, got)
		}
	}
}

// --- store view vocabulary --------------------------------------------------

// TestStoreView_UsesVerdictVocabulary pins the M28 display change M29 made on
// purpose, so it is not reverted by accident.
func TestStoreView_UsesVerdictVocabulary(t *testing.T) {
	denied := tsCert(t, "Denied Store Root")
	plain := tsCert(t, "Plain Store Root")

	sc := tsStore("macOS System Roots", truststore.StoreTypeOS, "/kc", denied, plain)
	sc.TrustMap = map[string]truststore.CertTrust{
		truststore.CertFingerprint(denied): {Overall: truststore.TrustDenied},
	}

	m := newStoreTestModel(t, sc)

	var seen int
	for i := range m.visible {
		n := &m.visible[i]
		if n.Item == nil || n.Item.Certificate == nil {
			continue
		}
		seen++
		switch n.Item.Certificate.Subject.CommonName {
		case "Denied Store Root":
			if n.Trust != truststore.VerdictDenied.Display() {
				t.Errorf("expected DENIED, got %q", n.Trust)
			}
		case "Plain Store Root":
			// In the store view everything shown is in a store, so the
			// baseline is ANCHOR rather than the uninformative UNSET.
			if n.Trust != truststore.VerdictAnchor.Display() {
				t.Errorf("expected ANCHOR, got %q", n.Trust)
			}
		}
		if truststore.ParseTrustVerdict(n.Trust) == truststore.VerdictUnknown {
			t.Errorf("%q is not part of the verdict vocabulary", n.Trust)
		}
	}
	if seen != 2 {
		t.Fatalf("expected both certificates, saw %d", seen)
	}
}
