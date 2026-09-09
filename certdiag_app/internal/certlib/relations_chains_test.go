package certlib

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
)

// Chains for every member, and more than one path when the graph has one.

func chainStore(t *testing.T, certs ...*x509.Certificate) (*CertStore, RelationIndex) {
	t.Helper()
	store := NewCertStore()
	c := CertContainer{FilePath: "/tmp/chain.pem", Format: FormatPEM, Source: SourceFile}
	for _, cert := range certs {
		c.Items = append(c.Items, CertItem{Type: ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)
	rels := DetectRelations(store)
	return store, BuildRelationIndex(rels, store)
}

func refOf(store *CertStore, cn string) ItemRef {
	for ci, c := range store.Containers {
		for ii, item := range c.Items {
			if item.Certificate != nil && item.Certificate.Subject.CommonName == cn {
				return ItemRef{ContainerIdx: ci, ItemIdx: ii, FilePath: c.FilePath, Alias: item.Alias}
			}
		}
	}
	return ItemRef{ContainerIdx: -1}
}

// TestChainsContaining_IntermediateListsAllLeaves: an intermediate had no chain
// line at all before, though it is on every chain beneath it.
func TestChainsContaining_IntermediateListsAllLeaves(t *testing.T) {
	root, rootKey := chainCert(t, "CC Root", true, nil, nil)
	inter, interKey := chainCert(t, "CC Intermediate", true, root, rootKey)
	leaf1, _ := chainCert(t, "one.example", false, inter, interKey)
	leaf2, _ := chainCert(t, "two.example", false, inter, interKey)
	leaf3, _ := chainCert(t, "three.example", false, inter, interKey)

	store, index := chainStore(t, root, inter, leaf1, leaf2, leaf3)
	containing := ChainsContaining(AssembleChainAlternatives(index, store))

	if got := len(containing[refOf(store, "CC Intermediate")]); got != 3 {
		t.Errorf("the intermediate is on three chains, got %d", got)
	}
	if got := len(containing[refOf(store, "CC Root")]); got != 3 {
		t.Errorf("the root is on three chains, got %d", got)
	}
	if got := len(containing[refOf(store, "one.example")]); got != 1 {
		t.Errorf("a leaf is on its own chain only, got %d", got)
	}
}

// TestAssembleChains_CrossSignBranches: a CA rolling a new root publishes it
// both self-signed and cross-signed by the old one. Following only the first
// found is what makes a chain line disagree with its own trust verdict.
func TestAssembleChains_CrossSignBranches(t *testing.T) {
	oldRoot, oldKey := chainCert(t, "Old Root", true, nil, nil)
	newRootSelf, newKey := chainCert(t, "New Root", true, nil, nil)
	// The same subject and key, signed by the old root: the cross-signed copy.
	newRootCross := crossSign(t, newRootSelf, newKey, oldRoot, oldKey)
	inter, interKey := chainCert(t, "Issuing CA", true, newRootSelf, newKey)
	leaf, _ := chainCert(t, "leaf.example", false, inter, interKey)

	store, index := chainStore(t, oldRoot, newRootSelf, newRootCross, inter, leaf)
	alts := AssembleChainAlternatives(index, store)

	paths := alts[refOf(store, "leaf.example")]
	if len(paths) < 2 {
		t.Fatalf("expected both the self-signed and the cross-signed path, got %d", len(paths))
	}

	var sawSelfSigned, sawCrossSigned bool
	for _, p := range paths {
		top := p[len(p)-1]
		switch top {
		case refOf(store, "New Root"):
			sawSelfSigned = true
		case refOf(store, "Old Root"):
			sawCrossSigned = true
		}
	}
	if !sawSelfSigned || !sawCrossSigned {
		t.Errorf("expected a path to each root, self=%v cross=%v", sawSelfSigned, sawCrossSigned)
	}
}

// TestAssembleChains_CompatibilityView: callers that want one chain still get
// one, and it is a real path.
func TestAssembleChains_CompatibilityView(t *testing.T) {
	root, rootKey := chainCert(t, "Compat Root", true, nil, nil)
	inter, interKey := chainCert(t, "Compat Intermediate", true, root, rootKey)
	leaf, _ := chainCert(t, "leaf.example", false, inter, interKey)

	store, index := chainStore(t, root, inter, leaf)
	chains := AssembleChains(index, store)

	chain, ok := chains[refOf(store, "leaf.example")]
	if !ok {
		t.Fatal("the leaf must have a chain")
	}
	if len(chain) != 3 {
		t.Fatalf("expected leaf, intermediate, root; got %d entries", len(chain))
	}
	if chain[0] != refOf(store, "leaf.example") || chain[2] != refOf(store, "Compat Root") {
		t.Error("the chain must run from the leaf up to the root")
	}
}

// TestFormatChainLabel_SelfByRef: an intermediate showing a chain must point at
// itself, not at the leaf.
func TestFormatChainLabel_SelfByRef(t *testing.T) {
	root, rootKey := chainCert(t, "Label Root", true, nil, nil)
	inter, interKey := chainCert(t, "Label Intermediate", true, root, rootKey)
	leaf, _ := chainCert(t, "leaf.example", false, inter, interKey)

	store, index := chainStore(t, root, inter, leaf)
	chain := AssembleChains(index, store)[refOf(store, "leaf.example")]

	mark := func(s string) string { return "<" + s + ">" }
	got := FormatChainLabelFor(chain, refOf(store, "Label Intermediate"), store, mark)
	if !strings.Contains(got, "<Label Intermediate>") {
		t.Errorf("the intermediate must be highlighted: %q", got)
	}
	if strings.Contains(got, "<leaf.example>") {
		t.Errorf("only the certificate being viewed is highlighted: %q", got)
	}

	// Issuance order: root first, leaf last.
	if strings.Index(got, "Label Root") > strings.Index(got, "leaf.example") {
		t.Errorf("chains render root first: %q", got)
	}
}

// TestAssembleChains_NoInfiniteLoopOnDuplicates: the same certificate present
// twice must not make a chain circle forever.
func TestAssembleChains_NoInfiniteLoopOnDuplicates(t *testing.T) {
	root, rootKey := chainCert(t, "Dup Root", true, nil, nil)
	inter, interKey := chainCert(t, "Dup Intermediate", true, root, rootKey)
	leaf, _ := chainCert(t, "leaf.example", false, inter, interKey)

	store, index := chainStore(t, root, inter, root, leaf, inter)
	alts := AssembleChainAlternatives(index, store)
	for ref, paths := range alts {
		for _, p := range paths {
			if len(p) > 8 {
				t.Fatalf("%v produced a path of %d entries; loop guard failed", ref, len(p))
			}
		}
	}
}

// crossSign issues a second copy of a root: same subject, same key, signed by
// another CA instead of itself. This is how a CA introduces a new root while
// older clients still chain to the old one.
func crossSign(t *testing.T, self *x509.Certificate, selfKey *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               self.Subject,
		NotBefore:             self.NotBefore,
		NotAfter:              self.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &selfKey.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
