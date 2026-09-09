package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

// detailFor builds the detail of one certificate in a store, through the same
// options the lister uses.
func detailFor(t *testing.T, store *certlib.CertStore, cn string) string {
	t.Helper()
	initStyles()

	opts := output.OutputOptions{}
	relations := certlib.DetectRelations(store)
	store.Relations = relations
	opts.RelationIndex = certlib.BuildRelationIndex(relations, store)
	alts := certlib.AssembleChainAlternatives(opts.RelationIndex, store)
	opts.Chains = certlib.FirstChains(alts)
	opts.ChainsContaining = certlib.ChainsContaining(alts)
	opts.Store = store

	nodes := ConvertStore(store, opts, "")
	structured := output.BuildStructuredOutput(containersOf(store), opts)

	for i := range nodes {
		if nodes[i].Item != nil && nodes[i].Item.Certificate != nil &&
			nodes[i].Item.Certificate.Subject.CommonName == cn {
			d := newDetailModel(nodes[i], structured, store, opts, 120, 40)
			var sb strings.Builder
			for _, l := range d.contentLines {
				sb.WriteString(l.text)
				sb.WriteString("\n")
			}
			return sb.String()
		}
	}
	t.Fatalf("certificate %q not found", cn)
	return ""
}

func containersOf(store *certlib.CertStore) []*certlib.CertContainer {
	out := make([]*certlib.CertContainer, 0, len(store.Containers))
	for i := range store.Containers {
		out = append(out, &store.Containers[i])
	}
	return out
}

func storeOf(t *testing.T, certs ...*x509.Certificate) *certlib.CertStore {
	t.Helper()
	store := certlib.NewCertStore()
	c := certlib.CertContainer{FilePath: "/tmp/chain.pem", Format: certlib.FormatPEM, Source: certlib.SourceFile}
	for _, cert := range certs {
		c.Items = append(c.Items, certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)
	return store
}

func countChainLines(detail string) int {
	n := 0
	for _, line := range strings.Split(detail, "\n") {
		if strings.Contains(line, "chain: ") {
			n++
		}
	}
	return n
}

// TestDetail_IntermediateShowsChains: before M30a part III an intermediate had
// no chain line, though it sits on every chain beneath it.
func TestDetail_IntermediateShowsChains(t *testing.T) {
	root, rootKey := tuiChainCert(t, "Det Root", true, nil, nil)
	inter, interKey := tuiChainCert(t, "Det Intermediate", true, root, rootKey)
	leafA, _ := tuiChainCert(t, "a.example", false, inter, interKey)
	leafB, _ := tuiChainCert(t, "b.example", false, inter, interKey)

	got := detailFor(t, storeOf(t, root, inter, leafA, leafB), "Det Intermediate")

	if n := countChainLines(got); n != 2 {
		t.Errorf("the intermediate is on two chains, saw %d chain lines:\n%s", n, got)
	}
	if !strings.Contains(got, "Det Root") {
		t.Errorf("the chain line must run up to the root:\n%s", got)
	}
}

// TestDetail_LeafUnchanged guards the existing behaviour: one chain, as before.
func TestDetail_LeafUnchanged(t *testing.T) {
	root, rootKey := tuiChainCert(t, "Leaf Root", true, nil, nil)
	inter, interKey := tuiChainCert(t, "Leaf Intermediate", true, root, rootKey)
	leaf, _ := tuiChainCert(t, "only.example", false, inter, interKey)

	got := detailFor(t, storeOf(t, root, inter, leaf), "only.example")
	if n := countChainLines(got); n != 1 {
		t.Errorf("a leaf has exactly one chain, saw %d:\n%s", n, got)
	}
}

// TestDetail_ChainCapFivePlus: a CA that issued many leaves must not turn its
// detail into a wall; issuer_of below already enumerates them.
func TestDetail_ChainCapFivePlus(t *testing.T) {
	root, rootKey := tuiChainCert(t, "Busy Root", true, nil, nil)
	inter, interKey := tuiChainCert(t, "Busy Intermediate", true, root, rootKey)

	certs := []*x509.Certificate{root, inter}
	for _, cn := range []string{"l1.example", "l2.example", "l3.example", "l4.example", "l5.example", "l6.example", "l7.example"} {
		leaf, _ := tuiChainCert(t, cn, false, inter, interKey)
		certs = append(certs, leaf)
	}

	got := detailFor(t, storeOf(t, certs...), "Busy Intermediate")
	if n := countChainLines(got); n != 5 {
		t.Errorf("expected the cap of 5 chain lines, saw %d:\n%s", n, got)
	}
	if !strings.Contains(got, "5+ chains") {
		t.Errorf("the detail must say how many were elided:\n%s", got)
	}
}

// TestDetail_RootShowsItsChains: the root is on every chain below it too.
func TestDetail_RootShowsItsChains(t *testing.T) {
	root, rootKey := tuiChainCert(t, "Anchor Root", true, nil, nil)
	inter, interKey := tuiChainCert(t, "Anchor Intermediate", true, root, rootKey)
	leaf, _ := tuiChainCert(t, "x.example", false, inter, interKey)

	got := detailFor(t, storeOf(t, root, inter, leaf), "Anchor Root")
	if countChainLines(got) == 0 {
		t.Errorf("a root must show the chains it anchors:\n%s", got)
	}
}

// tuiChainCert issues a certificate, self-signed when parent is nil.
func tuiChainCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
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
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: isCA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
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
