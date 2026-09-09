package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func tsCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return tsCertValid(t, cn, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

func tsCertValid(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func tsStore(name string, typ truststore.StoreType, path string, certs ...*x509.Certificate) truststore.StoreContents {
	return truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:      typ,
			Name:      name,
			Path:      path,
			CertCount: len(certs),
		},
		Certificates: certs,
	}
}

// loaderStub counts calls so tests can assert what does and does not re-read.
type loaderStub struct {
	calls  int
	stores []truststore.StoreContents
	err    error
}

func (s *loaderStub) load(certops.StoreLoadAllOptions) (*certops.StoreLoadAllResult, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &certops.StoreLoadAllResult{Stores: s.stores}, nil
}

// newStoreTestModel builds a RootModel already in the trust store view with the
// given stores loaded, without touching the real machine.
// newStoreTestModel returns a trust store model with every store unfolded, which
// is what a test inspecting rows, columns or verdicts wants. Trust stores start
// folded in production (M30a part I); the helper that keeps that default is
// newStoreTestModelWithLoader, and TestTrustStoreView_StartsCollapsed asserts it.
func newStoreTestModel(t *testing.T, stores ...truststore.StoreContents) RootModel {
	t.Helper()
	m, _ := newStoreTestModelWithLoader(t, stores...)
	m.expandAll(true)
	return m
}

func newStoreTestModelWithLoader(t *testing.T, stores ...truststore.StoreContents) (RootModel, *loaderStub) {
	t.Helper()
	initStyles()
	initFormStyles()

	stub := &loaderStub{stores: stores}

	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.storeGrouping = certops.GroupByInstance
	m.storeCols = defaultStoreCols()
	m.trustStores = stores
	m.tuiOpts.TrustStoreLoader = stub.load
	m.rebuildTrustStoreTree()

	return m, stub
}

// nodeByFilename finds a visible row by its first-column text.
func nodeByFilename(m RootModel, name string) *TreeNode {
	for i := range m.visible {
		if m.visible[i].Filename == name {
			return &m.visible[i]
		}
	}
	return nil
}

// cursorTo positions the cursor on the first row whose first column matches,
// unfolding the tree first so a folded-away child is still reachable.
func cursorTo(t *testing.T, m *RootModel, name string) {
	t.Helper()
	for i := range m.visible {
		if m.visible[i].Filename == name {
			m.tree.cursor = i
			return
		}
	}
	m.expandAll(true)
	for i := range m.visible {
		if m.visible[i].Filename == name {
			m.tree.cursor = i
			return
		}
	}
	t.Fatalf("row %q not found in %d visible rows", name, len(m.visible))
}
