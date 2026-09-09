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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// makeSignedPair returns a CA and a leaf it signed, so the served chain has a
// relation to find.
func makeSignedPair(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Remote Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return ca, leaf
}

func remoteChainModel(t *testing.T) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	ca, leaf := makeSignedPair(t)
	m := RootModel{width: 120, height: 40}
	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{{
			Target:     "example.com:443",
			Connection: &certops.RemoteConnectionInfo{TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"},
			Certs: []certops.RemoteCertInfo{
				{Index: 0, Role: "leaf", Cert: &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
				{Index: 1, Role: "intermediate", Cert: &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: ca, RawBytes: ca.Raw}},
			},
		}},
	}
	m.rebuildRemoteStore()
	return m
}

// TestRemoteDetail_HasFingerprintsAndRelations: the remote detail used to be
// rendered by its own builder with no structured item, so it had neither. It now
// goes through the same detail model a scanned file uses.
func TestRemoteDetail_HasFingerprintsAndRelations(t *testing.T) {
	m := remoteChainModel(t)

	nodes := ConvertStore(m.remoteStore, m.remoteOpts, m.pathDisplay)
	var leafNode *TreeNode
	for i := range nodes {
		if nodes[i].Item != nil && nodes[i].Item.Certificate != nil &&
			nodes[i].Item.Certificate.Subject.CommonName == "leaf.example.com" {
			leafNode = &nodes[i]
		}
	}
	if leafNode == nil {
		t.Fatal("leaf row not found in the remote store")
	}

	m.allNodes = nodes
	m.recomputeVisible()
	m.currentRoot = rootRemoteFetch
	m.remoteHasResult = true
	m.store = m.remoteStore
	m.opts = m.remoteOpts
	m.structured = m.remoteStructured
	m.openDetail(*leafNode)
	if m.detail == nil {
		t.Fatal("no detail model")
	}

	var text strings.Builder
	for _, line := range m.detail.contentLines {
		text.WriteString(line.text)
		text.WriteString("\n")
	}
	got := text.String()

	if !strings.Contains(got, "SHA-256") {
		t.Errorf("a remote certificate detail must carry fingerprints:\n%s", got)
	}
	if !strings.Contains(got, "Relations:") {
		t.Errorf("a remote certificate detail must carry relations:\n%s", got)
	}
	if !strings.Contains(got, "Remote Test CA") {
		t.Errorf("the relation must name the issuer served alongside it:\n%s", got)
	}
}

// TestRemoteNode_ReadOnly: a served chain is not ours to edit, the same guard
// M28 put on trust store rows.
func TestRemoteNode_ReadOnly(t *testing.T) {
	m := remoteChainModel(t)
	nodes := ConvertStore(m.remoteStore, m.remoteOpts, m.pathDisplay)

	var certNode *TreeNode
	for i := range nodes {
		if nodes[i].Item != nil && nodes[i].Item.Certificate != nil {
			certNode = &nodes[i]
			break
		}
	}
	if certNode == nil {
		t.Fatal("no certificate row")
	}
	if !certNode.isReadOnlySource() {
		t.Error("a remote row must be read-only")
	}

	m.allNodes = nodes
	m.recomputeVisible()
	m.state = stateTree
	for i := range m.visible {
		if m.visible[i].Item != nil {
			m.tree.cursor = i
			break
		}
	}

	for _, key := range []tea.KeyMsg{
		{Type: tea.KeyCtrlD},
		{Type: tea.KeyRunes, Runes: []rune{'a'}},
		{Type: tea.KeyRunes, Runes: []rune{'n'}},
	} {
		handled, model, _ := m.trustStoreKey(key, stateTree)
		if !handled {
			t.Errorf("%v on a remote row must be intercepted", key)
			continue
		}
		if got := model.(RootModel); got.statusMessage == "" {
			t.Errorf("%v must explain why nothing happened", key)
		}
	}
}
