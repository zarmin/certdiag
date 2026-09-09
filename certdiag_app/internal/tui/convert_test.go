package tui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

func makeContainer(format certlib.FileFormat, path string, items []certlib.CertItem) certlib.CertContainer {
	return certlib.CertContainer{
		FilePath: path,
		Format:   format,
		Items:    items,
	}
}

func makeStore(containers ...certlib.CertContainer) *certlib.CertStore {
	s := certlib.NewCertStore()
	for _, c := range containers {
		s.AddContainer(c)
	}
	return s
}

func TestConvertStore_SingleEntryJKS_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatJKS, "/tmp/keystore.jks", []certlib.CertItem{
		{Type: certlib.ContentCertificate, Alias: "myalias"},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (header + child), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected JKS header to be a bundle")
	}
	if nodes[0].Filename != "keystore.jks" {
		t.Fatalf("expected header filename 'keystore.jks', got %q", nodes[0].Filename)
	}
	if !nodes[1].IsChild {
		t.Fatal("expected second node to be a child")
	}
	if nodes[1].Filename != "myalias" {
		t.Fatalf("expected child filename 'myalias', got %q", nodes[1].Filename)
	}
}

func TestConvertStore_SingleEntryPKCS12_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatPKCS12, "/tmp/cert.p12", []certlib.CertItem{
		{Type: certlib.ContentCertificate},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (header + child), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected PKCS12 header to be a bundle")
	}
	if nodes[0].Filename != "cert.p12" {
		t.Fatalf("expected header filename 'cert.p12', got %q", nodes[0].Filename)
	}
}

func TestConvertStore_SingleEntryPKCS7_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatPKCS7, "/tmp/certs.p7b", []certlib.CertItem{
		{Type: certlib.ContentCertificate},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (header + child), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected PKCS7 header to be a bundle")
	}
}

func TestConvertStore_SingleEntryPEM_NotBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatPEM, "/tmp/cert.pem", []certlib.CertItem{
		{Type: certlib.ContentCertificate},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (flat), got %d", len(nodes))
	}
	if nodes[0].IsBundle {
		t.Fatal("expected PEM single entry to NOT be a bundle")
	}
	if nodes[0].IsChild {
		t.Fatal("expected PEM single entry to NOT be a child")
	}
}

func TestConvertStore_SingleEntryDER_NotBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatDER, "/tmp/cert.der", []certlib.CertItem{
		{Type: certlib.ContentCertificate},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (flat), got %d", len(nodes))
	}
	if nodes[0].IsBundle {
		t.Fatal("expected DER single entry to NOT be a bundle")
	}
}

func TestConvertStore_MultiEntryJKS_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatJKS, "/tmp/multi.jks", []certlib.CertItem{
		{Type: certlib.ContentCertificate, Alias: "cert1"},
		{Type: certlib.ContentPrivateKey, Alias: "key1"},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes (header + 2 children), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected multi-entry JKS to be a bundle")
	}
	if nodes[0].ChildCount != 2 {
		t.Fatalf("expected ChildCount=2, got %d", nodes[0].ChildCount)
	}
}

func TestConvertStore_MultiEntryPEM_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatPEM, "/tmp/chain.pem", []certlib.CertItem{
		{Type: certlib.ContentCertificate},
		{Type: certlib.ContentCertificate},
	}))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes (header + 2 children), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected multi-entry PEM to be a bundle")
	}
}

func TestConvertStore_EmptyBundleFormat_IsBundle(t *testing.T) {
	store := makeStore(makeContainer(certlib.FormatJKS, "/tmp/empty.jks", nil))
	nodes := ConvertStore(store, output.OutputOptions{}, "basename")

	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (empty bundle header), got %d", len(nodes))
	}
	if !nodes[0].IsBundle {
		t.Fatal("expected empty JKS to be a bundle")
	}
	if nodes[0].ChildCount != 0 {
		t.Fatalf("expected ChildCount=0, got %d", nodes[0].ChildCount)
	}
}

func testGenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func testCSR(t *testing.T, key interface{}, cn string) *x509.CertificateRequest {
	t.Helper()
	csr, _, err := certlib.CreateCSR(key, certlib.CertGenOptions{
		Subject: pkix.Name{CommonName: cn},
		SANs:    certlib.SANList{DNSNames: []string{cn}},
	})
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return csr
}

func testSelfSignedCert(t *testing.T, key interface{}) *x509.Certificate {
	t.Helper()
	cert, _, err := certlib.CreateSelfSignedCert(key, certlib.CertGenOptions{
		Subject: pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		IsCA:    true,
		Days:    365,
	})
	if err != nil {
		t.Fatalf("create self-signed cert: %v", err)
	}
	return cert
}

func TestConvertStore_KeyCSRRelation(t *testing.T) {
	key := testGenRSAKey(t)
	csr := testCSR(t, key, "test.example.com")

	store := makeStore(
		makeContainer(certlib.FormatPEM, "/tmp/test.key", []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, PrivateKey: key},
		}),
		makeContainer(certlib.FormatPEM, "/tmp/test.csr", []certlib.CertItem{
			{Type: certlib.ContentCSR, CSR: csr},
		}),
	)

	relations := certlib.DetectRelations(store)
	index := certlib.BuildRelationIndex(relations, store)
	opts := output.OutputOptions{RelationIndex: index, Store: store}

	nodes := ConvertStore(store, opts, "basename")

	keyNode := nodes[0]
	found := false
	for _, r := range keyNode.Relations {
		if strings.HasPrefix(r, "key-csr:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("key node should have 'key-csr:' relation, got %v", keyNode.Relations)
	}

	csrNode := nodes[1]
	found = false
	for _, r := range csrNode.Relations {
		if strings.HasPrefix(r, "key-csr:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CSR node should have 'key-csr:' relation, got %v", csrNode.Relations)
	}
}

func TestConvertStore_CSRCertRelation(t *testing.T) {
	key := testGenRSAKey(t)
	csr := testCSR(t, key, "test.example.com")
	cert := testSelfSignedCert(t, key)

	store := makeStore(
		makeContainer(certlib.FormatPEM, "/tmp/test.csr", []certlib.CertItem{
			{Type: certlib.ContentCSR, CSR: csr},
		}),
		makeContainer(certlib.FormatPEM, "/tmp/test.pem", []certlib.CertItem{
			{Type: certlib.ContentCertificate, Certificate: cert},
		}),
	)

	relations := certlib.DetectRelations(store)
	index := certlib.BuildRelationIndex(relations, store)
	opts := output.OutputOptions{RelationIndex: index, Store: store}

	nodes := ConvertStore(store, opts, "basename")

	csrNode := nodes[0]
	found := false
	for _, r := range csrNode.Relations {
		if strings.HasPrefix(r, "csr-cert:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CSR node should have 'csr-cert:' relation, got %v", csrNode.Relations)
	}

	certNode := nodes[1]
	found = false
	for _, r := range certNode.Relations {
		if strings.HasPrefix(r, "csr-cert:") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cert node should have 'csr-cert:' relation, got %v", certNode.Relations)
	}
}
