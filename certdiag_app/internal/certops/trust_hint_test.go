package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// An untrusted verdict is correct but unhelpful on its own. When the missing
// issuer is published at a known URL, saying so turns a dead end into the next
// step - and costs nothing, because it reads only what is already in hand.

func hintCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey, aiaURL string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if aiaURL != "" {
		tmpl.IssuingCertificateURL = []string{aiaURL}
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

func hintStore(certs ...*x509.Certificate) *certlib.CertStore {
	store := certlib.NewCertStore()
	c := certlib.CertContainer{FilePath: "/tmp/chain.pem", Format: certlib.FormatPEM, Source: certlib.SourceFile}
	for _, cert := range certs {
		c.Items = append(c.Items, certlib.CertItem{Type: certlib.ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)
	return store
}

// TestEvaluateTrust_OfflineHint is the merkantilflotta shape: the served chain
// stops at an intermediate whose issuer is elsewhere. No network is touched.
func TestEvaluateTrust_OfflineHint(t *testing.T) {
	root, rootKey := hintCert(t, "Hint Root", true, nil, nil, "")
	inter, interKey := hintCert(t, "Hint Intermediate", true, root, rootKey,
		"http://ca.example/root.crt")
	leaf, _ := hintCert(t, "leaf.example", false, inter, interKey, "")

	// The root is absent, exactly as it is in a served chain.
	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", mustCert(t, "Unrelated")),
	}
	index, err := EvaluateTrust(TrustEvalOptions{Store: hintStore(leaf, inter), Stores: stores})
	if err != nil {
		t.Fatal(err)
	}

	detail := index.Detail(leaf)
	if detail.Verdict != truststore.VerdictUntrusted {
		t.Fatalf("expected untrusted, got %q", detail.Verdict)
	}
	if detail.Hint == "" {
		t.Fatal("an untrusted chain whose issuer is published must say where")
	}
	if !strings.Contains(detail.Hint, "http://ca.example/root.crt") {
		t.Errorf("the hint must carry the URL: %q", detail.Hint)
	}
	if !strings.Contains(detail.Hint, "Hint Root") {
		t.Errorf("the hint must name the missing issuer: %q", detail.Hint)
	}
}

// TestEvaluateTrust_NoHintWhenTrusted: a verdict that needs no explanation
// gets none.
func TestEvaluateTrust_NoHintWhenTrusted(t *testing.T) {
	root, rootKey := hintCert(t, "Quiet Root", true, nil, nil, "")
	leaf, _ := hintCert(t, "leaf.example", false, root, rootKey, "http://ca.example/root.crt")

	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root),
	}
	index, err := EvaluateTrust(TrustEvalOptions{Store: hintStore(leaf, root), Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	if hint := index.Detail(leaf).Hint; hint != "" {
		t.Errorf("a trusted chain needs no hint, got %q", hint)
	}
}

// TestEvaluateTrust_NoHintWithoutURL: nothing to suggest, so nothing is said.
func TestEvaluateTrust_NoHintWithoutURL(t *testing.T) {
	root, rootKey := hintCert(t, "Silent Root", true, nil, nil, "")
	inter, interKey := hintCert(t, "Silent Intermediate", true, root, rootKey, "")
	leaf, _ := hintCert(t, "leaf.example", false, inter, interKey, "")

	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", mustCert(t, "Unrelated")),
	}
	index, err := EvaluateTrust(TrustEvalOptions{Store: hintStore(leaf, inter), Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	if hint := index.Detail(leaf).Hint; hint != "" {
		t.Errorf("with no published issuer there is nothing to suggest, got %q", hint)
	}
}

// TestEvaluateTrust_HintFollowsTheWholePath: the URL that matters is the one on
// the certificate where the chain actually ran out, not the leaf's.
func TestEvaluateTrust_HintFollowsTheWholePath(t *testing.T) {
	root, rootKey := hintCert(t, "Deep Root", true, nil, nil, "")
	inter, interKey := hintCert(t, "Deep Intermediate", true, root, rootKey,
		"http://ca.example/deep-root.crt")
	leaf, _ := hintCert(t, "leaf.example", false, inter, interKey,
		"http://ca.example/intermediate.crt")

	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", mustCert(t, "Unrelated")),
	}
	index, err := EvaluateTrust(TrustEvalOptions{Store: hintStore(leaf, inter), Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	hint := index.Detail(leaf).Hint
	if !strings.Contains(hint, "deep-root.crt") {
		t.Errorf("the hint must point at where the chain ran out, got %q", hint)
	}
}

func mustCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	cert, _ := hintCert(t, cn, true, nil, nil, "")
	return cert
}

// TestEvaluateTrust_ViaAIA: a chain that completes only through a fetched
// issuer must not read as plain TRUSTED. That distinction is the whole point:
// it is exactly the trust a client which does not chase AIA lacks.
func TestEvaluateTrust_ViaAIA(t *testing.T) {
	root, rootKey := hintCert(t, "AIA Root", true, nil, nil, "")
	inter, interKey := hintCert(t, "AIA Intermediate", true, root, rootKey, "")
	leaf, _ := hintCert(t, "leaf.example", false, inter, interKey, "")

	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root),
	}
	// Only the leaf is in the scan; the intermediate arrives over AIA.
	aia := &certlib.AIAResult{Fetched: []certlib.AIAFetched{
		{Cert: inter, URL: "http://ca.example/inter.crt", For: leaf},
	}}

	index, err := EvaluateTrust(TrustEvalOptions{
		Store: hintStore(leaf), Stores: stores, AIA: aia,
	})
	if err != nil {
		t.Fatal(err)
	}

	detail := index.Detail(leaf)
	if detail.Verdict != truststore.VerdictTrusted {
		t.Fatalf("the fetched intermediate completes the path, expected trusted, got %q", detail.Verdict)
	}
	if !detail.ViaAIA {
		t.Error("a path that needs a fetched certificate must be labelled via AIA")
	}
}

// TestEvaluateTrust_NotViaAIAWhenAlreadyComplete: fetching something that was
// not needed must not relabel a verdict that stood on its own.
func TestEvaluateTrust_NotViaAIAWhenAlreadyComplete(t *testing.T) {
	root, rootKey := hintCert(t, "Complete Root", true, nil, nil, "")
	inter, interKey := hintCert(t, "Complete Intermediate", true, root, rootKey, "")
	leaf, _ := hintCert(t, "leaf.example", false, inter, interKey, "")
	spare, _ := hintCert(t, "Spare CA", true, nil, nil, "")

	stores := []truststore.StoreContents{
		storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", root),
	}
	aia := &certlib.AIAResult{Fetched: []certlib.AIAFetched{{Cert: spare, URL: "http://ca.example/spare.crt"}}}

	index, err := EvaluateTrust(TrustEvalOptions{
		Store: hintStore(leaf, inter), Stores: stores, AIA: aia,
	})
	if err != nil {
		t.Fatal(err)
	}
	detail := index.Detail(leaf)
	if detail.Verdict != truststore.VerdictTrusted {
		t.Fatalf("expected trusted, got %q", detail.Verdict)
	}
	if detail.ViaAIA {
		t.Error("the scan already had the whole path; AIA was not what made it work")
	}
}
