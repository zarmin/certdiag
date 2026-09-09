package certops

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// --- chain-building helpers -------------------------------------------------

type trustCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func trustRoot(t *testing.T, cn string) trustCA {
	t.Helper()
	return trustIssue(t, trustCA{}, cn, true, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
}

// trustIssue signs cn with parent, or self-signs when parent is the zero value.
func trustIssue(t *testing.T, parent trustCA, cn string, isCA bool, notBefore, notAfter time.Time) trustCA {
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
	return trustCA{cert: cert, key: key}
}

// clientAuthLeaf carries an EKU that is not server auth, which is the case the
// ExtKeyUsageAny requirement exists for.
func clientAuthLeaf(t *testing.T, parent trustCA, cn string) trustCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return trustCA{cert: cert, key: key}
}

func scanStore(certs ...*x509.Certificate) *certlib.CertStore {
	cs := certlib.NewCertStore()
	items := make([]certlib.CertItem, 0, len(certs))
	for _, c := range certs {
		items = append(items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Alias:       c.Subject.CommonName,
			Certificate: c,
			RawBytes:    c.Raw,
		})
	}
	cs.AddContainer(certlib.CertContainer{
		FilePath: "/scan/chain.pem",
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items:    items,
	})
	return cs
}

func osStore(certs ...*x509.Certificate) truststore.StoreContents {
	return storeFixture("Test OS Store", truststore.StoreTypeOS, "/kc", certs...)
}

// --- EvaluateTrust ----------------------------------------------------------

// TestEvaluateTrust_Anchor: membership in the OS store outranks chaining, so a
// root the machine holds reads ANCHOR rather than the weaker TRUSTED.
func TestEvaluateTrust_Anchor(t *testing.T) {
	root := trustRoot(t, "Anchor Root")

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(root.cert),
		Stores: []truststore.StoreContents{osStore(root.cert)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(root.cert); got != truststore.VerdictAnchor {
		t.Errorf("expected anchor, got %q", got)
	}
	if idx.AnchorFor(root.cert) == nil {
		t.Error("an anchor is its own anchor")
	}
}

// TestEvaluateTrust_Denied: an explicit distrust beats membership. This is the
// point of macOS "Never Trust".
func TestEvaluateTrust_Denied(t *testing.T) {
	root := trustRoot(t, "Denied Root")

	store := osStore(root.cert)
	store.TrustMap = map[string]truststore.CertTrust{
		truststore.CertFingerprint(root.cert): {Overall: truststore.TrustDenied},
	}

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(root.cert),
		Stores: []truststore.StoreContents{store},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(root.cert); got != truststore.VerdictDenied {
		t.Errorf("expected denied, got %q", got)
	}
}

// TestEvaluateTrust_ChainsToAnchor: a leaf and its intermediate in the same
// scan resolve through a root held only by the store.
func TestEvaluateTrust_ChainsToAnchor(t *testing.T) {
	root := trustRoot(t, "Chain Root")
	inter := trustIssue(t, root, "Chain Intermediate", true, time.Now().Add(-time.Hour), time.Now().Add(200*24*time.Hour))
	leaf := trustIssue(t, inter, "leaf.chain.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(leaf.cert, inter.cert),
		Stores: []truststore.StoreContents{osStore(root.cert)},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := idx.Verdict(leaf.cert); got != truststore.VerdictTrusted {
		t.Errorf("leaf: expected trusted, got %q", got)
	}
	if got := idx.Verdict(inter.cert); got != truststore.VerdictTrusted {
		t.Errorf("intermediate: expected trusted, got %q", got)
	}
	anchor := idx.AnchorFor(leaf.cert)
	if anchor == nil || anchor.Subject.CommonName != "Chain Root" {
		t.Errorf("expected the store root as the anchor, got %v", anchor)
	}
}

func TestEvaluateTrust_NoPath(t *testing.T) {
	other := trustRoot(t, "Unrelated Root")
	root := trustRoot(t, "Private Root")
	leaf := trustIssue(t, root, "leaf.private.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(leaf.cert),
		Stores: []truststore.StoreContents{osStore(other.cert)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(leaf.cert); got != truststore.VerdictUntrusted {
		t.Errorf("expected untrusted, got %q", got)
	}
	if idx.AnchorFor(leaf.cert) != nil {
		t.Error("expected no anchor for an untrusted certificate")
	}
}

// TestEvaluateTrust_ExpiredCA: an expired certificate that would otherwise
// chain reports EXPIRED, not UNTRUSTED -- the distinction the expiry column
// cannot make on its own.
func TestEvaluateTrust_ExpiredCA(t *testing.T) {
	root := trustRoot(t, "Expiry Root")
	expired := trustIssue(t, root, "Expired Intermediate", true,
		time.Now().Add(-72*time.Hour), time.Now().Add(-time.Hour))

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(expired.cert),
		Stores: []truststore.StoreContents{osStore(root.cert)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(expired.cert); got != truststore.VerdictExpired {
		t.Errorf("expected expired, got %q", got)
	}
}

// TestEvaluateTrust_NonServerAuthEKU is the regression guard for the
// ExtKeyUsageAny requirement: VerifyOptions defaults to ExtKeyUsageServerAuth,
// which would mark every client-auth certificate untrusted.
func TestEvaluateTrust_NonServerAuthEKU(t *testing.T) {
	root := trustRoot(t, "EKU Root")
	inter := trustIssue(t, root, "EKU Intermediate", true, time.Now().Add(-time.Hour), time.Now().Add(200*24*time.Hour))
	client := clientAuthLeaf(t, inter, "client.eku.test")

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(client.cert, inter.cert),
		Stores: []truststore.StoreContents{osStore(root.cert)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(inter.cert); got != truststore.VerdictTrusted {
		t.Errorf("the client-auth chain's CA must resolve, got %q", got)
	}
}

// TestEvaluateTrust_DeniedRootExcludedFromPool: a distrusted root must not
// anchor anything, or DENIED would be cosmetic.
func TestEvaluateTrust_DeniedRootExcludedFromPool(t *testing.T) {
	root := trustRoot(t, "Poisoned Root")
	leaf := trustIssue(t, root, "leaf.poisoned.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	inter := trustIssue(t, root, "Poisoned Intermediate", true, time.Now().Add(-time.Hour), time.Now().Add(200*24*time.Hour))

	store := osStore(root.cert)
	store.TrustMap = map[string]truststore.CertTrust{
		truststore.CertFingerprint(root.cert): {Overall: truststore.TrustDenied},
	}

	idx, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(leaf.cert, inter.cert),
		Stores: []truststore.StoreContents{store},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Verdict(inter.cert); got == truststore.VerdictTrusted {
		t.Error("a distrusted root must not anchor an intermediate")
	}
}

// TestEvaluateTrust_NonOSStoresIgnored: TRUST answers the OS question. Presence
// in Java, NSS or a shipped snapshot belongs in the STORES column instead.
func TestEvaluateTrust_NonOSStoresIgnored(t *testing.T) {
	root := trustRoot(t, "Java Only Root")

	for _, typ := range []truststore.StoreType{
		truststore.StoreTypeJava,
		truststore.StoreTypeOpenSSL,
		truststore.StoreTypeNSS,
		truststore.StoreTypeBundle,
		truststore.StoreTypeCustom,
	} {
		t.Run(string(typ), func(t *testing.T) {
			idx, err := EvaluateTrust(TrustEvalOptions{
				Store:  scanStore(root.cert),
				Stores: []truststore.StoreContents{storeFixture("s", typ, "/p", root.cert)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := idx.Verdict(root.cert); got == truststore.VerdictAnchor {
				t.Errorf("a %s store must not make a certificate an OS anchor", typ)
			}
		})
	}
}

func TestEvaluateTrust_NoStores(t *testing.T) {
	root := trustRoot(t, "Alone Root")

	idx, err := EvaluateTrust(TrustEvalOptions{Store: scanStore(root.cert)})
	if err != nil {
		t.Fatal(err)
	}
	// With no OS store there is no pool, so a CA cannot be evaluated and must
	// degrade to untrusted rather than claiming trust.
	if got := idx.Verdict(root.cert); got != truststore.VerdictUntrusted {
		t.Errorf("expected untrusted with no stores, got %q", got)
	}
}

func TestEvaluateTrust_NilStore(t *testing.T) {
	idx, err := EvaluateTrust(TrustEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if idx == nil || idx.Len() != 0 {
		t.Error("expected an empty index for a nil store")
	}
}

func TestEvaluateTrust_ContextCancel(t *testing.T) {
	root := trustRoot(t, "Cancel Root")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := EvaluateTrust(TrustEvalOptions{
		Store:  scanStore(root.cert),
		Stores: []truststore.StoreContents{osStore(root.cert)},
		Ctx:    ctx,
	})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestEvaluateTrust_IgnoresNonCertificateItems(t *testing.T) {
	cs := certlib.NewCertStore()
	cs.AddContainer(certlib.CertContainer{
		FilePath: "/scan/key.pem",
		Items: []certlib.CertItem{
			{Type: certlib.ContentPrivateKey, Alias: "key"},
			{Type: certlib.ContentCSR, Alias: "csr"},
		},
	})

	idx, err := EvaluateTrust(TrustEvalOptions{Store: cs})
	if err != nil {
		t.Fatal(err)
	}
	if idx.Len() != 0 {
		t.Errorf("expected nothing to evaluate, got %d entries", idx.Len())
	}
}

// --- AnchorContainer --------------------------------------------------------

// TestAnchorContainer_IssuerClosureOnly: only the anchors that matter are
// injected. Pulling in every root would bloat the relation pass and fill the
// output with irrelevant same_cert links.
func TestAnchorContainer_IssuerClosureOnly(t *testing.T) {
	root := trustRoot(t, "Closure Root")
	leaf := trustIssue(t, root, "leaf.closure.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	noise := make([]*x509.Certificate, 0, 50)
	for i := 0; i < 50; i++ {
		noise = append(noise, trustRoot(t, "Noise Root "+itoa(i)).cert)
	}
	all := append([]*x509.Certificate{root.cert}, noise...)

	container := AnchorContainer(scanStore(leaf.cert), []truststore.StoreContents{osStore(all...)})
	if container == nil {
		t.Fatal("expected an anchor container")
	}
	if len(container.Items) != 1 {
		t.Fatalf("expected only the relevant root out of 51, got %d", len(container.Items))
	}
	if container.Items[0].Certificate.Subject.CommonName != "Closure Root" {
		t.Errorf("expected the leaf's issuer, got %q", container.Items[0].Certificate.Subject.CommonName)
	}
}

// TestAnchorContainer_TransitiveClosure: a cross-signed root pulls in its own
// issuer, which is what completes a chain past a cross-sign.
func TestAnchorContainer_TransitiveClosure(t *testing.T) {
	oldRoot := trustRoot(t, "Old Root")
	crossSigned := trustIssue(t, oldRoot, "Cross Signed Root", true, time.Now().Add(-time.Hour), time.Now().Add(200*24*time.Hour))
	leaf := trustIssue(t, crossSigned, "leaf.cross.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	container := AnchorContainer(
		scanStore(leaf.cert),
		[]truststore.StoreContents{osStore(crossSigned.cert, oldRoot.cert, trustRoot(t, "Irrelevant").cert)},
	)
	if container == nil {
		t.Fatal("expected an anchor container")
	}
	if len(container.Items) != 2 {
		t.Fatalf("expected the cross-signed root and its issuer, got %d", len(container.Items))
	}
	names := map[string]bool{}
	for _, item := range container.Items {
		names[item.Certificate.Subject.CommonName] = true
	}
	if !names["Cross Signed Root"] || !names["Old Root"] {
		t.Errorf("expected the transitive closure, got %v", names)
	}
}

func TestAnchorContainer_SkipsCertsAlreadyInScan(t *testing.T) {
	root := trustRoot(t, "Duplicate Root")
	leaf := trustIssue(t, root, "leaf.dup.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	// The root is both scanned and in the store; it must not be duplicated as
	// a second node.
	container := AnchorContainer(scanStore(leaf.cert, root.cert), []truststore.StoreContents{osStore(root.cert)})
	if container != nil {
		t.Errorf("expected no anchor container when the issuer is already in the scan, got %d items", len(container.Items))
	}
}

func TestAnchorContainer_IsRelationsOnly(t *testing.T) {
	root := trustRoot(t, "RelOnly Root")
	leaf := trustIssue(t, root, "leaf.relonly.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	container := AnchorContainer(scanStore(leaf.cert), []truststore.StoreContents{osStore(root.cert)})
	if container == nil {
		t.Fatal("expected an anchor container")
	}
	// RelationsOnly is what keeps injected anchors out of every render path
	// while still letting them complete chains.
	if !container.RelationsOnly {
		t.Error("the anchor container must be RelationsOnly")
	}
	if container.Source != certlib.SourceTrustStore {
		t.Errorf("expected SourceTrustStore, got %q", container.Source)
	}
	if container.Label != AnchorContainerLabel {
		t.Errorf("expected the label %q, got %q", AnchorContainerLabel, container.Label)
	}
	if container.FilePath != "" {
		t.Errorf("a synthesized container has no file path, got %q", container.FilePath)
	}
}

func TestAnchorContainer_Empty(t *testing.T) {
	root := trustRoot(t, "Nothing Root")

	if AnchorContainer(nil, []truststore.StoreContents{osStore(root.cert)}) != nil {
		t.Error("expected nil for a nil scan store")
	}
	if AnchorContainer(scanStore(root.cert), nil) != nil {
		t.Error("expected nil with no trust stores")
	}
	// Only non-OS stores: nothing to anchor with.
	if c := AnchorContainer(scanStore(root.cert),
		[]truststore.StoreContents{storeFixture("j", truststore.StoreTypeJava, "/j", root.cert)}); c != nil {
		t.Error("expected nil when no OS store is present")
	}
	// An unrelated store: no closure.
	unrelated := trustRoot(t, "Unrelated")
	leaf := trustIssue(t, trustRoot(t, "Private"), "leaf.x", false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if c := AnchorContainer(scanStore(leaf.cert), []truststore.StoreContents{osStore(unrelated.cert)}); c != nil {
		t.Errorf("expected nil when no store certificate matches an issuer, got %d items", len(c.Items))
	}
}

// TestAnchorContainer_CompletesChains is the end-to-end point of the container:
// after injection, the relation engine reaches the root with no new code.
func TestAnchorContainer_CompletesChains(t *testing.T) {
	root := trustRoot(t, "Chainable Root")
	inter := trustIssue(t, root, "Chainable Intermediate", true, time.Now().Add(-time.Hour), time.Now().Add(200*24*time.Hour))
	leaf := trustIssue(t, inter, "leaf.chainable.test", false, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	store := scanStore(leaf.cert, inter.cert)

	before := certlib.AssembleChains(
		certlib.BuildRelationIndex(certlib.DetectRelations(store), store), store)
	leafRef := certlib.ItemRef{ContainerIdx: 0, ItemIdx: 0, FilePath: "/scan/chain.pem", Alias: leaf.cert.Subject.CommonName}
	if got := len(before[leafRef]); got != 2 {
		t.Fatalf("expected a 2-link chain before injection, got %d", got)
	}

	container := AnchorContainer(store, []truststore.StoreContents{osStore(root.cert)})
	if container == nil {
		t.Fatal("expected an anchor container")
	}
	store.AddContainer(*container)

	after := certlib.AssembleChains(
		certlib.BuildRelationIndex(certlib.DetectRelations(store), store), store)
	if got := len(after[leafRef]); got != 3 {
		t.Errorf("expected the chain to reach the store root (3 links), got %d", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
