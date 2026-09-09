package certops

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// signCert issues a certificate for key with the given subject, signed by
// parent (self-signed when parent is nil). Unlike rsCert the key is the
// caller's, which is what a cross-sign needs: the same key under two issuers.
func signCert(t *testing.T, cn string, key *rsa.PrivateKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool, dns []string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              dns,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
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
	return cert
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// crossSignFixture builds the classic transition: a new root that is both
// self-signed and cross-signed by an old root, an intermediate under the new
// root's key, and a leaf. The server serves leaf, intermediate and the
// cross-signed copy; the store holds only the new self-signed root.
type crossSignFixture struct {
	oldRoot, newRoot, crossSigned, intermediate, leaf *x509.Certificate
}

func newCrossSignFixture(t *testing.T) crossSignFixture {
	t.Helper()
	oldKey, newKey, intKey, leafKey := rsaKey(t), rsaKey(t), rsaKey(t), rsaKey(t)
	oldRoot := signCert(t, "Old Root", oldKey, nil, nil, true, nil)
	newRoot := signCert(t, "New Root", newKey, nil, nil, true, nil)
	crossSigned := signCert(t, "New Root", newKey, oldRoot, oldKey, true, nil)
	intermediate := signCert(t, "Issuing CA", intKey, newRoot, newKey, true, nil)
	leaf := signCert(t, "www.example", leafKey, intermediate, intKey, false, []string{"www.example"})
	return crossSignFixture{oldRoot, newRoot, crossSigned, intermediate, leaf}
}

func issuesByID(result *certlib.CheckResult, id string) []certlib.CheckIssue {
	var out []certlib.CheckIssue
	for _, i := range result.Issues {
		if i.CheckID == id {
			out = append(out, i)
		}
	}
	return out
}

func warningsOf(result *certlib.CheckResult) []string {
	var out []string
	for _, i := range result.Issues {
		if i.Severity == certlib.SeverityWarning || i.Severity == certlib.SeverityCritical {
			out = append(out, i.CheckID+": "+i.Message)
		}
	}
	return out
}

func checkServed(in CheckTargetInput) *certlib.CheckResult {
	in.Target = certlib.RemoteTarget{Host: "www.example", Port: 443}
	return CheckFetchedTarget(in, certlib.CheckOptions{})
}

// TestRemoteCheck_CrossSignedChainCompletesThroughStore: the cross-signed
// copy's issuer is not served, but this machine holds the new root, so the
// chain completes here and the finding is an info naming that anchor.
func TestRemoteCheck_CrossSignedChainCompletesThroughStore(t *testing.T) {
	f := newCrossSignFixture(t)
	stores := []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", f.newRoot)}

	result := checkServed(CheckTargetInput{
		Certificates: []*x509.Certificate{f.leaf, f.intermediate, f.crossSigned},
		Roots:        OSAnchorPool(stores),
		Stores:       stores,
	})

	if w := warningsOf(result); len(w) != 0 {
		t.Errorf("a chain the local store completes must not warn: %v", w)
	}
	found := issuesByID(result, "chain_incomplete")
	if len(found) != 1 {
		t.Fatalf("expected one chain_incomplete info for the cross-signed CA, got %+v", found)
	}
	if found[0].Severity != certlib.SeverityInfo {
		t.Errorf("severity %s, want info", found[0].Severity)
	}
	if anchor, _ := found[0].Details["anchor"].(string); anchor == "" {
		t.Errorf("the info must name the anchor that completed the chain: %v", found[0].Details)
	}
}

// TestRemoteCheck_CrossSignedChainWithoutStoreStillWarns: with no store to
// consult the served bytes are all there is, and they do not reach a root.
func TestRemoteCheck_CrossSignedChainWithoutStoreStillWarns(t *testing.T) {
	f := newCrossSignFixture(t)
	result := checkServed(CheckTargetInput{
		Certificates: []*x509.Certificate{f.leaf, f.intermediate, f.crossSigned},
	})
	found := issuesByID(result, "chain_incomplete")
	if len(found) != 1 || found[0].Severity != certlib.SeverityWarning {
		t.Fatalf("expected one chain_incomplete warning, got %+v", found)
	}
}

// TestRemoteCheck_LeafOnlyIssuerInStore: a server that sends the leaf alone is
// still a finding, but an info when this machine's store holds the issuer.
func TestRemoteCheck_LeafOnlyIssuerInStore(t *testing.T) {
	f := newCrossSignFixture(t)
	stores := []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", f.newRoot, f.intermediate)}

	result := checkServed(CheckTargetInput{
		Certificates: []*x509.Certificate{f.leaf},
		Roots:        OSAnchorPool(stores),
		Stores:       stores,
	})
	if w := warningsOf(result); len(w) != 0 {
		t.Errorf("issuer in the local store must not warn: %v", w)
	}
	found := issuesByID(result, "remote_chain_incomplete")
	if len(found) != 1 || found[0].Severity != certlib.SeverityInfo {
		t.Fatalf("expected remote_chain_incomplete at info, got %+v", found)
	}
	if anchor, _ := found[0].Details["anchor"].(string); anchor == "" {
		t.Errorf("the info must name the anchor: %v", found[0].Details)
	}
}

// TestRemoteCheck_LeafOnlyIssuerAbsentWarns: the issuer is nowhere on this
// machine, so the leaf-only chain is the warning it always was.
func TestRemoteCheck_LeafOnlyIssuerAbsentWarns(t *testing.T) {
	f := newCrossSignFixture(t)
	stores := []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", f.oldRoot)}

	result := checkServed(CheckTargetInput{
		Certificates: []*x509.Certificate{f.leaf},
		Roots:        OSAnchorPool(stores),
		Stores:       stores,
	})
	found := issuesByID(result, "remote_chain_incomplete")
	if len(found) != 1 || found[0].Severity != certlib.SeverityWarning {
		t.Fatalf("expected remote_chain_incomplete warning, got %+v", found)
	}
}

// TestEvaluateTrust_CrossSignedCopyOfAnchor: the cross-signed copy of a root
// the OS holds reads TRUSTED with that root as its anchor, not UNTRUSTED
// because its own issuer is missing; every client ends the path at the anchor.
func TestEvaluateTrust_CrossSignedCopyOfAnchor(t *testing.T) {
	f := newCrossSignFixture(t)
	stores := []truststore.StoreContents{storeFixture("Stub OS Store", truststore.StoreTypeOS, "/os", f.newRoot)}
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{FilePath: "served", Items: []certlib.CertItem{
		{Type: certlib.ContentCertificate, Certificate: f.crossSigned, RawBytes: f.crossSigned.Raw},
	}})
	index, err := EvaluateTrust(TrustEvalOptions{Store: store, Stores: stores})
	if err != nil {
		t.Fatal(err)
	}
	d := index.Detail(f.crossSigned)
	if d.Verdict != truststore.VerdictTrusted {
		t.Fatalf("verdict %s, want trusted", d.Verdict)
	}
	if d.Anchor == nil || !d.Anchor.Equal(f.newRoot) {
		t.Errorf("anchor must be the self-signed root the store holds")
	}
	if got := index.Verdict(f.oldRoot); got == truststore.VerdictTrusted {
		t.Errorf("a certificate not in the served store must not gain a verdict: %s", got)
	}
}
