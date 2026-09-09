package certlib

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
)

// chainCert issues a certificate, self-signed when parent is nil.
func chainCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
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

// servedChain builds root -> intermediate -> leaf and hands back the pieces.
func servedChain(t *testing.T) (root, inter, leaf *x509.Certificate, rootKey *ecdsa.PrivateKey) {
	t.Helper()
	root, rootKey = chainCert(t, "Chain Test Root", true, nil, nil)
	inter, interKey := chainCert(t, "Chain Test Intermediate", true, root, rootKey)
	leaf, _ = chainCert(t, "leaf.example.com", false, inter, interKey)
	return root, inter, leaf, rootKey
}

func chainCtx(certs ...*x509.Certificate) RemoteCheckContext {
	return RemoteCheckContext{
		Target:       RemoteTarget{Host: "srv.example.com", Port: 443},
		TLSInfo:      TLSConnectionInfo{ServerName: "srv.example.com"},
		Certificates: certs,
	}
}

func idsOf(issues []CheckIssue) []string {
	var out []string
	for _, i := range issues {
		out = append(out, i.CheckID)
	}
	return out
}

// TestRemoteChainExtraneous_UnrelatedCA: a certificate concatenated into the
// server's bundle that signs nothing it serves is wasted bytes on every
// handshake, and usually a mistake worth naming.
func TestRemoteChainExtraneous_UnrelatedCA(t *testing.T) {
	_, inter, leaf, _ := servedChain(t)
	stranger, _ := chainCert(t, "Unrelated CA", true, nil, nil)

	issues := checkChainExtraneous(chainCtx(leaf, inter, stranger), CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected exactly the stranger to be flagged, got %v", idsOf(issues))
	}
	if issues[0].Severity != SeverityWarning {
		t.Errorf("expected a warning, got %s", issues[0].Severity)
	}
	if !strings.Contains(issues[0].Message, "Unrelated CA") {
		t.Errorf("the message must name the offender: %q", issues[0].Message)
	}
}

func TestRemoteChainExtraneous_NotForCompleteChain(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)
	if issues := checkChainExtraneous(chainCtx(leaf, inter), CheckOptions{}); len(issues) != 0 {
		t.Errorf("a leaf and its issuer are both on the path, got %v", idsOf(issues))
	}
	if issues := checkChainExtraneous(chainCtx(leaf, inter, root), CheckOptions{}); len(issues) != 0 {
		t.Errorf("a full chain has nothing extraneous, got %v", idsOf(issues))
	}
}

// TestRemoteChainWrongIntermediate_SameSubjectDifferentKey is the case this
// check exists for: the CA name reads correctly in every listing, so only the
// signature reveals that the server never rotated its intermediate.
func TestRemoteChainWrongIntermediate_SameSubjectDifferentKey(t *testing.T) {
	root, inter, leaf, rootKey := servedChain(t)
	// A second CA with the same subject but a different key: what a stale
	// bundle looks like after the CA rolled its intermediate.
	impostor, _ := chainCert(t, inter.Subject.CommonName, true, root, rootKey)

	issues := checkChainWrongIntermediate(chainCtx(leaf, impostor), CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected one critical finding, got %v", idsOf(issues))
	}
	if issues[0].Severity != SeverityCritical {
		t.Errorf("a chain that cannot verify is critical, got %s", issues[0].Severity)
	}
	for _, want := range []string{inter.Subject.CommonName, leaf.Subject.CommonName} {
		if !strings.Contains(issues[0].Message, want) {
			t.Errorf("the message must name both certificates, missing %q in %q", want, issues[0].Message)
		}
	}

	if issues := checkChainWrongIntermediate(chainCtx(leaf, inter), CheckOptions{}); len(issues) != 0 {
		t.Errorf("the real intermediate must not be flagged, got %v", idsOf(issues))
	}
}

func TestRemoteChainOrder_ReversedIsInfo(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)

	issues := checkRemoteChainOrder(chainCtx(leaf, root, inter), CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected one ordering note, got %v", idsOf(issues))
	}
	if issues[0].Severity != SeverityInfo {
		t.Errorf("TLS 1.3 allows any order after the leaf, so this is info, got %s", issues[0].Severity)
	}
}

func TestRemoteChainOrder_LeafFirstIsQuiet(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)
	if issues := checkRemoteChainOrder(chainCtx(leaf, inter, root), CheckOptions{}); len(issues) != 0 {
		t.Errorf("issuance order must be quiet, got %v", idsOf(issues))
	}
}

func TestRemoteChainSentRoot_Info(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)

	issues := checkChainSentRoot(chainCtx(leaf, inter, root), CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected the served root to be noted, got %v", idsOf(issues))
	}
	if issues[0].Severity != SeverityInfo {
		t.Errorf("sending the root is wasteful, not broken: got %s", issues[0].Severity)
	}

	if issues := checkChainSentRoot(chainCtx(leaf, inter), CheckOptions{}); len(issues) != 0 {
		t.Errorf("a chain without the root must be quiet, got %v", idsOf(issues))
	}
}

// TestRemoteChainSentRoot_SelfSignedLeafIsADifferentFault keeps the two apart:
// a self-signed leaf is remote_self_signed, not a wastefully served root.
func TestRemoteChainSentRoot_SelfSignedLeafIsADifferentFault(t *testing.T) {
	selfSigned, _ := chainCert(t, "self.example.com", false, nil, nil)
	other, _ := chainCert(t, "Other CA", true, nil, nil)
	for _, issue := range checkChainSentRoot(chainCtx(selfSigned, other), CheckOptions{}) {
		if issue.Details["index"] == 0 {
			t.Error("the leaf must never be reported as a served root")
		}
	}
}

// TestRemoteChainUntrusted_ExplicitPool: the verdict follows certdiag's own
// anchor pool, so it is the same answer the TRUST column gives on the same
// bytes, on every platform (M30a option A).
func TestRemoteChainUntrusted_ExplicitPool(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)

	empty := chainCtx(leaf, inter)
	empty.Roots = x509.NewCertPool()
	if issues := checkChainUntrusted(empty, CheckOptions{}); len(issues) != 1 {
		t.Errorf("a chain to an unknown root must be untrusted, got %v", idsOf(issues))
	}

	trusted := chainCtx(leaf, inter)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	trusted.Roots = pool
	if issues := checkChainUntrusted(trusted, CheckOptions{}); len(issues) != 0 {
		t.Errorf("a chain to a root in the pool must be trusted, got %v", idsOf(issues))
	}
}

// TestRemoteChainUntrusted_NoPoolNoVerdict: without an anchor pool the check
// says nothing rather than falling back to the host's verifier.
func TestRemoteChainUntrusted_NoPoolNoVerdict(t *testing.T) {
	_, inter, leaf, _ := servedChain(t)
	if issues := checkChainUntrusted(chainCtx(leaf, inter), CheckOptions{}); len(issues) != 0 {
		t.Errorf("no pool means no verdict, got %v", idsOf(issues))
	}
}

// TestRemotePlatformRejects_IsSeparateFinding: the platform's opinion is
// reported next to the verdict, never as the verdict.
func TestRemotePlatformRejects_IsSeparateFinding(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)

	ctx := chainCtx(leaf, inter)
	ctx.Roots = pool
	ctx.PlatformVerify = func(*x509.Certificate, *x509.CertPool) error {
		return errors.New("certificate is not standards compliant")
	}

	if issues := checkChainUntrusted(ctx, CheckOptions{}); len(issues) != 0 {
		t.Errorf("the pool trusts this chain, so the verdict must stay trusted: %v", idsOf(issues))
	}

	issues := checkPlatformRejects(ctx, CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected the platform's disagreement to be reported, got %v", idsOf(issues))
	}
	if issues[0].CheckID != "remote_platform_rejects" || issues[0].Severity != SeverityWarning {
		t.Errorf("expected a remote_platform_rejects warning, got %s/%s", issues[0].CheckID, issues[0].Severity)
	}
	if !strings.Contains(issues[0].Message, "not standards compliant") {
		t.Errorf("the platform's own words must survive: %q", issues[0].Message)
	}
}

// TestRemotePlatformRejects_QuietWhenAlreadyUntrusted avoids reporting the same
// failure twice.
func TestRemotePlatformRejects_QuietWhenAlreadyUntrusted(t *testing.T) {
	_, inter, leaf, _ := servedChain(t)
	ctx := chainCtx(leaf, inter)
	ctx.Roots = x509.NewCertPool()
	ctx.PlatformVerify = func(*x509.Certificate, *x509.CertPool) error {
		return errors.New("unknown authority")
	}
	if issues := checkPlatformRejects(ctx, CheckOptions{}); len(issues) != 0 {
		t.Errorf("remote_chain_untrusted already said this, got %v", idsOf(issues))
	}
}

// TestRemotePlatformRejects_NoVerifierNoFinding: on a platform without its own
// verifier there is no second opinion to report.
func TestRemotePlatformRejects_NoVerifierNoFinding(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	ctx := chainCtx(leaf, inter)
	ctx.Roots = pool
	if issues := checkPlatformRejects(ctx, CheckOptions{}); len(issues) != 0 {
		t.Errorf("no verifier means no finding, got %v", idsOf(issues))
	}
}

func TestServedPath_StopsAtSelfSigned(t *testing.T) {
	root, inter, leaf, _ := servedChain(t)
	got := servedPath([]*x509.Certificate{leaf, inter, root})
	want := []int{0, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("expected the whole chain on the path, got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path %v, want %v", got, want)
			break
		}
	}
}
