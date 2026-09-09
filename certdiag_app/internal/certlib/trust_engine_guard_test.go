package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// TestNoPlatformTrustEngineInCertlib guards H3 (M29 rule): the only trust
// engine is the explicit pool built by certops from store contents. Nothing in
// certlib may reach for the OS pool, because on darwin that routes to
// Security.framework and disagrees with the pool for CA certificates.
func TestNoPlatformTrustEngineInCertlib(t *testing.T) {
	// certlib itself and certops, the only two layers that build pools.
	for _, dir := range []string{".", "../certops"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if strings.Contains(line, "SystemCertPool") {
					t.Errorf("%s:%d uses x509.SystemCertPool; trust must come from certops.EvaluateTrust", filepath.Join(dir, name), i+1)
				}
			}
		}
	}
}

// TestChainIncompleteFollowsTheTrustIndex guards the replacement of the
// platform engine: the same check reports INFO when the explicit trust
// evaluation completed the chain, and WARNING otherwise. Remote containers
// get remote wording.
func TestChainIncompleteFollowsTheTrustIndex(t *testing.T) {
	ca, caKey := guardCA(t)
	leaf := guardLeaf(t, ca, caKey)
	container := func(source CertSource) CertContainer {
		return CertContainer{
			FilePath: "/tmp/leaf.crt", Format: FormatPEM, Source: source,
			Items: []CertItem{{Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
		}
	}
	run := func(c CertContainer, idx *truststore.TrustIndex) CheckIssue {
		store := NewCertStore()
		store.Containers = append(store.Containers, c)
		res := RunChecks(store, BuildRelationIndex(nil, store), CheckOptions{TrustIndex: idx})
		for _, is := range res.Issues {
			if is.CheckID == "chain_incomplete" {
				return is
			}
		}
		t.Fatal("chain_incomplete did not fire")
		return CheckIssue{}
	}

	trusted := truststore.NewTrustIndex()
	trusted.Set(leaf, truststore.VerdictTrusted, ca)
	untrusted := truststore.NewTrustIndex()
	untrusted.Set(leaf, truststore.VerdictUntrusted, nil)

	if is := run(container(SourceFile), trusted); is.Severity != SeverityInfo || !strings.Contains(is.Message, "completes through the trust store") {
		t.Errorf("trusted index: got %v %q", is.Severity, is.Message)
	}
	if is := run(container(SourceFile), untrusted); is.Severity != SeverityWarning || !strings.Contains(is.Message, "not found in scan") {
		t.Errorf("untrusted index: got %v %q", is.Severity, is.Message)
	}
	if is := run(container(SourceRemote), nil); !strings.Contains(is.Message, "not served by the endpoint") {
		t.Errorf("remote container: got %q", is.Message)
	}
}

// TestChainIncompleteWithoutTrustIndexNeverMentionsTheOSStore guards the
// wording half of H3: with no TrustIndex the check has no way to know what the
// OS trusts and must not claim to.
func guardCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Unscanned Issuer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	return ca, caKey
}

func guardLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:  []string{"leaf.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	return leaf
}

func TestChainIncompleteWithoutTrustIndexNeverMentionsTheOSStore(t *testing.T) {
	ca, caKey := guardCA(t)
	leaf := guardLeaf(t, ca, caKey)

	store := NewCertStore()
	store.Containers = append(store.Containers, CertContainer{
		FilePath: "/tmp/leaf.crt", Format: FormatPEM,
		Items: []CertItem{{Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw}},
	})
	result := RunChecks(store, BuildRelationIndex(nil, store), CheckOptions{})

	found := false
	for _, is := range result.Issues {
		if is.CheckID != "chain_incomplete" {
			continue
		}
		found = true
		if strings.Contains(is.Message, "system root store") {
			t.Errorf("no TrustIndex was given, yet the message claims OS trust: %q", is.Message)
		}
		if is.Severity != SeverityWarning {
			t.Errorf("severity %v, want WARNING when trust is unknown", is.Severity)
		}
	}
	if !found {
		t.Fatal("chain_incomplete did not fire for a leaf whose issuer is not in the scan")
	}
}
