package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

func provCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: parent == nil || cn[0] == 'I', BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func served(certs ...*x509.Certificate) []certops.RemoteCertInfo {
	var out []certops.RemoteCertInfo
	for i, c := range certs {
		out = append(out, certops.RemoteCertInfo{Index: i, Role: "leaf", Cert: &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: c, RawBytes: c.Raw}})
	}
	return out
}

// TestAppendAIAToChains_PerTarget guards H10: with two targets whose chains
// were completed over AIA, each saved chain receives only its own issuers,
// in chase order, and the result is the same on every run.
func TestAppendAIAToChains_PerTarget(t *testing.T) {
	rootA, rootAKey := provCert(t, "Root A", nil, nil)
	interA, interAKey := provCert(t, "Inter A", rootA, rootAKey)
	leafA, _ := provCert(t, "a.example", interA, interAKey)
	rootB, rootBKey := provCert(t, "Root B", nil, nil)
	interB, interBKey := provCert(t, "Inter B", rootB, rootBKey)
	leafB, _ := provCert(t, "b.example", interB, interBKey)

	fp := func(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }
	provenance := map[[32]byte]certlib.AIAFetched{
		fp(interA): {Cert: interA, URL: "http://a/inter", For: leafA},
		fp(rootA):  {Cert: rootA, URL: "http://a/root", For: interA},
		fp(interB): {Cert: interB, URL: "http://b/inter", For: leafB},
		fp(rootB):  {Cert: rootB, URL: "http://b/root", For: interB},
	}

	names := func(certs []certops.RemoteCertInfo) []string {
		var out []string
		for _, ci := range certs {
			out = append(out, ci.Cert.Certificate.Subject.CommonName)
		}
		return out
	}
	var first []string
	for run := 0; run < 5; run++ {
		result := &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
			{Target: "a.example:443", Certs: served(leafA)},
			{Target: "b.example:443", Certs: served(leafB)},
		}}
		result = appendAIAToChains(result, provenance)

		gotA, gotB := names(result.TargetResults[0].Certs), names(result.TargetResults[1].Certs)
		wantA, wantB := []string{"a.example", "Inter A", "Root A"}, []string{"b.example", "Inter B", "Root B"}
		if !equalStrings(gotA, wantA) || !equalStrings(gotB, wantB) {
			t.Fatalf("run %d: A=%v B=%v, want %v and %v", run, gotA, gotB, wantA, wantB)
		}
		if first == nil {
			first = gotA
		} else if !equalStrings(first, gotA) {
			t.Fatalf("order changed between runs: %v vs %v", first, gotA)
		}
		for i, ci := range result.TargetResults[0].Certs {
			if i > 0 && ci.Role != "aia" {
				t.Errorf("fetched certificate %d must carry the aia role, got %q", i, ci.Role)
			}
		}
	}
}
