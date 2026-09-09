package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// edgeFixture reads one file from testdata/edge (tools/testing/gen_edge_certs.sh).
func edgeFixture(t *testing.T, name string) (*CertContainer, error) {
	t.Helper()
	path := filepath.Join("testdata", "edge", name)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	return ReadFile(path, nil)
}

func edgeCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	c, err := edgeFixture(t, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, it := range c.Items {
		if it.Type == ContentCertificate && it.Certificate != nil {
			return it.Certificate
		}
	}
	t.Fatalf("%s: no certificate parsed (errors %v)", name, c.ParseErrors)
	return nil
}

func edgeCheckIDs(t *testing.T, c *CertContainer) map[string]bool {
	t.Helper()
	store := NewCertStore()
	store.AddContainer(*c)
	res := RunChecks(store, nil, CheckOptions{})
	ids := map[string]bool{}
	for _, is := range res.Issues {
		ids[is.CheckID] = true
	}
	return ids
}

// TestEdgeFixtures_ParseAndCheck runs every edge certificate through the reader
// and the checks (M31 WP12): none may panic, and what a fixture is about must
// be visible.
func TestEdgeFixtures_ParseAndCheck(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "edge"))
	if err != nil {
		t.Skipf("no edge fixtures: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".crt") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			c, err := edgeFixture(t, e.Name())
			if err != nil {
				if e.Name() == "negative-serial.crt" {
					if !strings.Contains(err.Error(), "serial") {
						t.Errorf("a negative serial must be reported as such, got %v", err)
					}
					return
				}
				t.Fatalf("read: %v", err)
			}
			if len(c.Items) == 0 && len(c.ParseErrors) == 0 {
				t.Fatal("neither items nor parse errors")
			}
			edgeCheckIDs(t, c)
		})
	}
}

func TestEdgeFixtures_Specifics(t *testing.T) {
	if cert := edgeCert(t, "many-sans.crt"); len(cert.DNSNames) != 300 {
		t.Errorf("many-sans: %d DNS names, want 300", len(cert.DNSNames))
	}
	if cert := edgeCert(t, "notafter-9999.crt"); cert.NotAfter.Year() != 9999 {
		t.Errorf("notafter-9999: NotAfter %v", cert.NotAfter)
	} else {
		c, _ := edgeFixture(t, "notafter-9999.crt")
		if ids := edgeCheckIDs(t, c); !ids["long_validity"] {
			t.Errorf("a validity to 9999 must trip long_validity, got %v", ids)
		}
	}
	if cert := edgeCert(t, "non-ascii-dn.crt"); !strings.Contains(cert.Subject.String(), "测试") {
		t.Errorf("non-ascii-dn: subject %q lost its characters", cert.Subject.String())
	}
	if cert := edgeCert(t, "trailing-dot-san.crt"); len(cert.DNSNames) != 1 || cert.DNSNames[0] != "trailing.edge.test." {
		t.Errorf("trailing-dot-san: DNS names %v", cert.DNSNames)
	}
	if cert := edgeCert(t, "duplicate-sans.crt"); len(cert.DNSNames) != 2 || len(cert.IPAddresses) != 2 {
		t.Errorf("duplicate-sans: %v %v (duplicates are kept as served)", cert.DNSNames, cert.IPAddresses)
	}
	if cert := edgeCert(t, "dsa.crt"); cert.PublicKeyAlgorithm != x509.DSA {
		t.Errorf("dsa: algorithm %v", cert.PublicKeyAlgorithm)
	}
	if cert := edgeCert(t, "rsa-pss.crt"); cert.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		t.Errorf("rsa-pss: signature algorithm %v", cert.SignatureAlgorithm)
	}
	c, _ := edgeFixture(t, "critical-unknown-ext.crt")
	if ids := edgeCheckIDs(t, c); !ids["unknown_ext"] {
		t.Errorf("a critical unknown extension must trip unknown_ext, got %v", ids)
	}
	edgeCert(t, "precert.crt")
	edgeCert(t, "dirname-constraints.crt")
	edgeCert(t, "ed448.crt")
}

// TestV1Certificate builds an X.509 v1 certificate by hand (Go and OpenSSL 3
// only produce v3) and checks it is parsed and flagged.
func TestV1Certificate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	var spkiVal asn1.RawValue
	asn1.Unmarshal(spki, &spkiVal)
	name := pkix.Name{CommonName: "v1.edge.test"}
	nameDER, _ := asn1.Marshal(name.ToRDNSequence())
	var nameVal asn1.RawValue
	asn1.Unmarshal(nameDER, &nameVal)
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}} // ecdsa-with-SHA256

	type validity struct{ NotBefore, NotAfter time.Time }
	type tbs struct {
		// Version omitted: DEFAULT v1.
		SerialNumber *big.Int
		Signature    pkix.AlgorithmIdentifier
		Issuer       asn1.RawValue
		Validity     validity
		Subject      asn1.RawValue
		PublicKey    asn1.RawValue
	}
	now := time.Now().UTC().Truncate(time.Second)
	tbsDER, err := asn1.Marshal(tbs{
		SerialNumber: big.NewInt(7), Signature: sigAlg, Issuer: nameVal,
		Validity: validity{now.Add(-time.Hour), now.Add(24 * time.Hour)}, Subject: nameVal, PublicKey: spkiVal,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, digest[:])
	certDER, _ := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, sigAlg, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})

	path := filepath.Join(t.TempDir(), "v1.der")
	os.WriteFile(path, certDER, 0o600)
	c, err := ReadFile(path, nil)
	if err != nil {
		t.Fatalf("read v1: %v", err)
	}
	if len(c.Items) != 1 || c.Items[0].Certificate == nil || c.Items[0].Certificate.Version != 1 {
		t.Fatalf("expected one v1 certificate, got %+v", c.Items)
	}
	if ids := edgeCheckIDs(t, c); !ids["version"] {
		t.Errorf("a v1 certificate must trip the version check, got %v", ids)
	}
}
