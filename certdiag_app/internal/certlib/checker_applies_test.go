package certlib

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEveryCheckDeclaresWhatItAppliesTo is the registry rule behind M31 R10:
// a check without AppliesTo would never run (the runner skips it), so a
// missing declaration is caught here rather than as silence in the field.
func TestEveryCheckDeclaresWhatItAppliesTo(t *testing.T) {
	for _, def := range AllChecks() {
		if len(def.AppliesTo) == 0 {
			t.Errorf("check %q declares no AppliesTo", def.ID)
		}
		for _, k := range def.AppliesTo {
			switch k {
			case KindLeaf, KindCA, KindKey, KindCSR:
			default:
				t.Errorf("check %q has unknown kind %q", def.ID, k)
			}
		}
	}
}

// TestRunnerSkipsChecksThatDoNotApply runs the full runner over a CA, a leaf
// and a key and asserts the leaf-only and key-only checks stay quiet on the
// other kinds (M2 and its siblings).
func TestRunnerSkipsChecksThatDoNotApply(t *testing.T) {
	ca, caKey := guardCA(t)
	leaf := guardLeaf(t, ca, caKey)
	key := mustGenerateECKey(t)

	items := map[ItemKind]CertItem{
		KindCA:   {Type: ContentCertificate, Certificate: ca, RawBytes: ca.Raw},
		KindLeaf: {Type: ContentCertificate, Certificate: leaf, RawBytes: leaf.Raw},
		KindKey:  {Type: ContentPrivateKey, PrivateKey: key},
	}
	for kind, item := range items {
		store := NewCertStore()
		store.Containers = append(store.Containers, CertContainer{
			FilePath: "/tmp/" + string(kind) + ".pem", Format: FormatPEM, Items: []CertItem{item},
		})
		res := RunChecks(store, BuildRelationIndex(nil, store), CheckOptions{})
		for _, is := range res.Issues {
			var def CheckDefinition
			for _, d := range AllChecks() {
				if d.ID == is.CheckID {
					def = d
				}
			}
			if !def.appliesTo(kind) {
				t.Errorf("%s fired on a %s item although it applies to %v", is.CheckID, kind, def.AppliesTo)
			}
		}
	}
}

// TestLeafValidityLimitSchedule pins the CA/B Forum SC-081 schedule (H7).
func TestLeafValidityLimitSchedule(t *testing.T) {
	cases := []struct {
		issued string
		want   int
	}{
		{"2017-01-01", 825},
		{"2019-06-01", 825},
		{"2020-09-01", 398},
		{"2025-12-01", 398},
		{"2026-03-14", 398},
		{"2026-03-15", 200},
		{"2026-09-07", 200},
		{"2027-03-15", 100},
		{"2029-03-15", 47},
		{"2031-01-01", 47},
	}
	for _, tc := range cases {
		issued, _ := time.Parse("2006-01-02", tc.issued)
		if got, _ := LeafValidityLimit(issued); got != tc.want {
			t.Errorf("issued %s: limit %d, want %d", tc.issued, got, tc.want)
		}
	}
}

// TestNameConstraintsViolation_TwoLevelsUp: RFC 5280 applies every ancestor's
// constraints, not only the direct issuer's (M3).
func TestNameConstraintsViolation_TwoLevelsUp(t *testing.T) {
	root, rootKey := ncCA(t, "Constrained Root", NameConstraints{PermittedDNS: []string{"example.com"}})
	inter, interKey := extCert(t, "Unconstrained Intermediate", true, root, rootKey, nil, -1)
	bad := ncLeaf(t, inter, interKey, "www.evil.test", SANList{DNSNames: []string{"www.evil.test"}})
	good := ncLeaf(t, inter, interKey, "www.example.com", SANList{DNSNames: []string{"www.example.com"}})

	found := runExtChecks(t, extStore(t, root, inter, bad))
	is, ok := found["name_constraints_violation"]
	if !ok {
		t.Fatalf("no violation reported two levels below the constrained root; got %v", keysOf(found))
	}
	if !strings.Contains(is.Message, "Constrained Root") {
		t.Errorf("message should name the ancestor whose constraint was broken: %q", is.Message)
	}
	if depth, _ := is.Details["depth"].(int); depth != 2 {
		t.Errorf("depth = %v, want 2", is.Details["depth"])
	}

	if _, ok := runExtChecks(t, extStore(t, root, inter, good))["name_constraints_violation"]; ok {
		t.Error("a leaf inside the root's permitted domain must not be flagged")
	}
}

// TestCheckNameConstraints_URI: URI constraints were written on CA creation
// but never enforced at sign time (M3).
func TestCheckNameConstraints_URI(t *testing.T) {
	ca, _ := ncCA(t, "URI CA", NameConstraints{PermittedURI: []string{"example.com"}})
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	if err := CheckNameConstraints(ca, "", SANList{URIs: []*url.URL{mustURL("https://api.example.com/x")}}); err != nil {
		t.Errorf("permitted URI rejected: %v", err)
	}
	if err := CheckNameConstraints(ca, "", SANList{URIs: []*url.URL{mustURL("https://evil.test/x")}}); err == nil {
		t.Error("URI outside the permitted domain was accepted")
	}
	if err := CheckNameConstraints(ca, "", SANList{URIs: []*url.URL{mustURL("https://10.0.0.1/x")}}); err == nil {
		t.Error("an IP-host URI cannot satisfy a URI domain constraint")
	}
	if len(ca.PermittedURIDomains) != 1 {
		t.Fatalf("test CA lost its URI constraint: %v", ca.PermittedURIDomains)
	}
	_ = x509.KeyUsageCertSign
}
