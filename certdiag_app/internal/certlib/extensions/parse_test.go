package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are real public certificates (see testdata/SOURCES.md): parsing
// bytes we wrote ourselves would only prove the encoder and the decoder agree.

func loadFixture(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("fixture %s is not PEM", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return cert
}

func TestParse_SCTsOnACurrentLeaf(t *testing.T) {
	got := Parse(loadFixture(t, "sct-dv-letsencrypt-2026.pem"))

	if len(got.SCTs) < 2 {
		t.Fatalf("a publicly trusted leaf carries at least two SCTs, got %d", len(got.SCTs))
	}
	for _, sct := range got.SCTs {
		if len(sct.LogID) != 64 {
			t.Errorf("a log ID is a 32-byte hash, got %q", sct.LogID)
		}
		if sct.Timestamp.IsZero() {
			t.Error("every SCT carries when it was issued")
		}
		if sct.Version != 0 {
			t.Errorf("expected SCT v1 (encoded as 0), got %d", sct.Version)
		}
	}
	if got.IsPrecertificate {
		t.Error("a final certificate is not a precertificate")
	}
}

// TestParse_PrecertificateIsRecognised: a precertificate is not a usable
// certificate, and saying so is the difference between a confusing diff and an
// obvious one.
func TestParse_PrecertificateIsRecognised(t *testing.T) {
	pre := Parse(loadFixture(t, "precert-radiantlock-2019.pem"))
	if !pre.IsPrecertificate {
		t.Error("the poison extension marks a precertificate")
	}
	if len(pre.SCTs) != 0 {
		t.Error("a precertificate carries no SCTs; they are what it earns")
	}

	final := Parse(loadFixture(t, "sct-final-radiantlock-2019.pem"))
	if final.IsPrecertificate {
		t.Error("the final certificate of the pair is not poisoned")
	}
	if len(final.SCTs) == 0 {
		t.Error("the final certificate carries the SCTs")
	}
}

// TestParse_RetiredLogsStillDecode: the 2019 pair references logs that no
// longer run. An unknown log ID must decode and be shown, not dropped.
func TestParse_RetiredLogsStillDecode(t *testing.T) {
	got := Parse(loadFixture(t, "sct-final-radiantlock-2019.pem"))
	if len(got.SCTs) == 0 {
		t.Fatal("expected SCTs from retired logs")
	}
	for _, sct := range got.SCTs {
		if sct.LogID == "" {
			t.Error("an unknown log must still show its ID")
		}
		if sct.Timestamp.Year() < 2015 || sct.Timestamp.Year() > 2030 {
			t.Errorf("timestamp decoded implausibly: %v", sct.Timestamp)
		}
	}
}

func TestParse_QCStatements(t *testing.T) {
	got := Parse(loadFixture(t, "qc-qwac-agenciatributaria-sectigo.pem"))

	if len(got.QCStatements) == 0 {
		t.Fatal("a qualified website certificate carries qcStatements")
	}
	var named int
	for _, s := range got.QCStatements {
		if s.OID == "" {
			t.Error("every statement has an OID")
		}
		if s.Name != "" {
			named++
		}
	}
	if named == 0 {
		t.Errorf("at least the eIDAS statements should be named, got %+v", got.QCStatements)
	}
}

// TestParse_PolicyConstraintsAndInhibit: real bridge-PKI certificates, which is
// where these extensions actually live.
func TestParse_PolicyConstraintsAndInhibit(t *testing.T) {
	got := Parse(loadFixture(t, "fpki-fbca-g4-from-certipath.pem"))

	if got.PolicyConstraints == nil {
		t.Fatal("this cross-certificate carries policy constraints")
	}
	if got.PolicyConstraints.String() == "" {
		t.Error("the constraint must render as something readable")
	}
	if got.InhibitAnyPolicy == nil {
		t.Error("this certificate also inhibits anyPolicy")
	}
}

// TestParse_ResidueListsWhatIsNotDecoded is Tier 0: anything certdiag does not
// render elsewhere must still be visible.
func TestParse_ResidueListsWhatIsNotDecoded(t *testing.T) {
	cert := loadFixture(t, "fpki-fbca-g4-from-certipath.pem")
	got := Parse(cert)

	if len(got.Other) == 0 {
		t.Fatal("this certificate carries extensions certdiag does not decode (SIA, policy mappings)")
	}
	for _, r := range got.Other {
		if r.OID == "" {
			t.Error("a residue entry must carry its OID")
		}
		if r.Length == 0 {
			t.Error("a residue entry must say how much data it holds")
		}
		if typedElsewhere[r.OID] {
			t.Errorf("%s is rendered elsewhere and must not also appear as residue", r.OID)
		}
	}

	var named bool
	for _, r := range got.Other {
		if r.Name != "" {
			named = true
		}
	}
	if !named {
		t.Error("a known OID must be shown by name, not only as a number")
	}
}

// TestParse_EveryFixtureIsAccountedFor: no extension may vanish. Each is either
// decoded into a field or listed in the residue.
func TestParse_EveryFixtureIsAccountedFor(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		cert := loadFixture(t, e.Name())
		got := Parse(cert)

		residue := make(map[string]bool)
		for _, r := range got.Other {
			residue[r.OID] = true
		}
		for _, ext := range cert.Extensions {
			id := ext.Id.String()
			if typedElsewhere[id] || residue[id] {
				continue
			}
			t.Errorf("%s: extension %s is neither decoded nor listed", e.Name(), id)
		}
	}
}

func TestParse_NilAndEmpty(t *testing.T) {
	if got := Parse(nil); len(got.Other) != 0 || got.IsPrecertificate {
		t.Error("a nil certificate must parse to nothing, not panic")
	}
	if got := Parse(&x509.Certificate{}); len(got.Other) != 0 {
		t.Error("a certificate with no extensions has no residue")
	}
}

func TestParse_MalformedIsNotFatal(t *testing.T) {
	cert := &x509.Certificate{Extensions: []pkix.Extension{
		{Id: OIDSCTList, Value: []byte{0xff, 0xff, 0xff}},
		{Id: OIDQCStatements, Value: []byte("garbage")},
		{Id: OIDTLSFeature, Value: []byte{0x01}},
		{Id: OIDPolicyConstraints, Value: []byte{0x99}},
	}}
	got := Parse(cert)
	// The point is that it returned at all.
	if got.MustStaple {
		t.Error("garbage must not decode into a feature")
	}
}

func TestName_And_Known(t *testing.T) {
	if Name(OIDSCTList) == "" {
		t.Error("the SCT list must be named")
	}
	if !Known(OIDPrecertPoison) {
		t.Error("the poison extension is known; unknown_ext must not fire on it")
	}
	if Known(asn1OID(t, "1.2.3.4.5.6.7.8.9")) {
		t.Error("an arbitrary OID is not known")
	}
	if PolicyName(asn1OID(t, "2.23.140.1.2.1")) == "" {
		t.Error("the CA/B DV policy must be named")
	}
}

func asn1OID(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	var out asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}
