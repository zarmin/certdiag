package output

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"gopkg.in/yaml.v3"
)

func storeOf(name string, typ truststore.StoreType, path string, certs ...*x509.Certificate) truststore.StoreContents {
	return truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:      typ,
			Name:      name,
			Path:      path,
			CertCount: len(certs),
		},
		Certificates: certs,
	}
}

func rootCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return mustSelfSignedCert(t, mustGenECKey(t))
}

func leafOf(t *testing.T) *x509.Certificate {
	t.Helper()
	caKey := mustGenECKey(t)
	ca := mustSelfSignedCert(t, caKey)
	return mustLeafCert(t, mustGenECKey(t), ca, caKey)
}

// --- ClassifyCert ---

func TestClassifyCert_RootCA(t *testing.T) {
	if got := ClassifyCert(rootCert(t)); got != CategoryRootCA {
		t.Errorf("expected Root CA, got %q", got)
	}
}

func TestClassifyCert_ServerLeaf(t *testing.T) {
	if got := ClassifyCert(leafOf(t)); got != CategoryServer && got != CategoryLeaf {
		t.Errorf("expected a leaf category, got %q", got)
	}
}

func TestClassifyCert_IntermediateCA(t *testing.T) {
	caKey := mustGenECKey(t)
	ca := mustSelfSignedCert(t, caKey)

	// A CA that is not self-signed is an intermediate.
	inter := mustLeafCert(t, mustGenECKey(t), ca, caKey)
	inter.IsCA = true

	if got := ClassifyCert(inter); got != CategoryIntermediateCA {
		t.Errorf("expected Intermediate CA, got %q", got)
	}
}

// --- list view ---

func TestFormatStoreList_HeaderAndCount(t *testing.T) {
	out := FormatStoreList([]truststore.StoreContents{
		storeOf("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk/cacerts", rootCert(t), rootCert(t)),
	}, false, "")

	if !strings.Contains(out, "Java 21 (Temurin)") {
		t.Error("expected the store name in the output")
	}
	if !strings.Contains(out, "/jdk/cacerts") {
		t.Error("expected the store path in the output")
	}
	if !strings.Contains(out, "2 certs") {
		t.Errorf("expected the certificate count, got:\n%s", out)
	}
}

func TestFormatStoreList_EmptyStoreStillRendersHeader(t *testing.T) {
	out := FormatStoreList([]truststore.StoreContents{
		storeOf("Empty Store", truststore.StoreTypeCustom, "/tmp/empty.pem"),
	}, false, "")

	if !strings.Contains(out, "Empty Store") {
		t.Errorf("an empty store must still show its header, got:\n%s", out)
	}
	if !strings.Contains(out, "0 certs") {
		t.Errorf("expected a zero count, got:\n%s", out)
	}
}

func TestFormatStoreList_ShowsWarnings(t *testing.T) {
	sc := storeOf("Java 17", truststore.StoreTypeJava, "/jdk17/cacerts", rootCert(t))
	sc.Info.Warnings = []string{"jssecacerts detected -- Java uses jssecacerts instead of cacerts"}

	out := FormatStoreList([]truststore.StoreContents{sc}, false, "")
	if !strings.Contains(out, "jssecacerts") {
		t.Errorf("expected the store warning to be rendered, got:\n%s", out)
	}
}

func TestFormatStoreList_GroupsByCategory(t *testing.T) {
	out := FormatStoreList([]truststore.StoreContents{
		storeOf("Mixed", truststore.StoreTypeOS, "/kc", rootCert(t), leafOf(t)),
	}, false, "")

	if !strings.Contains(out, string(CategoryRootCA)) {
		t.Errorf("expected a Root CA section, got:\n%s", out)
	}
}

func TestFormatStoreList_DetailsAddsFields(t *testing.T) {
	sc := storeOf("Store", truststore.StoreTypeOS, "/kc", rootCert(t))

	plain := FormatStoreList([]truststore.StoreContents{sc}, false, "")
	detailed := FormatStoreList([]truststore.StoreContents{sc}, true, "")

	if len(detailed) <= len(plain) {
		t.Error("expected --details to add output")
	}
}

func TestFormatStoreList_MultipleStoresSeparated(t *testing.T) {
	out := FormatStoreList([]truststore.StoreContents{
		storeOf("Store A", truststore.StoreTypeOS, "/a", rootCert(t)),
		storeOf("Store B", truststore.StoreTypeJava, "/b", rootCert(t)),
	}, false, "")

	if !strings.Contains(out, "Store A") || !strings.Contains(out, "Store B") {
		t.Errorf("expected both stores, got:\n%s", out)
	}
}

// --- trust badges ---

func TestFormatTrustBadge_States(t *testing.T) {
	orig := ColorsEnabled
	ColorsEnabled = false
	t.Cleanup(func() { ColorsEnabled = orig })

	if got := formatTrustBadge(truststore.CertTrust{Overall: truststore.TrustTrusted}); got != "[Trusted]" {
		t.Errorf("expected [Trusted], got %q", got)
	}
	if got := formatTrustBadge(truststore.CertTrust{Overall: truststore.TrustDenied}); got != "[Denied]" {
		t.Errorf("expected [Denied], got %q", got)
	}
	if got := formatTrustBadge(truststore.CertTrust{Overall: truststore.TrustUnset}); got != "" {
		t.Errorf("expected no badge for Unset, got %q", got)
	}
}

func TestFormatTrustBadge_PartialPurposes(t *testing.T) {
	orig := ColorsEnabled
	ColorsEnabled = false
	t.Cleanup(func() { ColorsEnabled = orig })

	trust := truststore.CertTrust{
		Overall: truststore.TrustTrusted,
		Policies: []truststore.TrustPolicy{
			{Purpose: "SSL", Status: truststore.TrustTrusted},
			{Purpose: "S/MIME", Status: truststore.TrustDenied},
		},
	}

	got := formatTrustBadge(trust)
	if !strings.Contains(got, "SSL") {
		t.Errorf("expected the trusted purpose named, got %q", got)
	}
}

func TestTrustedPurposes(t *testing.T) {
	policies := []truststore.TrustPolicy{
		{Purpose: "SSL", Status: truststore.TrustTrusted},
		{Purpose: "S/MIME", Status: truststore.TrustDenied},
		{Purpose: "Code Signing", Status: truststore.TrustTrusted},
	}

	got := trustedPurposes(policies)
	if len(got) != 2 {
		t.Fatalf("expected 2 trusted purposes, got %v", got)
	}
}

// --- structured output ---

func TestFormatStoreJSON_Schema(t *testing.T) {
	out, err := FormatStoreJSON([]truststore.StoreContents{
		storeOf("Java 21", truststore.StoreTypeJava, "/jdk/cacerts", rootCert(t)),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output must be valid JSON: %v\n%s", err, out)
	}

	// These field names are the contract that -o json consumers depend on.
	rows, ok := parsed.([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected a one-element array, got %T:\n%s", parsed, out)
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("expected an object per certificate, got %T", rows[0])
	}
	for _, key := range []string{
		"subject", "subject_dn", "issuer", "serial", "not_before", "not_after",
		"algorithm", "sha256", "sha1", "category", "is_ca", "trust_status", "store", "store_path",
	} {
		if _, present := row[key]; !present {
			t.Errorf("missing contract field %q in:\n%s", key, out)
		}
	}
	if row["store"] != "Java 21" {
		t.Errorf("expected the store name attached to the cert, got %v", row["store"])
	}
	if row["store_path"] != "/jdk/cacerts" {
		t.Errorf("expected the store path attached to the cert, got %v", row["store_path"])
	}
}

func TestFormatStoreJSON_EmptyInput(t *testing.T) {
	out, err := FormatStoreJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("empty input must still produce valid JSON: %v (%q)", err, out)
	}
}

func TestFormatStoreYAML_Parses(t *testing.T) {
	out := FormatStoreYAML([]truststore.StoreContents{
		storeOf("OpenSSL", truststore.StoreTypeOpenSSL, "/etc/ssl/cert.pem", rootCert(t)),
	})

	var parsed any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output must be valid YAML: %v\n%s", err, out)
	}
}

func TestFormatStoreTable_NoPanic(t *testing.T) {
	out := FormatStoreTable([]truststore.StoreContents{
		storeOf("Store", truststore.StoreTypeOS, "/kc", rootCert(t), leafOf(t)),
	})
	if out == "" {
		t.Error("expected table output")
	}
}

func TestFormatStoreTable_EmptyStores(t *testing.T) {
	// Must not panic on an empty set.
	_ = FormatStoreTable(nil)
}

// --- discover output ---

func TestFormatDiscoverList(t *testing.T) {
	out := FormatDiscoverList([]truststore.StoreInfo{
		{Type: truststore.StoreTypeOS, Name: "macOS System Roots", Path: "/kc", CertCount: 148},
		{Type: truststore.StoreTypeJava, Name: "Java 17", Path: "/jdk17", CertCount: 91,
			Warnings: []string{"jssecacerts present"}},
	})

	if !strings.Contains(out, "macOS System Roots") || !strings.Contains(out, "Java 17") {
		t.Errorf("expected both stores listed, got:\n%s", out)
	}
	if !strings.Contains(out, "148") {
		t.Errorf("expected the certificate count, got:\n%s", out)
	}
	if !strings.Contains(out, "jssecacerts") {
		t.Errorf("expected the warning marker, got:\n%s", out)
	}
}

func TestFormatDiscoverJSON(t *testing.T) {
	out, err := FormatDiscoverJSON([]truststore.StoreInfo{
		{Type: truststore.StoreTypeOS, Name: "System", Path: "/kc", CertCount: 3},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("must be valid JSON: %v\n%s", err, out)
	}
}

func TestFormatDiscoverYAML(t *testing.T) {
	out := FormatDiscoverYAML([]truststore.StoreInfo{
		{Type: truststore.StoreTypeJava, Name: "Java 21", Path: "/jdk", CertCount: 90},
	})

	var parsed any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("must be valid YAML: %v\n%s", err, out)
	}
}

func TestFormatDiscoverList_Empty(t *testing.T) {
	// No stores found must not panic and must say something.
	_ = FormatDiscoverList(nil)
}
