package certops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// storeTestCert builds a self-signed cert quickly (ECDSA, not RSA) since the
// store tests need many of them.
func storeTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	return storeTestCertOrg(t, cn, "")
}

func storeTestCertOrg(t *testing.T, cn, org string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: cn}
	if org != "" {
		subject.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func storeFixture(name string, typ truststore.StoreType, path string, certs ...*x509.Certificate) truststore.StoreContents {
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

// --- instance grouping ---

func TestSynthesize_InstanceGrouping(t *testing.T) {
	a := storeTestCert(t, "Root A")
	b := storeTestCert(t, "Root B")

	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/System/keychain", a),
		storeFixture("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21/cacerts", a, b),
		storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/etc/ssl/cert.pem", b),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByInstance})

	if len(cs.Containers) != 3 {
		t.Fatalf("expected one container per store, got %d", len(cs.Containers))
	}
	wantNames := []string{"macOS System Roots", "Java 21 (Temurin)", "OpenSSL"}
	for i, want := range wantNames {
		if cs.Containers[i].Label != want {
			t.Errorf("container %d: expected label %q, got %q", i, want, cs.Containers[i].Label)
		}
	}
	if len(cs.Containers[1].Items) != 2 {
		t.Errorf("expected 2 items in the Java store, got %d", len(cs.Containers[1].Items))
	}
}

func TestSynthesize_ContainerFields(t *testing.T) {
	cert := storeTestCert(t, "Field Root")
	stores := []truststore.StoreContents{
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk/cacerts", cert),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByInstance})
	c := cs.Containers[0]

	if c.Source != certlib.SourceTrustStore {
		t.Errorf("expected SourceTrustStore, got %q", c.Source)
	}
	if c.Label != "Java 21" {
		t.Errorf("expected the store name as label, got %q", c.Label)
	}
	if c.FilePath != "/jdk/cacerts" {
		t.Errorf("expected the store path, got %q", c.FilePath)
	}
	if c.Format != certlib.FormatJKS {
		t.Errorf("expected JKS format for a Java store, got %q", c.Format)
	}
}

func TestSynthesize_FormatPerKind(t *testing.T) {
	cert := storeTestCert(t, "Format Root")

	tests := []struct {
		name string
		typ  truststore.StoreType
		path string
		want certlib.FileFormat
	}{
		{"java", truststore.StoreTypeJava, "/jdk/cacerts", certlib.FormatJKS},
		{"openssl", truststore.StoreTypeOpenSSL, "/etc/ssl/cert.pem", certlib.FormatPEM},
		{"linux pem", truststore.StoreTypeOS, "/etc/ssl/certs/ca-certificates.crt", certlib.FormatPEM},
		{"macos keychain", truststore.StoreTypeOS, "/System/Library/Keychains/SystemRootCertificates.keychain", certlib.FormatDER},
		{"windows store", truststore.StoreTypeOS, "ROOT", certlib.FormatDER},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := SynthesizeCertStore(
				[]truststore.StoreContents{storeFixture("s", tt.typ, tt.path, cert)},
				SynthOptions{Grouping: GroupByInstance},
			)
			if got := cs.Containers[0].Format; got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestSynthesize_EmptyStoreKept(t *testing.T) {
	stores := []truststore.StoreContents{
		{Info: truststore.StoreInfo{
			Type:     truststore.StoreTypeJava,
			Name:     "Java 21 (locked)",
			Path:     "/jdk/cacerts",
			Warnings: []string{"read error: bad password"},
		}},
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByInstance})

	if len(cs.Containers) != 1 {
		t.Fatalf("a failed store must still appear, got %d containers", len(cs.Containers))
	}
	if len(cs.Containers[0].Items) != 0 {
		t.Errorf("expected no items, got %d", len(cs.Containers[0].Items))
	}
	if len(cs.Containers[0].ParseErrors) != 1 {
		t.Errorf("expected the failure to be preserved, got %v", cs.Containers[0].ParseErrors)
	}
}

func TestSynthesize_ZeroCertStoreNoErrors(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("Empty Bundle", truststore.StoreTypeCustom, "/tmp/empty.pem"),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByInstance})
	if len(cs.Containers) != 1 {
		t.Fatalf("expected the empty store to be kept, got %d", len(cs.Containers))
	}
	if len(cs.Containers[0].ParseErrors) != 0 {
		t.Errorf("a store that read fine must have no errors, got %v", cs.Containers[0].ParseErrors)
	}
}

func TestSynthesize_ItemRawBytesArePreserved(t *testing.T) {
	cert := storeTestCert(t, "Raw Root")
	cs := SynthesizeCertStore(
		[]truststore.StoreContents{storeFixture("s", truststore.StoreTypeOS, "/p", cert)},
		SynthOptions{Grouping: GroupByInstance},
	)

	item := cs.Containers[0].Items[0]
	if item.Type != certlib.ContentCertificate {
		t.Errorf("expected a certificate item, got %q", item.Type)
	}
	if string(item.RawBytes) != string(cert.Raw) {
		t.Error("RawBytes must be the original DER so export writes it unchanged")
	}
}

func TestSynthesize_DeterministicOrder(t *testing.T) {
	certs := []*x509.Certificate{
		storeTestCert(t, "R1"), storeTestCert(t, "R2"), storeTestCert(t, "R3"),
	}
	stores := []truststore.StoreContents{
		storeFixture("A", truststore.StoreTypeOS, "/a", certs...),
		storeFixture("B", truststore.StoreTypeJava, "/b", certs...),
	}

	first := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})
	second := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})

	if len(first.Containers) != len(second.Containers) {
		t.Fatal("container count differs between identical runs")
	}
	for i := range first.Containers {
		if first.Containers[i].Label != second.Containers[i].Label {
			t.Fatalf("container order not deterministic at %d", i)
		}
		for j := range first.Containers[i].Items {
			if first.Containers[i].Items[j].Alias != second.Containers[i].Items[j].Alias {
				t.Fatalf("item order not deterministic at %d/%d", i, j)
			}
		}
	}
}

// --- aliases ---

func TestSynthesize_AliasFromCN(t *testing.T) {
	cert := storeTestCert(t, "DigiCert Global Root G2")
	cs := SynthesizeCertStore(
		[]truststore.StoreContents{storeFixture("s", truststore.StoreTypeOS, "/p", cert)},
		SynthOptions{Grouping: GroupByInstance},
	)

	if got := cs.Containers[0].Items[0].Alias; got != "DigiCert Global Root G2" {
		t.Errorf("expected the CN as alias, got %q", got)
	}
}

func TestSynthesize_AliasFallsBackToOrg(t *testing.T) {
	cert := storeTestCertOrg(t, "", "Example Organisation")
	cs := SynthesizeCertStore(
		[]truststore.StoreContents{storeFixture("s", truststore.StoreTypeOS, "/p", cert)},
		SynthOptions{Grouping: GroupByInstance},
	)

	if got := cs.Containers[0].Items[0].Alias; got != "Example Organisation" {
		t.Errorf("expected the O as alias, got %q", got)
	}
}

func TestSynthesize_AliasFallsBackToFingerprint(t *testing.T) {
	cert := storeTestCertOrg(t, "", "")
	cs := SynthesizeCertStore(
		[]truststore.StoreContents{storeFixture("s", truststore.StoreTypeOS, "/p", cert)},
		SynthOptions{Grouping: GroupByInstance},
	)

	alias := cs.Containers[0].Items[0].Alias
	if alias == "" {
		t.Fatal("alias must never be empty")
	}
	if len(alias) != 16 {
		t.Errorf("expected a 16-char fingerprint prefix, got %q", alias)
	}
}

func TestSynthesize_AliasCollisionDisambiguated(t *testing.T) {
	// Two genuinely different certs sharing a CN, which happens in real root
	// stores (rolled-over roots keep the same name).
	a := storeTestCert(t, "GlobalSign Root CA")
	b := storeTestCert(t, "GlobalSign Root CA")

	cs := SynthesizeCertStore(
		[]truststore.StoreContents{storeFixture("s", truststore.StoreTypeOS, "/p", a, b)},
		SynthOptions{Grouping: GroupByInstance},
	)

	items := cs.Containers[0].Items
	if len(items) != 2 {
		t.Fatalf("expected both certs, got %d", len(items))
	}
	if items[0].Alias == items[1].Alias {
		t.Errorf("aliases must be unique within a store, both were %q", items[0].Alias)
	}
	if !strings.Contains(items[1].Alias, "#2") {
		t.Errorf("expected the second to be suffixed, got %q", items[1].Alias)
	}
}

// --- kind grouping ---

func TestSynthesize_KindGrouping(t *testing.T) {
	a := storeTestCert(t, "Root A")
	b := storeTestCert(t, "Root B")

	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc1", a),
		storeFixture("macOS Login Keychain", truststore.StoreTypeOS, "/kc2", b),
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", a),
		storeFixture("Java 17", truststore.StoreTypeJava, "/jdk17", a),
		storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", b),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})

	if len(cs.Containers) != 3 {
		t.Fatalf("expected 3 kind groups, got %d", len(cs.Containers))
	}
	if !strings.HasPrefix(cs.Containers[0].Label, "System") {
		t.Errorf("expected the System group first, got %q", cs.Containers[0].Label)
	}
	if !strings.HasPrefix(cs.Containers[1].Label, "Java") {
		t.Errorf("expected the Java group second, got %q", cs.Containers[1].Label)
	}
	if cs.Containers[2].Label != "OpenSSL" {
		t.Errorf("expected OpenSSL third, got %q", cs.Containers[2].Label)
	}
}

func TestSynthesize_KindDedup(t *testing.T) {
	shared := storeTestCert(t, "Shared Root")
	onlyIn21 := storeTestCert(t, "Only in 21")

	stores := []truststore.StoreContents{
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", shared, onlyIn21),
		storeFixture("Java 17", truststore.StoreTypeJava, "/jdk17", shared),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})

	if len(cs.Containers) != 1 {
		t.Fatalf("expected one Java group, got %d", len(cs.Containers))
	}
	if len(cs.Containers[0].Items) != 2 {
		t.Fatalf("expected the shared root once (2 unique), got %d", len(cs.Containers[0].Items))
	}
}

func TestSynthesize_KindLabelNamesInstanceCount(t *testing.T) {
	shared := storeTestCert(t, "Shared Root")
	stores := []truststore.StoreContents{
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
		storeFixture("Java 17", truststore.StoreTypeJava, "/jdk17", shared),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})

	if !strings.Contains(cs.Containers[0].Label, "2 stores") {
		t.Errorf("expected the merged label to name the instance count, got %q", cs.Containers[0].Label)
	}
	// The raw-vs-unique difference is surfaced so the count is not misleading.
	joined := strings.Join(cs.Containers[0].ParseErrors, " ")
	if !strings.Contains(joined, "unique") {
		t.Errorf("expected a note about deduplication, got %v", cs.Containers[0].ParseErrors)
	}
}

func TestSynthesize_InstanceModeDoesNotDedup(t *testing.T) {
	shared := storeTestCert(t, "Shared Root")
	stores := []truststore.StoreContents{
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
		storeFixture("Java 17", truststore.StoreTypeJava, "/jdk17", shared),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByInstance})

	if len(cs.Containers) != 2 {
		t.Fatalf("expected both stores, got %d", len(cs.Containers))
	}
	for i, c := range cs.Containers {
		if len(c.Items) != 1 {
			t.Errorf("store %d: expected its literal contents, got %d items", i, len(c.Items))
		}
	}
}

func TestSynthesize_CustomFilesGroupUnderCustom(t *testing.T) {
	cert := storeTestCert(t, "Bundle Root")
	stores := []truststore.StoreContents{
		storeFixture("ca-bundle.pem", truststore.StoreTypeCustom, "/tmp/ca-bundle.pem", cert),
	}

	cs := SynthesizeCertStore(stores, SynthOptions{Grouping: GroupByKind})
	if cs.Containers[0].Label != "Custom" {
		t.Errorf("expected the Custom kind group, got %q", cs.Containers[0].Label)
	}
}

func TestSynthesize_NoStores(t *testing.T) {
	for _, g := range []StoreGrouping{GroupByInstance, GroupByKind} {
		cs := SynthesizeCertStore(nil, SynthOptions{Grouping: g})
		if cs == nil {
			t.Fatalf("%s: expected a store, got nil", g)
		}
		if len(cs.Containers) != 0 {
			t.Errorf("%s: expected no containers, got %d", g, len(cs.Containers))
		}
	}
}

// --- grouping value handling ---

func TestParseStoreGrouping(t *testing.T) {
	tests := map[string]StoreGrouping{
		"kind":     GroupByKind,
		"KIND":     GroupByKind,
		" kind ":   GroupByKind,
		"instance": GroupByInstance,
		"":         GroupByInstance,
		"bogus":    GroupByInstance,
	}
	for in, want := range tests {
		if got := ParseStoreGrouping(in); got != want {
			t.Errorf("ParseStoreGrouping(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStoreGrouping_NextCycles(t *testing.T) {
	g := GroupByInstance
	if g = g.Next(); g != GroupByKind {
		t.Fatalf("expected kind, got %q", g)
	}
	if g = g.Next(); g != GroupByInstance {
		t.Fatalf("expected instance, got %q", g)
	}
}
