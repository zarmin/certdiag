package certops

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// --- matchesCert / filterStoreContents (M16) ---

func TestMatchesCert_CommonName(t *testing.T) {
	cert := storeTestCert(t, "DigiCert Global Root G2")

	if !matchesCert(cert, "digicert") {
		t.Error("expected a CN substring to match")
	}
	if !matchesCert(cert, "root g2") {
		t.Error("expected a multi-word CN substring to match")
	}
	if matchesCert(cert, "letsencrypt") {
		t.Error("did not expect an unrelated query to match")
	}
}

func TestMatchesCert_Organization(t *testing.T) {
	cert := storeTestCertOrg(t, "Some Root", "Internet Security Research Group")

	if !matchesCert(cert, "internet security") {
		t.Error("expected the O field to be searched")
	}
}

func TestMatchesCert_Serial(t *testing.T) {
	cert := storeTestCert(t, "Serial Root")
	serialHex := strings.ToLower(cert.SerialNumber.Text(16))

	if !matchesCert(cert, serialHex) {
		t.Errorf("expected the hex serial %q to match", serialHex)
	}
}

func TestMatchesCert_QueryIsLowercased(t *testing.T) {
	cert := storeTestCert(t, "MixedCase Root")

	// The caller lowercases the query; the cert fields are lowercased inside.
	if !matchesCert(cert, "mixedcase") {
		t.Error("expected case-insensitive matching")
	}
}

func TestFilterStoreContents_UpdatesCount(t *testing.T) {
	sc := storeFixture("OS", truststore.StoreTypeOS, "/kc",
		storeTestCert(t, "DigiCert Root"),
		storeTestCert(t, "GlobalSign Root"),
		storeTestCert(t, "DigiCert Assured ID"),
	)

	got := filterStoreContents(sc, "digicert")

	if len(got.Certificates) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(got.Certificates))
	}
	if got.Info.CertCount != 2 {
		t.Errorf("CertCount must track the filtered set, got %d", got.Info.CertCount)
	}
}

func TestFilterStoreContents_NoMatchIsEmptyNotError(t *testing.T) {
	sc := storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "Only Root"))

	got := filterStoreContents(sc, "nothing-matches-this")

	if len(got.Certificates) != 0 {
		t.Errorf("expected no matches, got %d", len(got.Certificates))
	}
	if got.Info.CertCount != 0 {
		t.Errorf("expected CertCount 0, got %d", got.Info.CertCount)
	}
	if got.Info.Name != "OS" {
		t.Error("filtering must preserve the store identity")
	}
}

// --- readCustomStore (M16) ---

func writeBundle(t *testing.T, path string, certs ...*bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	for _, c := range certs {
		out.Write(c.Bytes())
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pemOf(t *testing.T, cn string) *bytes.Buffer {
	t.Helper()
	cert := storeTestCert(t, cn)
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestReadCustomStore_PEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	writeBundle(t, path, pemOf(t, "Root One"), pemOf(t, "Root Two"))

	sc, err := readCustomStore(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(sc.Certificates))
	}
	if sc.Info.Type != truststore.StoreTypeCustom {
		t.Errorf("expected a custom store, got %q", sc.Info.Type)
	}
	if sc.Info.Path != path {
		t.Errorf("expected the path recorded, got %q", sc.Info.Path)
	}
}

func TestReadCustomStore_MissingFile(t *testing.T) {
	if _, err := readCustomStore(filepath.Join(t.TempDir(), "nope.pem"), nil); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestReadCustomStore_NotACertFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(path, []byte("just some text, definitely not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Must fail cleanly rather than panic.
	if _, err := readCustomStore(path, nil); err == nil {
		t.Fatal("expected an error for a non-certificate file")
	}
}

func TestReadCustomStore_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	sc, err := readCustomStore(path, nil)
	if err == nil && len(sc.Certificates) != 0 {
		t.Errorf("an empty file must yield no certificates, got %d", len(sc.Certificates))
	}
}

// --- StoreList / StoreDiscover (M16) ---

func TestStoreList_UnknownStoreType(t *testing.T) {
	_, err := StoreList(StoreListOptions{StoreType: truststore.StoreType("nonsense")})
	if err == nil {
		t.Fatal("expected an error for an unknown store type")
	}
	if !strings.Contains(err.Error(), "unknown store type") {
		t.Errorf("expected a clear message, got %q", err.Error())
	}
}

func TestStoreList_CustomRequiresPath(t *testing.T) {
	_, err := StoreList(StoreListOptions{StoreType: truststore.StoreTypeCustom})
	if err == nil {
		t.Fatal("expected an error when --trust-file is missing")
	}
	if !strings.Contains(err.Error(), "--trust-file") {
		t.Errorf("expected the message to name --trust-file, got %q", err.Error())
	}
}

func TestStoreList_CustomWithQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.pem")
	writeBundle(t, path, pemOf(t, "DigiCert Root"), pemOf(t, "GlobalSign Root"))

	result, err := StoreList(StoreListOptions{
		StoreType: truststore.StoreTypeCustom,
		FilePath:  path,
		Query:     "digicert",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stores) != 1 {
		t.Fatalf("expected one store, got %d", len(result.Stores))
	}
	if len(result.Stores[0].Certificates) != 1 {
		t.Errorf("expected the query to filter to 1, got %d", len(result.Stores[0].Certificates))
	}
}

// --- ExportCertificate / CertExportName (M28) ---

func TestExportCertificate_PEM(t *testing.T) {
	cert := storeTestCert(t, "Export Root")
	path := filepath.Join(t.TempDir(), "out.pem")

	if err := ExportCertificate(cert, path, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected a PEM certificate")
	}
	if !bytes.Equal(block.Bytes, cert.Raw) {
		t.Error("exported DER must match the original")
	}
}

func TestExportCertificate_DERFromExtension(t *testing.T) {
	cert := storeTestCert(t, "DER Root")
	path := filepath.Join(t.TempDir(), "out.der")

	if err := ExportCertificate(cert, path, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, cert.Raw) {
		t.Error("expected raw DER for a .der extension")
	}
}

func TestExportCertificate_UnknownExtensionDefaultsToPEM(t *testing.T) {
	cert := storeTestCert(t, "Default Root")
	path := filepath.Join(t.TempDir(), "out.unknown")

	if err := ExportCertificate(cert, path, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block == nil {
		t.Error("expected PEM as the default format")
	}
}

func TestExportCertificate_NilCert(t *testing.T) {
	if err := ExportCertificate(nil, filepath.Join(t.TempDir(), "x.pem"), true); err == nil {
		t.Fatal("expected an error for a nil certificate")
	}
}

func TestCertExportName(t *testing.T) {
	if got := CertExportName(storeTestCert(t, "DigiCert Global Root G2")); got == "" {
		t.Fatal("expected a name")
	} else if strings.ContainsAny(got, `/\:*?"<>|`) {
		t.Errorf("export name must be filesystem-safe, got %q", got)
	}

	if got := CertExportName(storeTestCertOrg(t, "", "Example Org")); !strings.Contains(strings.ToLower(got), "example") {
		t.Errorf("expected the O as fallback, got %q", got)
	}

	if got := CertExportName(nil); got != "certificate" {
		t.Errorf("expected a safe default for nil, got %q", got)
	}
}

func TestCertExportName_EmptySubjectFallsBackToSerial(t *testing.T) {
	cert := storeTestCertOrg(t, "", "")
	if got := CertExportName(cert); got == "" {
		t.Error("expected a serial-derived name, got empty")
	}
}

// --- ReadCertificatesFromFile (M28) ---

func TestReadCertificatesFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.pem")
	writeBundle(t, path, pemOf(t, "Leaf"), pemOf(t, "Issuer"))

	certs, err := ReadCertificatesFromFile(path, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestReadCertificatesFromFile_Missing(t *testing.T) {
	if _, err := ReadCertificatesFromFile(filepath.Join(t.TempDir(), "nope.pem"), nil); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestReadCertificatesFromFile_NoCertificates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadCertificatesFromFile(path, []certlib.TaggedPassword{})
	if err == nil {
		t.Fatal("expected an error when the file holds no certificates")
	}
}
