package output

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func fpCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return mustSelfSignedCert(t, mustGenECKey(t))
}

func fpContainers(t *testing.T) []*certlib.CertContainer {
	t.Helper()
	return []*certlib.CertContainer{{
		FilePath: "/tmp/fp.pem",
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items:    []certlib.CertItem{makeCertItem(fpCert(t))},
	}}
}

// --- structured output stays canonical ---

func TestBuildStructuredCert_AllFiveFingerprints(t *testing.T) {
	sc := BuildStructuredCert(&certlib.CertItem{
		Type:        certlib.ContentCertificate,
		Certificate: fpCert(t),
	})

	got := map[string]string{
		"md5": sc.MD5, "sha1": sc.SHA1, "sha256": sc.SHA256,
		"sha384": sc.SHA384, "sha512": sc.SHA512,
	}
	want := map[string]int{"md5": 32, "sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}

	for name, n := range want {
		v := got[name]
		if len(v) != n {
			t.Errorf("%s: expected %d hex chars, got %d (%q)", name, n, len(v), v)
		}
		if strings.ContainsAny(v, ":=+/") || v != strings.ToLower(v) {
			t.Errorf("%s must be canonical lowercase hex, got %q", name, v)
		}
	}
}

func TestStructuredOutput_CanonicalRegardlessOfFormat(t *testing.T) {
	// The headline contract: a user's display format must never reach JSON.
	containers := fpContainers(t)

	var baseline string
	for _, format := range certlib.FingerprintFormats {
		out := BuildStructuredOutput(containers, OutputOptions{
			DetailLevel:       1,
			FingerprintFormat: format,
		})
		data, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if baseline == "" {
			baseline = string(data)
			continue
		}
		if string(data) != baseline {
			t.Errorf("format %q changed the structured output; JSON must be canonical", format)
		}
	}
}

// --- human list output honours the format ---

func TestFormatListView_ShowsAllFiveFingerprints(t *testing.T) {
	out := FormatListView(fpContainers(t)[0], 0, OutputOptions{DetailLevel: 1})

	for _, algo := range certlib.FingerprintAlgos {
		if !strings.Contains(out, algo.Label()+":") {
			t.Errorf("expected a %s line in detailed output:\n%s", algo.Label(), out)
		}
	}
}

func TestFormatListView_DefaultFormatUnchanged(t *testing.T) {
	// The zero value must render exactly like an explicit hex request, which is
	// what keeps existing output byte-identical.
	containers := fpContainers(t)
	zero := FormatListView(containers[0], 0, OutputOptions{DetailLevel: 1})
	explicit := FormatListView(containers[0], 0, OutputOptions{
		DetailLevel:       1,
		FingerprintFormat: certlib.FingerprintHex,
	})
	if zero != explicit {
		t.Error("zero-value FingerprintFormat must render as hex")
	}
}

func TestFormatListView_HonoursFormat(t *testing.T) {
	containers := fpContainers(t)
	cert := containers[0].Items[0].Certificate

	for _, format := range certlib.FingerprintFormats {
		out := FormatListView(containers[0], 0, OutputOptions{DetailLevel: 1, FingerprintFormat: format})
		want := certlib.CertFingerprint(cert, certlib.FingerprintSHA256, format)
		if !strings.Contains(out, want) {
			t.Errorf("format %q: expected %q in output", format, want)
		}
	}
}

func TestFormatListView_NoFingerprintsWithoutDetails(t *testing.T) {
	out := FormatListView(fpContainers(t)[0], 0, OutputOptions{})
	if strings.Contains(out, "SHA-256:") {
		t.Error("fingerprints must stay behind --details")
	}
}

// --- store view ---

func TestFormatStoreList_DetailsShowFingerprints(t *testing.T) {
	stores := []truststore.StoreContents{
		storeOf("Test Store", truststore.StoreTypeOS, "/kc", fpCert(t)),
	}
	out := FormatStoreListFormat(stores, true, "", certlib.FingerprintHexColon)

	if !strings.Contains(out, "SHA-256:") {
		t.Errorf("expected fingerprints in store details:\n%s", out)
	}
	if !strings.Contains(out, ":") {
		t.Error("expected hex-colon rendering")
	}
}

func TestFormatStoreList_NoFingerprintsWithoutDetails(t *testing.T) {
	stores := []truststore.StoreContents{
		storeOf("Test Store", truststore.StoreTypeOS, "/kc", fpCert(t)),
	}
	out := FormatStoreListFormat(stores, false, "", certlib.FingerprintHex)
	if strings.Contains(out, "SHA-256:") {
		t.Error("store fingerprints must stay behind --details")
	}
}
