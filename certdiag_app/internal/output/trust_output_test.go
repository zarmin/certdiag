package output

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func outputTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
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

func trustOutputContainer(certs ...*x509.Certificate) *certlib.CertContainer {
	items := make([]certlib.CertItem, 0, len(certs))
	for _, c := range certs {
		items = append(items, certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Alias:       c.Subject.CommonName,
			Certificate: c,
			RawBytes:    c.Raw,
		})
	}
	return &certlib.CertContainer{
		FilePath: "/scan/out.pem",
		Format:   certlib.FormatPEM,
		Source:   certlib.SourceFile,
		Items:    items,
	}
}

func trustOpts(cert *x509.Certificate, verdict truststore.TrustVerdict, anchor *x509.Certificate, tags []string) OutputOptions {
	idx := truststore.NewTrustIndex()
	idx.Set(cert, verdict, anchor)
	return OutputOptions{
		TrustIndex: idx,
		StoreTags: func(c *x509.Certificate) []string {
			if c.Equal(cert) {
				return tags
			}
			return nil
		},
	}
}

// --- structured output ------------------------------------------------------

// TestStructuredCert_TrustFieldsOmittedWhenNotEvaluated: the published JSON
// contract must gain nothing when trust was not requested.
func TestStructuredCert_TrustFieldsOmittedWhenNotEvaluated(t *testing.T) {
	cert := outputTestCert(t, "no-trust.test")
	out := BuildStructuredOutput([]*certlib.CertContainer{trustOutputContainer(cert)}, OutputOptions{})

	sc := out.Files[0].Items[0].Certificate
	if sc.Trust != "" || sc.TrustAnchor != "" || len(sc.Stores) != 0 {
		t.Errorf("expected no trust fields, got %+v", sc)
	}

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"trust"`, `"trust_anchor"`, `"stores"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("%s must be omitted from JSON when trust was not evaluated: %s", key, data)
		}
	}
}

// TestStructuredCert_TrustIsCanonicalLowercase: display formatting must never
// leak into the contract, the same rule fingerprints follow.
func TestStructuredCert_TrustIsCanonicalLowercase(t *testing.T) {
	cert := outputTestCert(t, "canonical.test")
	anchor := outputTestCert(t, "Canonical Anchor")

	opts := trustOpts(cert, truststore.VerdictAnchor, anchor, []string{"OS", "MOZ"})
	out := BuildStructuredOutput([]*certlib.CertContainer{trustOutputContainer(cert)}, opts)

	sc := out.Files[0].Items[0].Certificate
	if sc.Trust != "anchor" {
		t.Errorf("expected canonical lowercase %q, got %q", "anchor", sc.Trust)
	}
	if sc.Trust != strings.ToLower(sc.Trust) {
		t.Errorf("the contract value must be lowercase, got %q", sc.Trust)
	}
	if sc.TrustAnchor == "" {
		t.Error("expected the anchor subject to be reported")
	}
	if len(sc.Stores) != 2 || sc.Stores[0] != "OS" {
		t.Errorf("expected the store tags, got %v", sc.Stores)
	}
}

func TestStructuredCert_EveryVerdictSerialises(t *testing.T) {
	for _, v := range []truststore.TrustVerdict{
		truststore.VerdictAnchor, truststore.VerdictTrusted,
		truststore.VerdictExpired, truststore.VerdictUntrusted, truststore.VerdictDenied,
	} {
		t.Run(string(v), func(t *testing.T) {
			cert := outputTestCert(t, "verdict.test")
			opts := trustOpts(cert, v, nil, nil)
			out := BuildStructuredOutput([]*certlib.CertContainer{trustOutputContainer(cert)}, opts)

			if got := out.Files[0].Items[0].Certificate.Trust; got != string(v) {
				t.Errorf("expected %q, got %q", v, got)
			}
		})
	}
}

func TestStructuredCert_UnknownVerdictOmitted(t *testing.T) {
	cert := outputTestCert(t, "unknown.test")

	// An index that was built but never given this certificate must not
	// produce an empty-string trust field in the JSON.
	opts := OutputOptions{TrustIndex: truststore.NewTrustIndex()}
	out := BuildStructuredOutput([]*certlib.CertContainer{trustOutputContainer(cert)}, opts)

	if got := out.Files[0].Items[0].Certificate.Trust; got != "" {
		t.Errorf("expected no trust value for an unevaluated certificate, got %q", got)
	}
}

// --- OutputOptions helpers --------------------------------------------------

func TestOutputOptions_TrustEnabled(t *testing.T) {
	if (OutputOptions{}).TrustEnabled() {
		t.Error("trust must be off without an index")
	}
	if !(OutputOptions{TrustIndex: truststore.NewTrustIndex()}).TrustEnabled() {
		t.Error("an index means trust was evaluated")
	}
}

func TestOutputOptions_TrustVerdict(t *testing.T) {
	cert := outputTestCert(t, "display.test")
	opts := trustOpts(cert, truststore.VerdictTrusted, nil, nil)

	if got := opts.TrustVerdict(cert); got != "TRUSTED" {
		t.Errorf("expected the upper-cased display form, got %q", got)
	}
	if got := opts.TrustVerdict(nil); got != "" {
		t.Errorf("expected empty for a nil certificate, got %q", got)
	}
	if got := (OutputOptions{}).TrustVerdict(cert); got != "" {
		t.Errorf("expected empty without an index, got %q", got)
	}
}

// --- table view -------------------------------------------------------------

func TestTableView_TrustColumnsOnlyWhenEnabled(t *testing.T) {
	cases := []struct {
		name     string
		hasTrust bool
	}{
		{"without trust", false},
		{"with trust", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tbl := newTable(false, false, tc.hasTrust)

			// The existing invariant: headers and columns stay in step.
			if len(tbl.Headers) != len(tbl.Columns) {
				t.Fatalf("header count %d != column count %d", len(tbl.Headers), len(tbl.Columns))
			}
			joined := strings.Join(tbl.Headers, " ")
			hasCols := strings.Contains(joined, "TRUST") && strings.Contains(joined, "STORES")
			if hasCols != tc.hasTrust {
				t.Errorf("expected trust columns present=%v, got headers %v", tc.hasTrust, tbl.Headers)
			}
		})
	}
}

func TestTableView_RendersVerdictAndStores(t *testing.T) {
	cert := outputTestCert(t, "table.test")
	opts := trustOpts(cert, truststore.VerdictAnchor, nil, []string{"OS", "J21"})

	out := FormatTableView([]*certlib.CertContainer{trustOutputContainer(cert)}, opts)
	if !strings.Contains(out, "ANCHOR") {
		t.Errorf("expected the verdict in the table:\n%s", out)
	}
	// The STORES cell wraps at the narrow width tableformat auto-detects with no
	// TTY, so only the header is asserted here. Tag joining is covered by
	// TestFormatStoreTags, and wrapping is tableformat's own concern.
	if !strings.Contains(out, "STORES") && !strings.Contains(out, "S…") {
		t.Errorf("expected a STORES column in the table:\n%s", out)
	}
}

func TestFormatStoreTags(t *testing.T) {
	cert := outputTestCert(t, "tags.test")

	if got := formatStoreTags(cert, OutputOptions{}); got != "" {
		t.Errorf("expected empty with no tag function, got %q", got)
	}
	if got := formatStoreTags(nil, trustOpts(cert, truststore.VerdictAnchor, nil, []string{"OS"})); got != "" {
		t.Errorf("expected empty for a nil certificate, got %q", got)
	}
	opts := trustOpts(cert, truststore.VerdictAnchor, nil, []string{"OS", "MOZ", "CHR"})
	if got := formatStoreTags(cert, opts); got != "OS MOZ CHR" {
		t.Errorf("expected space-joined tags, got %q", got)
	}
}

// --- list view --------------------------------------------------------------

func TestListView_TrustLines(t *testing.T) {
	cert := outputTestCert(t, "list.test")
	anchor := outputTestCert(t, "List Anchor")
	opts := trustOpts(cert, truststore.VerdictTrusted, anchor, []string{"OS"})

	out := FormatListView(trustOutputContainer(cert), 0, opts)

	for _, want := range []string{"Trust:", "TRUSTED", "Stores:", "OS"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the list output:\n%s", want, out)
		}
	}
}

func TestListView_NoTrustLinesWhenDisabled(t *testing.T) {
	cert := outputTestCert(t, "quiet.test")
	out := FormatListView(trustOutputContainer(cert), 0, OutputOptions{})

	for _, unwanted := range []string{"Trust:", "Stores:", "Anchor:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("%q must not appear when trust was not evaluated:\n%s", unwanted, out)
		}
	}
}

// TestListView_NoAnchorLineForSelfSigned: a self-signed anchor is its own
// anchor, so repeating it is noise.
func TestListView_NoAnchorLineForSelfSigned(t *testing.T) {
	cert := outputTestCert(t, "selfsigned.test") // outputTestCert is self-signed
	opts := trustOpts(cert, truststore.VerdictAnchor, cert, nil)

	out := FormatListView(trustOutputContainer(cert), 0, opts)
	if strings.Contains(out, "Anchor:") {
		t.Errorf("a self-signed certificate must not repeat itself as its anchor:\n%s", out)
	}
}

// --- colour -----------------------------------------------------------------

func TestColorizeTrust(t *testing.T) {
	prev := ColorsEnabled
	ColorsEnabled = true
	t.Cleanup(func() { ColorsEnabled = prev })

	for _, v := range []truststore.TrustVerdict{
		truststore.VerdictAnchor, truststore.VerdictTrusted,
		truststore.VerdictDenied, truststore.VerdictUntrusted, truststore.VerdictExpired,
	} {
		display := v.Display()
		got := ColorizeTrust(display)
		if !strings.Contains(got, display) {
			t.Errorf("%s: the text must survive colouring, got %q", v, got)
		}
	}

	ColorsEnabled = false
	if got := ColorizeTrust("ANCHOR"); got != "ANCHOR" {
		t.Errorf("NO_COLOR must pass through unchanged, got %q", got)
	}
	if got := ColorizeTrust(""); got != "" {
		t.Errorf("expected empty to stay empty, got %q", got)
	}
}
