package truststore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

// --- certdata.txt synthesis -------------------------------------------------
//
// The excerpts are built from real certificates rather than committed, so the
// input is exactly known and the test cannot drift from the fixture.

func octalBlock(attr string, data []byte) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s MULTILINE_OCTAL\n", attr)
	for i, b := range data {
		if i > 0 && i%16 == 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(&sb, "\\%03o", b)
	}
	sb.WriteString("\nEND\n")
	return sb.String()
}

func certdataCertObject(label string, der []byte) string {
	return "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +
		"CKA_TOKEN CK_BBOOL CK_TRUE\n" +
		fmt.Sprintf("CKA_LABEL UTF8 %q\n", label) +
		"CKA_CERTIFICATE_TYPE CK_CERTIFICATE_TYPE CKC_X_509\n" +
		octalBlock("CKA_VALUE", der) +
		"\n"
}

func certdataTrustObject(label string, der []byte, serverAuth, email, codeSigning string) string {
	sha1sum := sha1Sum(der)
	return "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n" +
		"CKA_TOKEN CK_BBOOL CK_TRUE\n" +
		fmt.Sprintf("CKA_LABEL UTF8 %q\n", label) +
		octalBlock("CKA_CERT_SHA1_HASH", sha1sum) +
		"CKA_TRUST_SERVER_AUTH CK_TRUST " + serverAuth + "\n" +
		"CKA_TRUST_EMAIL_PROTECTION CK_TRUST " + email + "\n" +
		"CKA_TRUST_CODE_SIGNING CK_TRUST " + codeSigning + "\n" +
		"CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE\n" +
		"\n"
}

const certdataHeader = `#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.
#
# certdata.txt
#
BEGINDATA
`

func TestParseCertdata(t *testing.T) {
	delegator := newTestCA(t, "Delegator Root")
	mustVerify := newTestCA(t, "Must Verify Root")
	notTrusted := newTestCA(t, "Distrusted Root")
	emailOnly := newTestCA(t, "Email Only Root")

	data := certdataHeader +
		certdataCertObject("Delegator Root", delegator.cert.Raw) +
		certdataTrustObject("Delegator Root", delegator.cert.Raw,
			"CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST") +
		certdataCertObject("Must Verify Root", mustVerify.cert.Raw) +
		certdataTrustObject("Must Verify Root", mustVerify.cert.Raw,
			"CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST") +
		certdataCertObject("Distrusted Root", notTrusted.cert.Raw) +
		certdataTrustObject("Distrusted Root", notTrusted.cert.Raw,
			"CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED", "CKT_NSS_NOT_TRUSTED") +
		certdataCertObject("Email Only Root", emailOnly.cert.Raw) +
		certdataTrustObject("Email Only Root", emailOnly.cert.Raw,
			"CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST")

	parsed, err := ParseCertdata([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	trusted := labelSet(parsed.Trusted)
	distrusted := labelSet(parsed.Distrusted)

	if len(parsed.Trusted) != 1 || !trusted["Delegator Root"] {
		t.Errorf("expected only the server-auth delegator to be trusted, got %v", keys(trusted))
	}
	if len(parsed.Distrusted) != 1 || !distrusted["Distrusted Root"] {
		t.Errorf("expected only the explicitly distrusted root, got %v", keys(distrusted))
	}
	// A root trusted for email but not server auth is not a TLS anchor, and is
	// not a distrust record either: it belongs in neither list.
	if trusted["Email Only Root"] || distrusted["Email Only Root"] {
		t.Error("an email-only root must be neither shipped as trusted nor claimed as distrusted")
	}
	if trusted["Must Verify Root"] || distrusted["Must Verify Root"] {
		t.Error("a must-verify root must be in neither list")
	}
}

// TestParseCertdata_DERSurvivesOctalRoundTrip is the byte-exactness guard: an
// octal decoding slip would silently ship corrupt anchors.
func TestParseCertdata_DERSurvivesOctalRoundTrip(t *testing.T) {
	ca := newTestCA(t, "Round Trip Root")

	data := certdataHeader +
		certdataCertObject("Round Trip Root", ca.cert.Raw) +
		certdataTrustObject("Round Trip Root", ca.cert.Raw,
			"CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST")

	parsed, err := ParseCertdata([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Trusted) != 1 {
		t.Fatalf("expected 1 anchor, got %d", len(parsed.Trusted))
	}
	if hex.EncodeToString(parsed.Trusted[0].DER) != hex.EncodeToString(ca.cert.Raw) {
		t.Error("DER did not survive the MULTILINE_OCTAL round trip")
	}
	if _, err := x509.ParseCertificate(parsed.Trusted[0].DER); err != nil {
		t.Errorf("the decoded DER must still parse: %v", err)
	}
	if parsed.Trusted[0].Label != "Round Trip Root" {
		t.Errorf("expected the label to be carried, got %q", parsed.Trusted[0].Label)
	}
}

func TestParseCertdata_AlwaysCarriesNameConstraintCaveat(t *testing.T) {
	ca := newTestCA(t, "Caveat Root")
	data := certdataHeader +
		certdataCertObject("Caveat Root", ca.cert.Raw) +
		certdataTrustObject("Caveat Root", ca.cert.Raw,
			"CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_MUST_VERIFY_TRUST")

	parsed, err := ParseCertdata([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(parsed.Caveats, " ")
	if !strings.Contains(joined, "name constraints") {
		t.Errorf("the lossiness must be recorded, got %v", parsed.Caveats)
	}
}

func TestParseCertdata_Rejects(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"header only", certdataHeader},
		{"certificates with no trust records", certdataHeader +
			certdataCertObject("Orphan", []byte{0x30, 0x00})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCertdata([]byte(tc.data)); err == nil {
				t.Error("expected an error when no server-auth anchors are found")
			}
		})
	}
}

func TestParseCertdata_TruncatedOctal(t *testing.T) {
	data := certdataHeader +
		"CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +
		"CKA_LABEL UTF8 \"Bad\"\n" +
		"CKA_VALUE MULTILINE_OCTAL\n\\06\nEND\n"

	if _, err := ParseCertdata([]byte(data)); err == nil {
		t.Error("expected a truncated octal escape to be rejected, not silently truncated")
	}
}

func TestDecodeOctalLine(t *testing.T) {
	got, err := decodeOctalLine(`\060\202\005\012`)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0o060, 0o202, 0o005, 0o012}
	if len(got) != len(want) {
		t.Fatalf("expected %d bytes, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("byte %d: expected %#o, got %#o", i, want[i], got[i])
		}
	}

	if _, err := decodeOctalLine(`\0`); err == nil {
		t.Error("expected an error for a truncated escape")
	}
	if _, err := decodeOctalLine(`\09a`); err == nil {
		t.Error("expected an error for a non-octal escape")
	}
	if b, err := decodeOctalLine(""); err != nil || len(b) != 0 {
		t.Errorf("expected an empty line to decode to nothing, got %v %v", b, err)
	}
}

func TestUnquoteUTF8(t *testing.T) {
	cases := map[string]string{
		`CKA_LABEL UTF8 "GlobalSign Root CA"`:   "GlobalSign Root CA",
		`CKA_LABEL UTF8 "Has \"inner\" quotes"`: `Has \"inner\" quotes`,
		`CKA_LABEL UTF8 ""`:                     "",
		`CKA_LABEL UTF8 no quotes here`:         "no quotes here",
	}
	for in, want := range cases {
		if got := unquoteUTF8(in); got != want {
			t.Errorf("%q: expected %q, got %q", in, want, got)
		}
	}
}

// --- Chrome Root Store ------------------------------------------------------

func chromeCertsFile(certs ...*x509.Certificate) []byte {
	var sb strings.Builder
	sb.WriteString("# This file contains certificates referenced by root_store.textproto.\n\n")
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		fmt.Fprintf(&sb, "# %s\n", hex.EncodeToString(sum[:]))
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
		sb.WriteString("\n")
	}
	return []byte(sb.String())
}

func chromeAnchor(c *x509.Certificate, id int, constraints bool) string {
	sum := sha256.Sum256(c.Raw)
	body := fmt.Sprintf("trust_anchors {\n  sha256_hex: %q\n  crs_root_id: %d\n",
		hex.EncodeToString(sum[:]), id)
	if constraints {
		body += "  constraints {\n    sct_not_after_sec: 1234567890\n  }\n"
	}
	return body + "}\n\n"
}

func TestParseChromeRootStore(t *testing.T) {
	included := newTestCA(t, "Chrome Included Root")
	constrained := newTestCA(t, "Chrome Constrained Root")
	excluded := newTestCA(t, "Chrome Excluded Root")
	missing := newTestCA(t, "Chrome Missing Cert Root")

	textproto := "# Chrome Root Store.\nversion_major: 42\n\n" +
		chromeAnchor(included.cert, 1, false) +
		chromeAnchor(constrained.cert, 2, true) +
		chromeAnchor(missing.cert, 3, false)

	// root_store.certs holds an extra certificate the textproto does not list.
	certs := chromeCertsFile(included.cert, constrained.cert, excluded.cert)

	parsed, err := ParseChromeRootStore([]byte(textproto), certs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(parsed.Trusted) != 2 {
		t.Fatalf("expected only the two anchors present in both files, got %d", len(parsed.Trusted))
	}
	// The textproto is authoritative for membership.
	for _, bc := range parsed.Trusted {
		c, err := x509.ParseCertificate(bc.DER)
		if err != nil {
			t.Fatal(err)
		}
		if c.Subject.CommonName == "Chrome Excluded Root" {
			t.Error("a certificate absent from the textproto must not be included")
		}
	}

	if parsed.Revision != "version_major 42" {
		t.Errorf("expected the store version as the revision, got %q", parsed.Revision)
	}

	joined := strings.Join(parsed.Caveats, " ")
	if !strings.Contains(joined, "1 anchors listed") {
		t.Errorf("an anchor with no certificate must be recorded, got %v", parsed.Caveats)
	}
	if !strings.Contains(joined, "carry constraints") {
		t.Errorf("constraints a PEM cannot express must be recorded, got %v", parsed.Caveats)
	}
	if !strings.Contains(joined, "public TLS server authentication") {
		t.Errorf("the purpose scope must be recorded, got %v", parsed.Caveats)
	}
}

func TestParseChromeRootStore_Rejects(t *testing.T) {
	ca := newTestCA(t, "Lonely Root")

	if _, err := ParseChromeRootStore([]byte("version_major: 1\n"), chromeCertsFile(ca.cert)); err == nil {
		t.Error("expected an error when the textproto lists no anchors")
	}

	textproto := "version_major: 1\n\n" + chromeAnchor(ca.cert, 1, false)
	if _, err := ParseChromeRootStore([]byte(textproto), []byte("# no certificates\n")); err == nil {
		t.Error("expected an error when no certificate matches an anchor")
	}
}

func TestParseChromeRootStore_NoDuplicates(t *testing.T) {
	ca := newTestCA(t, "Repeated Root")
	textproto := "version_major: 1\n\n" + chromeAnchor(ca.cert, 1, false)

	// The same certificate appearing twice in root_store.certs must be taken
	// once, or the anchor count guard would be meaningless.
	certs := append(chromeCertsFile(ca.cert), chromeCertsFile(ca.cert)...)

	parsed, err := ParseChromeRootStore([]byte(textproto), certs)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Trusted) != 1 {
		t.Errorf("expected the duplicate to be collapsed, got %d", len(parsed.Trusted))
	}
}

// --- helpers ---

func labelSet(certs []BundleCert) map[string]bool {
	out := map[string]bool{}
	for _, c := range certs {
		out[c.Label] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
