package certlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/extensions"
)

// These conditions are invisible without a parser and consequential with one,
// which is why each earns a check rather than only a display line.

func extCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, extra []pkix.Extension, maxPathLen int) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       extra,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		if maxPathLen >= 0 {
			tmpl.MaxPathLen = maxPathLen
			tmpl.MaxPathLenZero = maxPathLen == 0
		}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func extStore(t *testing.T, certs ...*x509.Certificate) *CertStore {
	t.Helper()
	store := NewCertStore()
	c := CertContainer{FilePath: "/tmp/ext.pem", Format: FormatPEM, Source: SourceFile}
	for _, cert := range certs {
		c.Items = append(c.Items, CertItem{Type: ContentCertificate, Certificate: cert, RawBytes: cert.Raw})
	}
	store.AddContainer(c)
	return store
}

func runExtChecks(t *testing.T, store *CertStore) map[string]CheckIssue {
	t.Helper()
	rels := DetectRelations(store)
	index := BuildRelationIndex(rels, store)
	result := RunChecks(store, index, CheckOptions{})
	out := make(map[string]CheckIssue)
	for _, issue := range result.Issues {
		out[issue.CheckID] = issue
	}
	return out
}

// TestCheckPrecertAsCert: a precertificate exists only to be logged. Serving
// one is a mistake no client accepts, and the poison extension makes it certain.
func TestCheckPrecertAsCert(t *testing.T) {
	poison := pkix.Extension{Id: extensions.OIDPrecertPoison, Critical: true, Value: []byte{0x05, 0x00}}
	pre, _ := extCert(t, "precert.example", false, nil, nil, []pkix.Extension{poison}, -1)

	issues := runExtChecks(t, extStore(t, pre))
	issue, ok := issues["precert_as_cert"]
	if !ok {
		t.Fatalf("expected precert_as_cert, got %v", keysOf(issues))
	}
	if issue.Severity != SeverityWarning {
		t.Errorf("expected a warning, got %s", issue.Severity)
	}

	plain, _ := extCert(t, "plain.example", false, nil, nil, nil, -1)
	if _, fired := runExtChecks(t, extStore(t, plain))["precert_as_cert"]; fired {
		t.Error("an ordinary certificate is not a precertificate")
	}
}

// TestCheckPrecertPoison_NoLongerUnknownExt: the poison OID used to trip the
// unknown-critical-extension check with no explanation.
func TestCheckPrecertPoison_NoLongerUnknownExt(t *testing.T) {
	poison := pkix.Extension{Id: extensions.OIDPrecertPoison, Critical: true, Value: []byte{0x05, 0x00}}
	pre, _ := extCert(t, "precert.example", false, nil, nil, []pkix.Extension{poison}, -1)

	if _, fired := runExtChecks(t, extStore(t, pre))["unknown_ext"]; fired {
		t.Error("the poison extension is known now; unknown_ext must stay quiet")
	}
}

// TestCheckPathLengthViolation: x509.Verify rejects a chain that is too deep
// with an error that does not say which constraint was exceeded.
func TestCheckPathLengthViolation(t *testing.T) {
	root, rootKey := extCert(t, "PL Root", true, nil, nil, nil, 0)
	inter, interKey := extCert(t, "PL Intermediate", true, root, rootKey, nil, -1)
	deeper, _ := extCert(t, "PL Too Deep", true, inter, interKey, nil, -1)

	issues := runExtChecks(t, extStore(t, root, inter, deeper))
	issue, ok := issues["path_length_violation"]
	if !ok {
		t.Fatalf("a CA two levels under a pathlen:0 root violates it, got %v", keysOf(issues))
	}
	if issue.Severity != SeverityCritical {
		t.Errorf("expected critical, got %s", issue.Severity)
	}
	if !strings.Contains(issue.Message, "PL Root") {
		t.Errorf("the message must name the constraint's owner: %q", issue.Message)
	}
}

func TestCheckPathLengthViolation_WithinLimitIsQuiet(t *testing.T) {
	// pathlen:1 allows one CA layer below the root: the intermediate is fine,
	// a leaf under it is fine, a second CA layer is not (x509.Verify would
	// reject anything it issued).
	root, rootKey := extCert(t, "OK Root", true, nil, nil, nil, 1)
	inter, interKey := extCert(t, "OK Intermediate", true, root, rootKey, nil, -1)
	leaf, _ := extCert(t, "ok.example", false, inter, interKey, nil, -1)

	if _, fired := runExtChecks(t, extStore(t, root, inter, leaf))["path_length_violation"]; fired {
		t.Error("a chain inside the allowance must be quiet")
	}
	deeper, _ := extCert(t, "Second CA layer", true, inter, interKey, nil, -1)
	if _, fired := runExtChecks(t, extStore(t, root, inter, deeper))["path_length_violation"]; !fired {
		t.Error("a second CA layer under a pathlen:1 root sits too deep")
	}
}

// TestCheckNetscapeTypeConflict: the legacy extension disagreeing with Basic
// Constraints is a sign of a certificate built from a stale template.
func TestCheckNetscapeTypeConflict(t *testing.T) {
	// Bit 5 is "SSL CA".
	bits := asn1.BitString{Bytes: []byte{0x04}, BitLength: 6}
	der, err := asn1.Marshal(bits)
	if err != nil {
		t.Fatal(err)
	}
	nsCA := pkix.Extension{Id: extensions.OIDNetscapeCertType, Value: der}

	// A leaf that claims to be a CA in the legacy extension.
	leaf, _ := extCert(t, "conflict.example", false, nil, nil, []pkix.Extension{nsCA}, -1)

	issues := runExtChecks(t, extStore(t, leaf))
	if _, ok := issues["netscape_type_conflict"]; !ok {
		t.Errorf("expected netscape_type_conflict, got %v", keysOf(issues))
	}
}

func keysOf(m map[string]CheckIssue) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestCheckMustStaple: a certificate that demands a staple and does not get one
// is meant to be rejected. That makes a missing staple a failure, not a note.
func TestCheckMustStaple(t *testing.T) {
	feature, err := asn1.Marshal([]int{5})
	if err != nil {
		t.Fatal(err)
	}
	mustStaple := pkix.Extension{Id: extensions.OIDTLSFeature, Value: feature}
	leaf, _ := extCert(t, "staple.example", false, nil, nil, []pkix.Extension{mustStaple}, -1)

	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "staple.example", Port: 443},
		TLSInfo:      TLSConnectionInfo{OCSPStapled: false},
		Certificates: []*x509.Certificate{leaf},
	}
	issues := checkMustStaple(ctx, CheckOptions{})
	if len(issues) != 1 {
		t.Fatalf("expected a must-staple failure, got %d", len(issues))
	}
	if issues[0].Severity != SeverityCritical {
		t.Errorf("the server opted into this being fatal, got %s", issues[0].Severity)
	}

	ctx.TLSInfo.OCSPStapled = true
	if got := checkMustStaple(ctx, CheckOptions{}); len(got) != 0 {
		t.Error("a stapled response satisfies the requirement")
	}
}

func TestCheckMustStaple_QuietWithoutTheExtension(t *testing.T) {
	leaf, _ := extCert(t, "plain.example", false, nil, nil, nil, -1)
	ctx := RemoteCheckContext{
		Target:       RemoteTarget{Host: "plain.example", Port: 443},
		Certificates: []*x509.Certificate{leaf},
	}
	if got := checkMustStaple(ctx, CheckOptions{}); len(got) != 0 {
		t.Error("without the extension a missing staple stays an observation")
	}
}
