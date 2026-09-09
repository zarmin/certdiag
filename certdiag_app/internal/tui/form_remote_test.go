package tui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestBuildRemoteForm(t *testing.T) {
	initStyles()
	f := buildRemoteForm()

	if f == nil {
		t.Fatal("expected non-nil form")
	}
	if f.title != "Remote Certificate Fetch" {
		t.Errorf("unexpected title: %s", f.title)
	}

	// Check key fields exist
	fields := []string{"target", "starttls", "tls_version", "sni", "ip_version",
		"mtls_mode", "client_cert", "client_key", "client_p12", "client_jks",
		"client_alias", "client_password", "submit"}
	for _, name := range fields {
		if f.fieldIndex(name) < 0 {
			t.Errorf("missing field: %s", name)
		}
	}
}

func TestBuildRemoteForm_Visibility(t *testing.T) {
	initStyles()
	f := buildRemoteForm()

	// Initially mTLS mode is "None" - PEM/P12/JKS/alias/password fields should be hidden
	certField := f.fieldByName("client_cert")
	if certField.Visible() {
		t.Error("client_cert should be hidden when mTLS is None")
	}
	keyField := f.fieldByName("client_key")
	if keyField.Visible() {
		t.Error("client_key should be hidden when mTLS is None")
	}
	p12Field := f.fieldByName("client_p12")
	if p12Field.Visible() {
		t.Error("client_p12 should be hidden when mTLS is None")
	}
	jksField := f.fieldByName("client_jks")
	if jksField.Visible() {
		t.Error("client_jks should be hidden when mTLS is None")
	}

	// Switch to PEM mode
	mtlsField := f.fieldByName("mtls_mode")
	mtlsField.SetValue(labelMTLSPEM)
	f.evaluateVisibility()

	if !f.fieldByName("client_cert").Visible() {
		t.Error("client_cert should be visible for PEM mode")
	}
	if !f.fieldByName("client_key").Visible() {
		t.Error("client_key should be visible for PEM mode")
	}
	if f.fieldByName("client_p12").Visible() {
		t.Error("client_p12 should be hidden for PEM mode")
	}

	// Switch to P12 mode
	mtlsField.SetValue(labelMTLSP12)
	f.evaluateVisibility()

	if f.fieldByName("client_cert").Visible() {
		t.Error("client_cert should be hidden for P12 mode")
	}
	if !f.fieldByName("client_p12").Visible() {
		t.Error("client_p12 should be visible for P12 mode")
	}
	if !f.fieldByName("client_alias").Visible() {
		t.Error("client_alias should be visible for P12 mode")
	}
}

func TestStarttlsFromLabel(t *testing.T) {
	tests := []struct {
		label string
		want  string
	}{
		{labelStarttlsNone, ""},
		{labelStarttlsSMTP, "smtp"},
		{labelStarttlsIMAP, "imap"},
		{labelStarttlsPOP3, "pop3"},
		{labelStarttlsFTP, "ftp"},
		{labelStarttlsLDAP, "ldap"},
		{labelStarttlsMySQL, "mysql"},
		{labelStarttlsPostgres, "postgres"},
	}
	for _, tt := range tests {
		got := starttlsFromLabel(tt.label)
		if got != tt.want {
			t.Errorf("starttlsFromLabel(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

func TestTLSVersionFromLabel(t *testing.T) {
	tests := []struct {
		label string
		want  string
	}{
		{labelTLSAuto, ""},
		{labelTLS10, "tls1.0"},
		{labelTLS11, "tls1.1"},
		{labelTLS12, "tls1.2"},
		{labelTLS13, "tls1.3"},
	}
	for _, tt := range tests {
		got := tlsVersionFromLabel(tt.label)
		if got != tt.want {
			t.Errorf("tlsVersionFromLabel(%q) = %q, want %q", tt.label, got, tt.want)
		}
	}
}

func TestCertToTreeNode(t *testing.T) {
	cert := makeTestCert(t, "test.example.com")
	node := certToTreeNode(cert, "leaf")

	if node.Subject != "test.example.com" {
		t.Errorf("unexpected subject: %s", node.Subject)
	}
	if node.Container == nil {
		t.Error("expected non-nil container")
	}
	if node.Item == nil {
		t.Error("expected non-nil item")
	}
	if node.Item.Certificate != cert {
		t.Error("expected certificate in item")
	}
}

func makeCertItem(t *testing.T, cn string) *certlib.CertItem {
	t.Helper()
	cert := makeTestCert(t, cn)
	return &certlib.CertItem{
		Type:        certlib.ContentCertificate,
		Certificate: cert,
		RawBytes:    cert.Raw,
	}
}

func makeTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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

func containsString(s, sub string) bool {
	return len(s) > 0 && len(sub) > 0 && contains(s, sub)
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
