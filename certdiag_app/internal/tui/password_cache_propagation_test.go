package tui

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func msgHasPassword(pws [][]byte, want string) bool {
	for _, p := range pws {
		if string(p) == want {
			return true
		}
	}
	return false
}

func writeCertKeyPEM(t *testing.T, path string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestSubmitCreateCert_BundleCarriesKeyPassword verifies fix (A): the create-cert
// bundle branch propagates the generated key's encryption password so it is cached.
func TestSubmitCreateCert_BundleCarriesKeyPassword(t *testing.T) {
	dir := t.TempDir()
	f := buildCreateCertForm(dir, nil, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365, 3650)
	f.fieldByName("cn").SetValue("example.com")
	f.fieldByName("output_mode").SetValue(labelBundlePEM)
	f.fieldByName("bundle_out").SetValue(filepath.Join(dir, "bundle.pem"))
	f.fieldByName("encrypt_key").SetValue("true")
	f.evaluateVisibility()
	f.fieldByName("encrypt_password").SetValue("keypass123")
	f.evaluateVisibility()

	msg := submitCreateCert(f, dir, true, nil)()
	res, ok := msg.(FormResultMsg)
	if !ok {
		t.Fatalf("unexpected msg type %T", msg)
	}
	if res.Err != nil {
		t.Fatalf("bundle create should succeed, got: %v", res.Err)
	}
	if !msgHasPassword(res.Passwords, "keypass123") {
		t.Errorf("bundle result did not carry the key password: %v", res.Passwords)
	}
}

// TestSubmitConvert_CarriesOutputPassword verifies fix (B): converting to an
// encrypted PKCS#12 propagates the output password so it is cached.
func TestSubmitConvert_CarriesOutputPassword(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pem")
	writeCertKeyPEM(t, in)

	node := &TreeNode{Container: &certlib.CertContainer{FilePath: in, Format: certlib.FormatPEM}, Filename: "in.pem"}
	f := buildConvertForm(dir, node)
	if f == nil {
		t.Fatal("buildConvertForm returned nil")
	}
	f.fieldByName("format").SetValue(labelPKCS12)
	f.evaluateVisibility()
	f.fieldByName("password").SetValue("outpass123")
	f.fieldByName("output").SetValue(filepath.Join(dir, "out.p12"))
	f.evaluateVisibility()

	msg := submitConvert(f, true, nil)()
	res, ok := msg.(FormResultMsg)
	if !ok {
		t.Fatalf("unexpected msg type %T", msg)
	}
	if res.Err != nil {
		t.Fatalf("convert should succeed, got: %v", res.Err)
	}
	if !msgHasPassword(res.Passwords, "outpass123") {
		t.Errorf("convert result did not carry the output password: %v", res.Passwords)
	}
}

// TestSubmitRemoteFetch_CarriesTypedClientPassword verifies fix (C): a typed
// client_password that unlocks the client-cert container is propagated for caching.
func TestSubmitRemoteFetch_CarriesTypedClientPassword(t *testing.T) {
	dir := t.TempDir()
	p12 := filepath.Join(dir, "client.p12")
	bundleEncP12(t, p12, "secret123")

	f := buildRemoteForm()
	f.fieldByName("target").SetValue("127.0.0.1:1")
	f.fieldByName("mtls_mode").SetValue(labelMTLSP12)
	f.fieldByName("client_p12").SetValue(p12)
	f.fieldByName("client_password").SetValue("secret123")

	msg := submitRemoteFetch(context.Background(), f, nil)()
	res, ok := msg.(RemoteFetchResultMsg)
	if !ok {
		t.Fatalf("unexpected msg type %T", msg)
	}
	if !msgHasPassword(res.Passwords, "secret123") {
		t.Errorf("remote fetch did not carry the typed client password: %v (err=%v)", res.Passwords, res.Err)
	}
}

// TestSubmitRemoteFetch_ConsultsPasswordCache verifies fix (C): with no typed
// password, submitRemoteFetch uses its passwords param (the session cache) to
// unlock the client-cert container, and propagates the matching password.
func TestSubmitRemoteFetch_ConsultsPasswordCache(t *testing.T) {
	dir := t.TempDir()
	p12 := filepath.Join(dir, "client.p12")
	bundleEncP12(t, p12, "secret123")

	f := buildRemoteForm()
	f.fieldByName("target").SetValue("127.0.0.1:1")
	f.fieldByName("mtls_mode").SetValue(labelMTLSP12)
	f.fieldByName("client_p12").SetValue(p12)

	cache := []certlib.TaggedPassword{{Password: []byte("secret123")}}
	msg := submitRemoteFetch(context.Background(), f, cache)()
	res, ok := msg.(RemoteFetchResultMsg)
	if !ok {
		t.Fatalf("unexpected msg type %T", msg)
	}
	if res.Err != nil && !msgHasPassword(res.Passwords, "secret123") {
		t.Fatalf("client cert should load from cached password, got err: %v", res.Err)
	}
	if !msgHasPassword(res.Passwords, "secret123") {
		t.Errorf("remote fetch did not consult/propagate the cached password: %v", res.Passwords)
	}
}
