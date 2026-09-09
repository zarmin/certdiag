package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// TestCreateCertOptions_WiresPasswordCache verifies the fix: the create-cert
// option builder propagates the session password cache into KeyFilePasswords and
// SignerKeyPasswords so encrypted existing/CA keys can be decrypted.
func TestCreateCertOptions_WiresPasswordCache(t *testing.T) {
	cache := []certlib.TaggedPassword{{Password: []byte("known-passphrase")}}
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365, 3650)
	f.fieldByName("cn").SetValue("example.com")
	f.fieldByName("key_source").SetValue(keySourceExisting)
	f.fieldByName("key_path").SetValue("/tmp/leaf.key")
	f.fieldByName("signing").SetValue(labelSignWithCA)
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")
	f.evaluateVisibility()

	opts, _, err := buildCreateCertOptions(f, "/tmp", cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.KeyFilePasswords) == 0 {
		t.Error("KeyFilePasswords not wired from cache")
	}
	if len(opts.SignerKeyPasswords) == 0 {
		t.Error("SignerKeyPasswords not wired from cache")
	}
}

// TestRenewOptions_WiresPasswordCache verifies the same for renew.
func TestRenewOptions_WiresPasswordCache(t *testing.T) {
	cache := []certlib.TaggedPassword{{Password: []byte("known-passphrase")}}
	node := &TreeNode{Container: &certlib.CertContainer{FilePath: "/tmp/server.crt"}, Subject: "CN=server"}
	f := buildRenewForm("/tmp", node, certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365)
	if f == nil {
		t.Fatal("buildRenewForm returned nil")
	}
	f.fieldByName("signing").SetValue(labelSignWithCA)
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")
	f.evaluateVisibility()

	opts, err := buildRenewOptions(f, "/tmp", cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.KeyFilePasswords) == 0 {
		t.Error("KeyFilePasswords not wired from cache")
	}
	if len(opts.SignerKeyPasswords) == 0 {
		t.Error("SignerKeyPasswords not wired from cache")
	}
}

// TestSignOptions_MergesPasswordCache verifies the sign builder merges the cache
// into CAKeyPasswords (previously only the CSR container password was used).
func TestSignOptions_MergesPasswordCache(t *testing.T) {
	cache := []certlib.TaggedPassword{{Password: []byte("ca-key-passphrase")}}
	node := &TreeNode{Container: &certlib.CertContainer{FilePath: "/tmp/req.csr"}, Subject: "CN=req"}
	f := buildSignCSRForm("/tmp", node, 365, 3650)
	if f == nil {
		t.Fatal("buildSignCSRForm returned nil")
	}
	f.fieldByName("ca_cert").SetValue("/tmp/ca.crt")
	f.fieldByName("ca_key").SetValue("/tmp/ca.key")
	f.evaluateVisibility()

	opts, err := buildSignCSROptions(f, "/tmp", cache)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range opts.CAKeyPasswords {
		if string(p.Password) == "ca-key-passphrase" {
			found = true
		}
	}
	if !found {
		t.Errorf("cached CA key password not present in CAKeyPasswords: %v", opts.CAKeyPasswords)
	}
}
