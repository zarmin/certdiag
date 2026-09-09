package tui

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestKeyForm_HiddenEncryptDoesNotApplyStaleValue(t *testing.T) {
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048})
	f.fieldByName("format").SetValue(labelPEM)
	f.fieldByName("encrypt").SetValue("true")
	f.fieldByName("password").SetValue("secret")
	f.evaluateVisibility()

	if !f.fieldByName("encrypt").Visible() || !f.fieldByName("password").Visible() {
		t.Fatalf("precondition: encrypt and password must be visible under PEM")
	}

	f.fieldByName("format").SetValue(labelDER)
	f.evaluateVisibility()

	if f.fieldByName("encrypt").Visible() {
		t.Error("encrypt checkbox should be hidden under DER")
	}
	if f.fieldByName("password").Visible() {
		t.Error("password should be hidden when its controlling encrypt is hidden")
	}

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("buildCreateKeyOptions: %v", err)
	}
	if opts.Encrypt {
		t.Error("Encrypt must be false for DER, hidden checkbox applied stale true")
	}
}

func TestKeyForm_EncryptAppliesUnderPEM(t *testing.T) {
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048})
	f.fieldByName("format").SetValue(labelPEM)
	f.fieldByName("encrypt").SetValue("true")
	f.fieldByName("password").SetValue("secret")
	f.evaluateVisibility()

	opts, err := buildCreateKeyOptions(f)
	if err != nil {
		t.Fatalf("buildCreateKeyOptions: %v", err)
	}
	if !opts.Encrypt {
		t.Error("Encrypt must be true for PEM with encrypt checked")
	}
	if string(opts.Password) != "secret" {
		t.Errorf("Password mismatch, got %q", string(opts.Password))
	}
}

func TestCertForm_HiddenEncryptKeyDoesNotApplyStaleValue(t *testing.T) {
	f := buildCreateCertForm("/tmp", nil, "", "", certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048}, 365, 3650)
	f.fieldByName("cn").SetValue("example.com")
	f.fieldByName("encrypt_key").SetValue("true")
	f.fieldByName("encrypt_password").SetValue("secret")
	f.evaluateVisibility()

	if !f.fieldByName("encrypt_key").Visible() {
		t.Fatalf("precondition: encrypt_key must be visible for Generate+Individual+PEM")
	}

	f.fieldByName("format").SetValue(labelDER)
	f.evaluateVisibility()

	if f.fieldByName("encrypt_key").Visible() {
		t.Error("encrypt_key should be hidden under DER individual output")
	}
	if f.fieldByName("encrypt_password").Visible() {
		t.Error("encrypt_password should be hidden when its controlling encrypt_key is hidden")
	}

	opts, _, err := buildCreateCertOptions(f, "/tmp", nil)
	if err != nil {
		t.Fatalf("buildCreateCertOptions: %v", err)
	}
	if opts.EncryptKey {
		t.Error("EncryptKey must be false for DER, hidden checkbox applied stale true")
	}
}
