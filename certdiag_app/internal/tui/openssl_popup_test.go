package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestOpenSSLForForm_CreateKey(t *testing.T) {
	f := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	f.fieldByName(fieldKeyAlgo).SetValue(labelRSA)
	f.fieldByName(fieldKeySize).SetValue("2048")

	m := RootModel{activeForm: f, activeFormKind: formCreateKey, passwordCache: newPasswordCache()}
	cmds, err := m.openSSLForForm()
	if err != nil {
		t.Fatalf("openSSLForForm: %v", err)
	}
	popup := openSSLPopup(cmds)
	if popup.kind != popupCommand {
		t.Fatalf("popup kind = %v, want popupCommand", popup.kind)
	}
	if !strings.Contains(popup.message, "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048") {
		t.Errorf("popup message missing genpkey command:\n%s", popup.message)
	}
}

func TestOpenSSLForForm_CreateCSR(t *testing.T) {
	f := buildCreateCSRForm("/tmp", nil, "", "", certlib.KeyGenOptions{})
	f.fieldByName(fieldKeyCn).SetValue("example.com")

	m := RootModel{activeForm: f, activeFormKind: formCreateCSR, passwordCache: newPasswordCache()}
	cmds, err := m.openSSLForForm()
	if err != nil {
		t.Fatalf("openSSLForForm: %v", err)
	}
	popup := openSSLPopup(cmds)
	if !strings.Contains(popup.message, "openssl req -new") {
		t.Errorf("popup message missing req command:\n%s", popup.message)
	}
	if !strings.Contains(popup.message, "/CN=example.com") {
		t.Errorf("popup message missing subject:\n%s", popup.message)
	}
}

// TestRemoteDetailOpenSSLKey is the M10 regression: the 'o' key in a remote
// split detail must open the openssl (s_client) popup that the footer advertises.
func TestRemoteDetailOpenSSLKey(t *testing.T) {
	d := &detailModel{source: "example.com:443"}
	m := RootModel{state: stateSplit, focus: focusDetail, detail: d}

	updated, _ := m.handleSplitKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'o'}})
	rm := updated.(RootModel)
	if rm.popup.kind != popupCommand {
		t.Fatalf("expected an openssl popup after 'o', got kind %v", rm.popup.kind)
	}
	if !strings.Contains(rm.popup.message, "openssl s_client") {
		t.Errorf("popup missing s_client command:\n%s", rm.popup.message)
	}
	if !strings.Contains(rm.popup.message, "example.com") {
		t.Errorf("popup missing the target host:\n%s", rm.popup.message)
	}
}

func TestFormOpenSSLHintGating(t *testing.T) {
	eligible := buildForm(formCreateKey, "/tmp", nil, "", "", certlib.KeyGenOptions{}, 365, 3650)
	if eligible == nil || !eligible.opensslEligible {
		t.Fatal("create-key form should be openssl-eligible")
	}
	notEligible := buildForm(formReencrypt, "/tmp", nil, "", "", certlib.KeyGenOptions{}, 365, 3650)
	if notEligible != nil && notEligible.opensslEligible {
		t.Error("reencrypt form should not be openssl-eligible")
	}
}
