package password

import (
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

// TestPasswordsForFile_BuiltInIsLast: the built-in keystore default is offered
// for every file, after everything the user configured, and tagged as such.
func TestPasswordsForFile_BuiltInIsLast(t *testing.T) {
	cfg := &config.ConfigFile{}
	cfg.Passwords.CommonPlaintext = []string{"fromconfig"}
	pm, err := NewPasswordManager(PasswordManagerOpts{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	got := pm.PasswordsForFile("/opt/jdk/lib/security/cacerts")
	if len(got) != 2 {
		t.Fatalf("passwords %v, want config entry then built-in", got)
	}
	if got[0].Source != certlib.PasswordSourceCommonPlaintext {
		t.Errorf("first source %q, want common plaintext", got[0].Source)
	}
	last := got[len(got)-1]
	if last.Source != certlib.PasswordSourceBuiltIn || string(last.Password) != "changeit" {
		t.Errorf("last password %q source %q, want built-in changeit", last.Password, last.Source)
	}
}

// TestPasswordsForFile_NoTryAllExcludesBuiltIn: --no-try-all-passwords means
// only file-specific matches, and a built-in guess is the opposite of that.
func TestPasswordsForFile_NoTryAllExcludesBuiltIn(t *testing.T) {
	pm, err := NewPasswordManager(PasswordManagerOpts{NoTryAll: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := pm.PasswordsForFile("/opt/jdk/lib/security/cacerts"); len(got) != 0 {
		t.Errorf("no-try-all must offer nothing, got %v", got)
	}
}
