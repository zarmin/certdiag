package password

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

// TestReadPasswordFile_CommentsAndPadding: `#` lines are comments, padding
// is not part of a password, a BOM is invisible.
func TestReadPasswordFile_CommentsAndPadding(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pw.txt")
	os.WriteFile(p, []byte("\xEF\xBB\xBF# comment\n  padded  \r\n\n#another\nplain\n"), 0o600)
	got, err := readPasswordFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "padded" || string(got[1]) != "plain" {
		t.Errorf("got %q", got)
	}
}

func TestCollectEnvPasswords_EmptyValue(t *testing.T) {
	t.Setenv("CERTDIAG_PASSWORD_EDGE", "")
	t.Setenv("CERTDIAG_PASSWORD_REAL", "x")
	got := CollectEnvPasswords()
	seenEmpty, seenReal := false, false
	for _, pw := range got {
		if string(pw) == "" {
			seenEmpty = true
		}
		if string(pw) == "x" {
			seenReal = true
		}
	}
	if !seenEmpty || !seenReal {
		t.Errorf("empty and set values must both be collected, got %q", got)
	}
}

// TestPasswordsForFile_ConfigMatches: by_filename entries match by basename
// glob or by exact filepath; a relative filepath entry only matches the same
// string, never the absolute path of the same file.
func TestPasswordsForFile_ConfigMatches(t *testing.T) {
	cfg := &config.ConfigFile{}
	cfg.Passwords.ByFilename = []config.FilenamePassword{
		{Filename: "*.p12", PlaintextPassword: "glob"},
		{Filepath: "/abs/store.jks", PlaintextPassword: "exact"},
		{Filepath: "rel/store.jks", PlaintextPassword: "relative"},
	}
	pm, err := NewPasswordManager(PasswordManagerOpts{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	values := func(path string) []string {
		var out []string
		for _, tp := range pm.PasswordsForFile(path) {
			// The built-in keystore default trails every list; this test is
			// about the config matches in front of it.
			if tp.Source == certlib.PasswordSourceBuiltIn {
				continue
			}
			out = append(out, string(tp.Password))
		}
		return out
	}
	if v := values("/x/keys/site.p12"); len(v) != 1 || v[0] != "glob" {
		t.Errorf("glob: %v", v)
	}
	if v := values("/abs/store.jks"); len(v) != 1 || v[0] != "exact" {
		t.Errorf("exact filepath: %v", v)
	}
	if v := values("rel/store.jks"); len(v) != 1 || v[0] != "relative" {
		t.Errorf("relative filepath, same string: %v", v)
	}
	if v := values("/cwd/rel/store.jks"); len(v) != 0 {
		t.Errorf("relative filepath must not match an absolute path: %v", v)
	}
}

func TestInteractive_OffByDefault(t *testing.T) {
	pm, _ := NewPasswordManager(PasswordManagerOpts{CLIPasswords: []string{"a"}})
	if pm.IsInteractive() {
		t.Error("not interactive unless asked")
	}
	if pm.HandleInteractive("/x.p12", func([]byte) bool { return true }) {
		t.Error("HandleInteractive must refuse when not interactive")
	}
}
