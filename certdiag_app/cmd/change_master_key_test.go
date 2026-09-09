package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/config"
	"github.com/zarmin/certdiag/certdiag_app/internal/crypto"
)

func runWithEnv(t *testing.T, dir string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "HOME="+dir, "CERTDIAG_CONFIG=", "NO_COLOR=1"), env...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("run: %v", err)
	return "", -1
}

// TestChangeMasterKey_RoundTrip (M31 WP12): the new key can come from the
// environment or a file, and every encrypted entry decrypts with it afterwards.
func TestChangeMasterKey_RoundTrip(t *testing.T) {
	for _, mode := range []string{"env", "file"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			oldKey, newKey := "old-master-1", "new-master-2"
			enc1, _ := crypto.Encrypt([]byte(oldKey), []byte("secret-one"))
			enc2, _ := crypto.Encrypt([]byte(oldKey), []byte("secret-two"))
			cfgPath := filepath.Join(dir, "certdiag.yaml")
			cfgText := "kind: certdiag-config\nversion: \"1\"\npasswords:\n  common_encrypted:\n    - " + enc1 +
				"\n  by_filename:\n    - filename: \"*.p12\"\n      encrypted_password: " + enc2 + "\n"
			os.WriteFile(cfgPath, []byte(cfgText), 0o600)

			env := []string{"CERTDIAG_MASTER_KEY=" + oldKey}
			args := []string{"-c", cfgPath, "password", "change-master-key"}
			if mode == "env" {
				env = append(env, "CERTDIAG_NEW_MASTER_KEY="+newKey)
			} else {
				pwFile := filepath.Join(dir, "new.txt")
				os.WriteFile(pwFile, []byte(newKey+"\nignored second line\n"), 0o600)
				args = append(args, "--new-master-password-file", pwFile)
			}
			out, code := runWithEnv(t, dir, env, args...)
			if code != 0 || !strings.Contains(out, "changed successfully") {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			if _, err := os.Stat(cfgPath + ".bak"); err != nil {
				t.Error("a backup must be written before the rewrite")
			}
			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := crypto.Decrypt([]byte(newKey), cfg.Passwords.CommonEncrypted[0]); err != nil || string(got) != "secret-one" {
				t.Errorf("common_encrypted after rotation: %q %v", got, err)
			}
			if got, err := crypto.Decrypt([]byte(newKey), cfg.Passwords.ByFilename[0].EncryptedPassword); err != nil || string(got) != "secret-two" {
				t.Errorf("by_filename after rotation: %q %v", got, err)
			}
		})
	}
	t.Run("too short", func(t *testing.T) {
		dir := t.TempDir()
		enc, _ := crypto.Encrypt([]byte("old-master-1"), []byte("s"))
		cfgPath := filepath.Join(dir, "certdiag.yaml")
		os.WriteFile(cfgPath, []byte("kind: certdiag-config\nversion: \"1\"\npasswords:\n  common_encrypted:\n    - "+enc+"\n"), 0o600)
		out, code := runWithEnv(t, dir, []string{"CERTDIAG_MASTER_KEY=old-master-1", "CERTDIAG_NEW_MASTER_KEY=abc"}, "-c", cfgPath, "password", "change-master-key")
		if code != 1 || !strings.Contains(out, "at least 6") {
			t.Errorf("a short new key must be refused: exit %d\n%s", code, out)
		}
	})
}
