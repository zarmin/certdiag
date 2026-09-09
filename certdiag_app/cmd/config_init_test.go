package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runWithHome runs the test binary with HOME pointed at home, so the test can
// look at what the command left behind there.
func runWithHome(t *testing.T, home string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = home
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "CERTDIAG_CONFIG=", "NO_COLOR=1")
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

// TestNoCommandWritesConfigOnFirstRun: a read-only diagnostic leaves $HOME
// alone. Scans, checks, config show and config path must all run in a fresh
// home without creating ~/.certdiag/.
func TestNoCommandWritesConfigOnFirstRun(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "a.crt")
	_, _, der := makeSelfSigned(t)
	writePEMFile(t, cert, "CERTIFICATE", der)
	commands := [][]string{
		{cert},
		{"list", cert},
		{"check", cert},
		{"-o", "json", cert},
		{"config", "show"},
		{"config", "path"},
		{"store", "--mozilla"},
		{"templates", "cert"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			home := t.TempDir()
			out, _ := runWithHome(t, home, args...)
			if strings.Contains(out, "created example config") {
				t.Errorf("output announces a config write:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(home, ".certdiag")); !os.IsNotExist(err) {
				t.Errorf("%s created ~/.certdiag in a fresh home", strings.Join(args, " "))
			}
		})
	}
}

func TestConfigInitAndPath(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".certdiag", "certdiag.yaml")

	out, code := runWithHome(t, home, "config", "path")
	if code != 0 || !strings.Contains(out, target) || !strings.Contains(out, "not found") {
		t.Fatalf("config path before init: exit %d\n%s", code, out)
	}

	out, code = runWithHome(t, home, "config", "init")
	if code != 0 || !strings.Contains(out, target) {
		t.Fatalf("config init: exit %d\n%s", code, out)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("config init wrote nothing: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("config file mode %o, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "kind: certdiag-config") {
		t.Errorf("config init did not write the example template:\n%s", data)
	}

	out, code = runWithHome(t, home, "config", "path")
	if code != 0 || !strings.Contains(out, "Status: exists") {
		t.Errorf("config path after init: exit %d\n%s", code, out)
	}

	out, code = runWithHome(t, home, "config", "init")
	if code != 1 || !strings.Contains(out, "already exists") {
		t.Errorf("second config init must refuse: exit %d\n%s", code, out)
	}

	if err := os.WriteFile(target, []byte("kind: certdiag-config\nversion: \"1\"\n# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runWithHome(t, home, "config", "init", "--force")
	if code != 0 {
		t.Fatalf("config init --force: exit %d\n%s", code, out)
	}
	data, _ = os.ReadFile(target)
	if strings.Contains(string(data), "# mine") {
		t.Error("config init --force left the old file in place")
	}
}

func TestConfigInitRefusesWhileLegacyIsInEffect(t *testing.T) {
	home := t.TempDir()
	legacy := filepath.Join(home, ".certdiag.yaml")
	if err := os.WriteFile(legacy, []byte("kind: certdiag-config\nversion: \"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runWithHome(t, home, "config", "path")
	if code != 0 || !strings.Contains(out, legacy) || !strings.Contains(out, "legacy") {
		t.Errorf("config path with a legacy file: exit %d\n%s", code, out)
	}
	out, code = runWithHome(t, home, "config", "init")
	if code != 1 || !strings.Contains(out, "config migrate") {
		t.Errorf("config init must point at migrate: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".certdiag")); !os.IsNotExist(err) {
		t.Error("config init wrote the new file next to a legacy one")
	}
}
