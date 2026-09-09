package cmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runPromptBinary(t *testing.T, configPath string, args ...string) (int, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, remoteTestBinary, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG="+configPath, "CERTDIAG_MASTER_KEY=")

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer devnull.Close()
	cmd.Stdin = devnull

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("binary hung (deadline exceeded); args=%v", args)
	}

	code := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running binary: %v", runErr)
		}
	}
	return code, stderr.String()
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestPasswordPromptSkippedWithoutEncryptedPasswords(t *testing.T) {
	cfg := writeConfig(t, "kind: certdiag-config\nversion: \"1\"\n")
	scanDir := t.TempDir()

	code, stderr := runPromptBinary(t, cfg, "-i", scanDir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, "master password:") {
		t.Errorf("resolve path exercised without encrypted passwords; stderr=%q", stderr)
	}
}

func TestPasswordPromptResolvedWithEncryptedPasswords(t *testing.T) {
	cfg := writeConfig(t, "kind: certdiag-config\nversion: \"1\"\npasswords:\n  common_encrypted:\n    - \"base64encryptedblob==\"\n")
	scanDir := t.TempDir()

	code, stderr := runPromptBinary(t, cfg, "-i", scanDir)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "master password: not provided") {
		t.Errorf("resolve path not exercised with encrypted passwords; stderr=%q", stderr)
	}
}
