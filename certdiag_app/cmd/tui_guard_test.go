package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const nestedShellGuardMsg = "cannot start TUI inside a certdiag subshell"

func runGuardBinary(t *testing.T, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	cmd.Env = append(cmd.Env, env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running binary: %v", err)
		}
	}
	return code, stderr.String()
}

func TestTUINestedShellGuard(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"tui", []string{"tui"}},
		{"tui_pcap", []string{"tui", "pcap", "/nonexistent.pcap"}},
		{"tui_proxy", []string{"tui", "proxy", "--listen", "127.0.0.1:0", "--target", "127.0.0.1:1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stderr := runGuardBinary(t, []string{"CERTDIAG_SHELL=1"}, tt.args...)
			if code != 1 {
				t.Errorf("%v under CERTDIAG_SHELL exit code = %d, want 1", tt.args, code)
			}
			if !strings.Contains(stderr, nestedShellGuardMsg) {
				t.Errorf("%v under CERTDIAG_SHELL stderr = %q, want guard message %q", tt.args, stderr, nestedShellGuardMsg)
			}
		})
	}
}
