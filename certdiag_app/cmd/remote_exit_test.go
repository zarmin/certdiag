package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

var remoteTestBinary string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "certdiag-remote-exit")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	binName := "certdiag"
	if runtime.GOOS == "windows" {
		// go build -o auto-appends .exe on Windows; match it so exec finds the file.
		binName += ".exe"
	}
	remoteTestBinary = filepath.Join(tmpDir, binName)
	build := exec.Command("go", "build", "-o", remoteTestBinary, "github.com/zarmin/certdiag/certdiag_app")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		panic("failed to build test binary: " + buildErr.Error() + "\n" + string(out))
	}

	os.Exit(m.Run())
}

func runRemoteBinary(t *testing.T, args ...string) int {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	// Isolate HOME so config resolution stays hermetic.
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("unexpected error running binary: %v", err)
	return -1
}

func TestRemoteUsageErrorsExitOne(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"mutually_exclusive_ip", []string{"remote", "check", "--ipv4", "--ipv6", "example.com:443"}},
		{"invalid_timeout", []string{"remote", "check", "--timeout", "notaduration", "example.com:443"}},
		{"invalid_tls_version", []string{"remote", "check", "--tls-version", "bogus", "example.com:443"}},
		{"invalid_starttls", []string{"remote", "fetch", "--starttls", "bogus", "example.com:443"}},
		{"invalid_proxy", []string{"remote", "probe", "--proxy", "ftp://bad", "example.com:443"}},
		{"invalid_severity", []string{"remote", "check", "--severity", "bogus", "example.com:443"}},
		{"invalid_output", []string{"remote", "check", "--output", "bogus", "example.com:443"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := runRemoteBinary(t, tt.args...)
			if code != 1 {
				t.Errorf("%v exit code = %d, want 1 (usage error must not collide with 2=CRITICAL)", tt.args, code)
			}
		})
	}
}

// TestAutodetectRemoteExitConvention is the M14 regression: 'certdiag <host>'
// (autodetected remote) follows the root 0/1 contract, so a connection failure
// exits 1, while the explicit 'remote fetch' keeps its richer 0/1/2/3 codes
// (3 = target error).
func TestAutodetectRemoteExitConvention(t *testing.T) {
	const refused = "127.0.0.1:1" // connection refused, fast and deterministic

	if code := runRemoteBinary(t, refused); code != 1 {
		t.Errorf("autodetect 'certdiag %s' exit = %d, want 1 (root 0/1 contract)", refused, code)
	}
	if code := runRemoteBinary(t, "remote", "fetch", refused); code != 3 {
		t.Errorf("explicit 'remote fetch %s' exit = %d, want 3 (target error)", refused, code)
	}
}

// TestAutodetectRemoteInapplicableFlags is the LOW regression: filesystem-scan
// flags on an autodetected remote target are rejected (exit 1), not silently
// ignored.
func TestAutodetectRemoteInapplicableFlags(t *testing.T) {
	for _, flag := range []string{"--recursive", "--check", "--query=x", "--depth=2"} {
		if code := runRemoteBinary(t, "example.com", flag); code != 1 {
			t.Errorf("'certdiag example.com %s' exit = %d, want 1 (flag does not apply)", flag, code)
		}
	}
}

func TestCheckEnumValidation(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"bogus_severity", []string{"check", "--severity", "bogus"}, 1},
		{"bogus_output", []string{"check", "--output", "bogus"}, 1},
		{"valid_severity", []string{"check", "--severity", "warning"}, 0},
		{"valid_output", []string{"check", "--output", "json"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := runRemoteBinary(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("%v exit code = %d, want %d", tt.args, code, tt.wantCode)
			}
		})
	}
}
