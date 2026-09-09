package cmd

import (
	"bytes"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestPEM(t *testing.T, dir string) {
	t.Helper()
	_, _, der := makeSelfSigned(t)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(block), 0644); err != nil {
		t.Fatal(err)
	}
}

// runListStdout runs the built binary and returns only stdout, so assertions on
// jsonpath output are not polluted by stderr notices (e.g. config auto-creation).
func runListStdout(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected error running binary: %v", err)
		}
	}
	return stdout.String(), code
}

func TestListJSONPathScalar(t *testing.T) {
	dir := t.TempDir()
	writeTestPEM(t, dir)

	out, code := runListStdout(t, dir, "list", "-o", "jsonpath=$.files[*].items[*].certificate.subject")
	if code != 0 {
		t.Fatalf("jsonpath exit=%d, want 0; output: %s", code, out)
	}
	if strings.TrimSpace(out) != "list-alias-test" {
		t.Fatalf("expected bare subject %q, got: %q", "list-alias-test", out)
	}
	// It must be the extracted value, not the full human/list rendering.
	if strings.Contains(out, "Subject:") || strings.Contains(out, "Certificate") {
		t.Fatalf("jsonpath output leaked list formatting: %s", out)
	}
}

func TestListJSONPathKubectlLeadingDot(t *testing.T) {
	dir := t.TempDir()
	writeTestPEM(t, dir)

	out, code := runListStdout(t, dir, "list", "-o", "jsonpath=.files[*].format")
	if code != 0 {
		t.Fatalf("jsonpath exit=%d, want 0; output: %s", code, out)
	}
	if strings.TrimSpace(out) != "pem" {
		t.Fatalf("expected %q, got: %q", "pem", out)
	}
}

func TestListJSONPathBadExprExits(t *testing.T) {
	dir := t.TempDir()
	writeTestPEM(t, dir)

	out, code := runListBinary(t, dir, "list", "-o", "jsonpath=$.nonexistent")
	if code == 0 {
		t.Fatalf("bad jsonpath should exit non-zero; output: %s", out)
	}
}

func TestListJSONPathInvalidFormatRejected(t *testing.T) {
	dir := t.TempDir()
	writeTestPEM(t, dir)

	out, code := runListBinary(t, dir, "list", "-o", "xml")
	if code == 0 {
		t.Fatalf("unknown format should exit non-zero; output: %s", out)
	}
	if !strings.Contains(out, "jsonpath=EXPR") {
		t.Fatalf("format error should advertise jsonpath option; got: %s", out)
	}
}
