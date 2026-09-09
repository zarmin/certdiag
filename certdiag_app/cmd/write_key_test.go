package cmd

import (
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writePEMFile(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runInDir(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(remoteTestBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=", "NO_COLOR=1")
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

func keyFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			keys = append(keys, e.Name())
		}
	}
	return keys
}

// TestGeneratedKeyIsNeverLost guards H1 (decision D1): a command that generates
// a private key and writes the certificate or CSR to a file must either write
// the key next to it, or refuse. Exiting 0 with the key discarded is the one
// outcome that is never acceptable.
func TestGeneratedKeyIsNeverLost(t *testing.T) {
	t.Run("create-cert", func(t *testing.T) {
		dir := t.TempDir()
		out, code := runInDir(t, dir, "create-cert", "--with-key", "--subject", "CN=keyloss", "-o", filepath.Join(dir, "x.crt"))
		keys := keyFilesIn(t, dir)
		if code == 0 && len(keys) == 0 {
			t.Fatalf("exit 0 and no key file written:\n%s", out)
		}
		if code == 0 && !strings.Contains(out, keys[0]) {
			t.Errorf("key written as %s but the output does not mention it:\n%s", keys[0], out)
		}
	})

	t.Run("create-csr", func(t *testing.T) {
		dir := t.TempDir()
		out, code := runInDir(t, dir, "create-csr", "--with-key", "--subject", "CN=keyloss", "-o", filepath.Join(dir, "x.csr"))
		keys := keyFilesIn(t, dir)
		if code == 0 && len(keys) == 0 {
			t.Fatalf("exit 0 and no key file written:\n%s", out)
		}
	})

	t.Run("renew-new-key", func(t *testing.T) {
		dir := t.TempDir()
		_, code := runInDir(t, dir, "create-cert", "--with-key", "--subject", "CN=orig", "-o", filepath.Join(dir, "orig.crt"), "--key-output", filepath.Join(dir, "orig.key"))
		if code != 0 {
			t.Fatalf("setup create-cert failed with %d", code)
		}
		out, code := runInDir(t, dir, "renew", filepath.Join(dir, "orig.crt"), "-k", filepath.Join(dir, "orig.key"), "--new-key", "-o", filepath.Join(dir, "renewed.crt"))
		keys := keyFilesIn(t, dir)
		if code == 0 && len(keys) < 2 {
			t.Fatalf("exit 0 and the new key was not written (keys: %v):\n%s", keys, out)
		}
	})

	t.Run("stdout-carries-both-blocks", func(t *testing.T) {
		dir := t.TempDir()
		out, code := runInDir(t, dir, "create-cert", "--with-key", "--subject", "CN=stdout")
		if code != 0 {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if !strings.Contains(out, "BEGIN CERTIFICATE") || !strings.Contains(out, "PRIVATE KEY") {
			t.Errorf("stdout must carry the certificate and the key:\n%s", out)
		}
	})
}
