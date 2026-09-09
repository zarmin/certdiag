package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigLoadErrorIsUniform runs every command that reads the config with
// a missing and with a malformed config file. All of them must exit 1 and say
// so with the same message, whichever code path loads the config (M15, T10).
func TestConfigLoadErrorIsUniform(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "a.crt")
	key := filepath.Join(dir, "a.key")
	_, _, der := makeSelfSigned(t)
	writePEMFile(t, cert, "CERTIFICATE", der)
	if err := os.WriteFile(key, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(broken, []byte(": : : [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")

	// OUT is replaced by a fresh directory per run so write commands never
	// trip over their own output from the previous config variant. Commands
	// that never read the config (version, schema, completion, store discover)
	// are not listed.
	commands := [][]string{
		{dir},
		{"list", dir},
		{"check", dir},
		{"diff", cert, cert},
		{"convert", cert, "-o", "OUT/out.pem"},
		{"extract", cert, "-o", "OUT"},
		{"bundle", cert, "-o", "OUT/b.pem"},
		{"reencrypt", key, "-p", "x", "--new-password", "y", "-o", "OUT/k2.key"},
		{"verify", cert},
		{"store", "list"},
		{"templates", "cert"},
		{"create-key", "-o", "OUT/new.key"},
		{"create-cert", "--subject", "CN=x", "-o", "OUT/x.crt"},
		{"create-csr", "--subject", "CN=x", "-o", "OUT/x.csr"},
		{"sign", cert, "--ca-cert", cert, "--ca-key", key, "-o", "OUT/s.crt"},
		{"renew", cert, "-o", "OUT/r.crt"},
		{"config", "show"},
		{"aia", "cache", "list"},
	}

	for _, cfgFile := range []string{missing, broken} {
		for _, args := range commands {
			name := filepath.Base(cfgFile) + "/" + strings.Join(args[:min(2, len(args))], " ")
			t.Run(name, func(t *testing.T) {
				outDir := t.TempDir()
				full := []string{"-c", cfgFile}
				for _, a := range args {
					full = append(full, strings.Replace(a, "OUT", outDir, 1))
				}
				cmd := exec.Command(remoteTestBinary, full...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "CERTDIAG_CONFIG=", "NO_COLOR=1")
				out, err := cmd.CombinedOutput()
				code := 0
				if err != nil {
					if ee, ok := err.(*exec.ExitError); ok {
						code = ee.ExitCode()
					} else {
						t.Fatalf("run: %v", err)
					}
				}
				want := 1
				if args[0] == "diff" {
					want = 2 // diff documents 2 for every error
				}
				if code != want {
					t.Errorf("exit %d, want %d\n%s", code, want, out)
				}
				s := string(out)
				if !strings.Contains(s, "Error loading config") && !strings.Contains(s, "Config file not found") {
					t.Errorf("no config error reported:\n%s", s)
				}
			})
		}
	}
}
