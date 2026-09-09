package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPcapCheckHonoursDisabledChecks guards R9: `pcap check` runs the shared
// analysis, so defaults.check.disabled_checks applies to a capture too.
func TestPcapCheckHonoursDisabledChecks(t *testing.T) {
	pcap, err := filepath.Abs(filepath.Join("..", "..", "tools", "testing", "testdata", "tls_handshake.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pcap); err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	dir := t.TempDir()

	out, code := runInDir(t, dir, "--no-color", "pcap", "check", pcap)
	if code != 0 {
		t.Fatalf("pcap check exit %d:\n%s", code, out)
	}
	ids := regexp.MustCompile(`\[([a-z0-9_]+)\]`).FindAllStringSubmatch(out, -1)
	if len(ids) == 0 {
		t.Skip("the capture yields no findings to disable")
	}
	seen := map[string]bool{}
	var yaml strings.Builder
	yaml.WriteString("kind: certdiag-config\nversion: \"1\"\ndefaults:\n  check:\n    disabled_checks:\n")
	for _, m := range ids {
		if !seen[m[1]] {
			seen[m[1]] = true
			yaml.WriteString("      - " + m[1] + "\n")
		}
	}
	cfg := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfg, []byte(yaml.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	out, code = runInDir(t, dir, "--no-color", "-c", cfg, "pcap", "check", pcap)
	if code != 0 {
		t.Fatalf("pcap check with config exit %d:\n%s", code, out)
	}
	for id := range seen {
		if strings.Contains(out, "["+id+"]") {
			t.Errorf("check %s is disabled in the config but still reported:\n%s", id, out)
		}
	}
}
