//go:build dockertest

package certops

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The only place the real OS trust store and the real verifier are exercised.
//
// Everywhere else that is impossible to assert on: the store differs per machine
// and per CI runner. Here the store is ours -- a Debian image with the testinfra
// root CA installed via update-ca-certificates -- so "does the OS-store path
// actually work" has a known-correct answer.

const trustImage = "certdiag-trustlinux:test"

// dockerPlatform pins image build and run to the host architecture. Mixing them
// makes docker try to pull a variant that was never built, which surfaces as a
// confusing "pull access denied".
func dockerPlatform() string { return "linux/" + runtime.GOARCH }

var (
	trustImageOnce  sync.Once
	trustImageErr   error
	trustBinaryOnce sync.Once
	trustBinary     string
	trustBinaryErr  error
)

func testinfraDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	// internal/certops -> internal -> certdiag_app -> repo root
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
	dir := filepath.Join(root, "tools", "testinfra")
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile.trustlinux")); err != nil {
		t.Skipf("testinfra not found at %s: %v", dir, err)
	}
	return dir
}

// buildTrustImage builds the controlled-store image once per run.
func buildTrustImage(t *testing.T, dir string) {
	t.Helper()
	trustImageOnce.Do(func() {
		cmd := exec.Command("docker", "build",
			"--platform", dockerPlatform(),
			"-f", filepath.Join(dir, "Dockerfile.trustlinux"),
			"-t", trustImage, dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			trustImageErr = fmt.Errorf("%v:\n%s", err, out)
		}
	})
	if trustImageErr != nil {
		t.Skipf("could not build the trust image: %v", trustImageErr)
	}
}

// buildLinuxBinary cross-compiles certdiag for the container, once per run and
// into a directory that outlives any single test.
func buildLinuxBinary(t *testing.T) string {
	t.Helper()
	trustBinaryOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		appDir := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

		dir, err := os.MkdirTemp("", "certdiag-trustbin-")
		if err != nil {
			trustBinaryErr = err
			return
		}
		out := filepath.Join(dir, "certdiag")

		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = appDir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
		if outBytes, err := cmd.CombinedOutput(); err != nil {
			trustBinaryErr = fmt.Errorf("cross-compiling for %s failed (%v):\n%s", dockerPlatform(), err, outBytes)
			return
		}
		trustBinary = out
	})
	if trustBinaryErr != nil {
		t.Fatalf("%v", trustBinaryErr)
	}
	return trustBinary
}

// runInTrustImage executes certdiag inside the controlled-store container.
func runInTrustImage(t *testing.T, binary, certsDir string, args ...string) (string, string, int) {
	t.Helper()

	full := append([]string{
		"run", "--rm", "--platform", dockerPlatform(),
		"-v", binary + ":/certdiag:ro",
		"-v", certsDir + ":/certs:ro",
		trustImage, "/certdiag",
	}, args...)

	cmd := exec.Command("docker", full...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("docker run: %v", err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		code := 0
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("docker run: %v (stderr: %s)", err, stderr.String())
		}
		return stdout.String(), stderr.String(), code
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("certdiag in the trust container timed out")
		return "", "", -1
	}
}

type dockerTrustCert struct {
	Subject string `json:"subject"`
	Trust   string `json:"trust"`
	Anchor  string `json:"trust_anchor"`
}

func dockerTrustCerts(t *testing.T, stdout string) []dockerTrustCert {
	t.Helper()
	var parsed struct {
		Files []struct {
			Items []struct {
				Certificate *dockerTrustCert `json:"certificate"`
			} `json:"items"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("output was not valid JSON: %v\n%s", err, stdout)
	}
	var out []dockerTrustCert
	for _, f := range parsed.Files {
		for _, i := range f.Items {
			if i.Certificate != nil {
				out = append(out, *i.Certificate)
			}
		}
	}
	return out
}

func setupTrustContainer(t *testing.T) (binary, certsDir string) {
	t.Helper()
	dir := testinfraDir(t)
	buildTrustImage(t, dir)
	return buildLinuxBinary(t), filepath.Join(dir, "certs")
}

// TestDockerTrust_InstalledRootIsAnchor: the CA the image installed into the
// system store must read ANCHOR. If this fails, ReadOSStore is not seeing the
// Linux bundle at all.
func TestDockerTrust_InstalledRootIsAnchor(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	stdout, stderr, code := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/ca.crt")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	got := dockerTrustCerts(t, stdout)
	if len(got) != 1 {
		t.Fatalf("expected one certificate, got %d", len(got))
	}
	if got[0].Trust != "anchor" {
		t.Errorf("the installed root must read anchor, got %q (%s)", got[0].Trust, got[0].Subject)
	}
}

// TestDockerTrust_LeafChainsToInstalledRoot is the end-to-end claim: a leaf
// signed by the installed CA is trusted, and the anchor is named.
func TestDockerTrust_LeafChainsToInstalledRoot(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	stdout, stderr, code := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/server.crt")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	got := dockerTrustCerts(t, stdout)
	if len(got) == 0 {
		t.Fatal("expected at least one certificate")
	}
	leaf := got[0]
	if leaf.Trust != "trusted" {
		t.Errorf("a leaf signed by the installed CA must read trusted, got %q", leaf.Trust)
	}
	if leaf.Anchor == "" {
		t.Error("a trusted leaf must name the anchor that terminated the chain")
	}
}

// TestDockerTrust_UnknownSelfSignedIsUntrusted is the negative control: without
// it, a bug that reports everything trusted would pass the two tests above.
func TestDockerTrust_UnknownSelfSignedIsUntrusted(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	stdout, stderr, code := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/selfsigned.crt")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	got := dockerTrustCerts(t, stdout)
	if len(got) != 1 {
		t.Fatalf("expected one certificate, got %d", len(got))
	}
	if got[0].Trust != "untrusted" {
		t.Errorf("a certificate the store does not know must read untrusted, got %q", got[0].Trust)
	}
}

// TestDockerTrust_ExpiredLeafIsNotSilentlyTrusted: an expired certificate under
// the installed CA must not read trusted.
func TestDockerTrust_ExpiredLeafIsNotSilentlyTrusted(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	if _, err := os.Stat(filepath.Join(certs, "expired.crt")); err != nil {
		t.Skipf("expired.crt not present: %v", err)
	}

	stdout, stderr, code := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/expired.crt")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", code, stderr)
	}

	got := dockerTrustCerts(t, stdout)
	if len(got) != 1 {
		t.Fatalf("expected one certificate, got %d", len(got))
	}
	if got[0].Trust == "trusted" || got[0].Trust == "anchor" {
		t.Errorf("an expired certificate must not read trusted, got %q", got[0].Trust)
	}
}

// TestDockerTrust_VerifyAgreesWithTheColumn: `certdiag verify` (whose default
// store is the OS) and the TRUST column answer the same question, so they must
// agree on the same input.
//
// They use different engines on purpose -- verify hands a nil pool to the
// platform verifier, the column builds an explicit pool from the store contents
// -- so this is the test that would catch that divergence becoming visible.
func TestDockerTrust_VerifyAgreesWithTheColumn(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	stdout, _, _ := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/server.crt")
	got := dockerTrustCerts(t, stdout)
	if len(got) == 0 {
		t.Fatal("expected a certificate")
	}
	columnSaysTrusted := got[0].Trust == "trusted" || got[0].Trust == "anchor"

	vOut, vErr, vCode := runInTrustImage(t, binary, certs, "verify", "/certs/server.crt")
	verifySaysTrusted := vCode == 0 && !strings.Contains(strings.ToLower(vOut+vErr), "not trusted")

	if columnSaysTrusted != verifySaysTrusted {
		t.Errorf("verify --os and the TRUST column disagree: column=%v verify=%v\nverify output: %s%s",
			columnSaysTrusted, verifySaysTrusted, vOut, vErr)
	}
}

// TestDockerTrust_NoBrowserProfilesIsQuiet: a server with no browser installed
// must not turn the missing NSS profiles into an error.
func TestDockerTrust_NoBrowserProfilesIsQuiet(t *testing.T) {
	binary, certs := setupTrustContainer(t)

	stdout, stderr, code := runInTrustImage(t, binary, certs, "--trust", "-o", "json", "/certs/ca.crt")
	if code != 0 {
		t.Fatalf("expected exit 0 with no browser profiles, got %d\nstderr: %s", code, stderr)
	}
	if strings.Contains(stderr, "panic") {
		t.Errorf("no browser profiles must not panic:\n%s", stderr)
	}
	if !json.Valid([]byte(stdout)) {
		t.Errorf("stdout must stay parseable:\n%s", stdout)
	}
}
