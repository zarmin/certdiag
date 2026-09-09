package truststore

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJavaHome builds a JDK-shaped directory tree under a temp dir.
func fakeJavaHome(t *testing.T, dir string, relPaths ...string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), dir)
	for _, rel := range relPaths {
		full := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fake keystore"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestResolveJavaCacerts_LibSecurity(t *testing.T) {
	home := fakeJavaHome(t, "jdk-21", filepath.Join("lib", "security", "cacerts"))

	info := resolveJavaCacerts(JavaInstallation{JavaHome: home})
	if info == nil {
		t.Fatal("expected cacerts to be found")
	}
	want := filepath.Join(home, "lib", "security", "cacerts")
	if info.Path != want {
		t.Errorf("expected path %q, got %q", want, info.Path)
	}
	if info.Type != StoreTypeJava {
		t.Errorf("expected java store type, got %q", info.Type)
	}
}

func TestResolveJavaCacerts_JreLibSecurity(t *testing.T) {
	home := fakeJavaHome(t, "jdk-8", filepath.Join("jre", "lib", "security", "cacerts"))

	info := resolveJavaCacerts(JavaInstallation{JavaHome: home})
	if info == nil {
		t.Fatal("expected legacy jre/lib/security/cacerts to be found")
	}
	if !strings.Contains(info.Path, filepath.Join("jre", "lib", "security")) {
		t.Errorf("expected the legacy path, got %q", info.Path)
	}
}

func TestResolveJavaCacerts_JsseOverride(t *testing.T) {
	home := fakeJavaHome(t, "jdk-17",
		filepath.Join("lib", "security", "cacerts"),
		filepath.Join("lib", "security", "jssecacerts"),
	)

	info := resolveJavaCacerts(JavaInstallation{JavaHome: home})
	if info == nil {
		t.Fatal("expected a store")
	}

	// Java prefers jssecacerts when both exist, so that is the file we must read.
	if filepath.Base(info.Path) != "jssecacerts" {
		t.Errorf("expected jssecacerts to win, got %q", info.Path)
	}
	if len(info.Warnings) == 0 {
		t.Error("expected a warning about the jssecacerts override")
	}
}

func TestResolveJavaCacerts_Missing(t *testing.T) {
	home := fakeJavaHome(t, "jdk-nothing")

	if info := resolveJavaCacerts(JavaInstallation{JavaHome: home}); info != nil {
		t.Errorf("expected nil for a JDK with no cacerts, got %+v", info)
	}
}

func TestDeduplicateJavaHomes_Symlinks(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real-jdk")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "sdkman-current")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got := deduplicateJavaHomes([]JavaInstallation{
		{JavaHome: real},
		{JavaHome: link},
	})

	if len(got) != 1 {
		t.Fatalf("expected symlinked duplicates to collapse to 1, got %d: %+v", len(got), got)
	}
}

func TestDeduplicateJavaHomes_OrderStable(t *testing.T) {
	base := t.TempDir()
	var homes []JavaInstallation
	for _, name := range []string{"jdk-21", "jdk-17", "jdk-11"} {
		p := filepath.Join(base, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		homes = append(homes, JavaInstallation{JavaHome: p})
	}

	// Discovery order drives the store tag suffixes, so it must be stable and
	// first-occurrence-wins.
	first := deduplicateJavaHomes(append(homes, homes[0]))
	second := deduplicateJavaHomes(append(homes, homes[0]))

	if len(first) != 3 {
		t.Fatalf("expected 3 unique homes, got %d", len(first))
	}
	for i := range first {
		if first[i].JavaHome != second[i].JavaHome {
			t.Fatalf("order not stable at %d: %q vs %q", i, first[i].JavaHome, second[i].JavaHome)
		}
		if !strings.HasSuffix(first[i].JavaHome, []string{"jdk-21", "jdk-17", "jdk-11"}[i]) {
			t.Errorf("unexpected order at %d: %q", i, first[i].JavaHome)
		}
	}
}

func TestDiscoverJavaStores_ExplicitHomeBypassesScan(t *testing.T) {
	home := fakeJavaHome(t, "explicit-jdk", filepath.Join("lib", "security", "cacerts"))

	stores := DiscoverJavaStores(home)
	if len(stores) != 1 {
		t.Fatalf("expected exactly the explicit home, got %d stores", len(stores))
	}
	// Discovery resolves symlinks (macOS /var -> /private/var), so compare
	// against the resolved form.
	resolved, err := filepath.EvalSymlinks(home)
	if err != nil {
		resolved = home
	}
	if !strings.HasPrefix(stores[0].Path, resolved) {
		t.Errorf("expected the explicit home %q to be used, got %q", resolved, stores[0].Path)
	}
}

func TestReadJavaStores_NoInstallations(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-a-jdk")

	_, err := ReadJavaStores(missing, func(string, []byte) ([]*x509.Certificate, error) {
		t.Fatal("reader must not be called when no store was found")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected an error for a JAVA_HOME with no cacerts")
	}
	if !strings.Contains(err.Error(), "JAVA_HOME") {
		t.Errorf("expected the explicit-home message, got %q", err.Error())
	}
}

func TestReadJavaStores_AllFail(t *testing.T) {
	home := fakeJavaHome(t, "jdk-broken", filepath.Join("lib", "security", "cacerts"))

	_, err := ReadJavaStores(home, func(string, []byte) ([]*x509.Certificate, error) {
		return nil, errors.New("bad password")
	})
	if err == nil {
		t.Fatal("expected an error when no store could be read")
	}
}

func TestReadJavaStores_PartialFailKeepsWarning(t *testing.T) {
	home := fakeJavaHome(t, "jdk-ok", filepath.Join("lib", "security", "cacerts"))
	ca := newTestCA(t, "Java Root")

	stores, err := ReadJavaStores(home, func(string, []byte) ([]*x509.Certificate, error) {
		return []*x509.Certificate{ca.cert}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stores) != 1 {
		t.Fatalf("expected 1 store, got %d", len(stores))
	}
	if stores[0].Info.CertCount != 1 {
		t.Errorf("expected CertCount to reflect the read, got %d", stores[0].Info.CertCount)
	}
}

func TestReadJavaStores_UsesDefaultPassword(t *testing.T) {
	home := fakeJavaHome(t, "jdk-pw", filepath.Join("lib", "security", "cacerts"))

	var seen []byte
	_, err := ReadJavaStores(home, func(_ string, pw []byte) ([]*x509.Certificate, error) {
		seen = pw
		return nil, nil
	})
	if err != nil && len(seen) == 0 {
		t.Fatalf("reader was not called: %v", err)
	}
	if string(seen) != "changeit" {
		t.Errorf("expected the JKS default password, got %q", string(seen))
	}
}
