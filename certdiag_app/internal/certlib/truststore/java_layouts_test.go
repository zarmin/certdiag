package truststore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkJDK(t *testing.T, home, version, vendor string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, "lib", "security"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "lib", "security", "cacerts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := "JAVA_VERSION=\"" + version + "\"\nIMPLEMENTOR=\"" + vendor + "\"\n"
	if err := os.WriteFile(filepath.Join(home, "release"), []byte(rel), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestJavaHomeGlobs_NewLayouts guards M31 M17: Homebrew openjdk, the per-user
// JavaVirtualMachines directory and the Linux vendor directories are found.
func TestJavaHomeGlobs_NewLayouts(t *testing.T) {
	prefix := t.TempDir()
	home := filepath.Join(prefix, "home")
	darwin := []string{
		"opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
		"Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",
		"home/Library/Java/JavaVirtualMachines/zulu-11.jdk/Contents/Home",
	}
	linux := []string{
		"usr/lib64/jvm/java-11-openjdk",
		"usr/java/jdk-8u392",
		"opt/jdk-22",
		"usr/local/graalvm-jdk-21",
	}
	for _, p := range append(darwin, linux...) {
		mkJDK(t, filepath.Join(prefix, p), "1", "Test")
	}
	found := func(goos string) map[string]bool {
		out := map[string]bool{}
		for _, h := range globJavaHomes(javaHomeGlobs(goos, home, prefix)) {
			out[filepath.ToSlash(strings.TrimPrefix(h.JavaHome, prefix+string(filepath.Separator)))] = true
		}
		return out
	}
	got := found("darwin")
	for _, p := range darwin {
		if !got[p] {
			t.Errorf("darwin: %s not discovered (got %v)", p, got)
		}
	}
	got = found("linux")
	for _, p := range linux {
		if !got[p] {
			t.Errorf("linux: %s not discovered (got %v)", p, got)
		}
	}
}

func TestParseJavaHomeTool(t *testing.T) {
	out := "Matching Java Virtual Machines (2):\n" +
		"    21.0.2 (arm64) \"Homebrew\" - \"OpenJDK 21.0.2\" /opt/homebrew/Cellar/openjdk/21.0.2/libexec/openjdk.jdk/Contents/Home\n" +
		"    17.0.9 (arm64) \"Eclipse Adoptium\" - \"OpenJDK 17.0.9\" /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home\n" +
		"/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home\n"
	homes := parseJavaHomeTool(out)
	if len(homes) != 3 || !strings.HasPrefix(homes[0], "/opt/homebrew") {
		t.Errorf("parsed %v", homes)
	}
}

// TestOrderJavaStores sorts newest first and disambiguates equal labels.
func TestOrderJavaStores(t *testing.T) {
	found := []javaStore{
		{jdk: JavaInstallation{JavaHome: "/b/jdk-11", Version: "11.0.2"}, info: StoreInfo{Name: "Java 11 (Temurin)"}},
		{jdk: JavaInstallation{JavaHome: "/z/jdk-17", Version: "17.0.9"}, info: StoreInfo{Name: "Java 17 (Temurin)"}},
		{jdk: JavaInstallation{JavaHome: "/a/jdk-17", Version: "17.0.9"}, info: StoreInfo{Name: "Java 17 (Temurin)"}},
		{jdk: JavaInstallation{JavaHome: "/c/jdk8", Version: "1.8.0_392"}, info: StoreInfo{Name: "Java 8 (Oracle)"}},
		{jdk: JavaInstallation{JavaHome: "/d/jdk-21", Version: "21"}, info: StoreInfo{Name: "Java 21 (Zulu)"}},
	}
	stores := orderJavaStores(found)
	var names []string
	for _, s := range stores {
		names = append(names, s.Name)
	}
	want := []string{
		"Java 21 (Zulu)",
		"Java 17 (Temurin) [/a/jdk-17]",
		"Java 17 (Temurin) [/z/jdk-17]",
		"Java 11 (Temurin)",
		"Java 8 (Oracle)",
	}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Errorf("order/labels:\n got %v\nwant %v", names, want)
	}
}
