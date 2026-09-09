package truststore

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVersionFromDirName(t *testing.T) {
	tests := []struct {
		name    string
		dirName string
		want    string
	}{
		{"Oracle JDK 17", "jdk-17.0.1.jdk", "17.0.1"},
		{"Oracle JDK 8 old style", "jdk1.8.0_301.jdk", "1.8.0"},
		{"Oracle JDK 7 old style", "jdk1.7.0_80.jdk", "1.7.0"},
		{"Temurin", "temurin-21.jdk", "21"},
		{"Corretto", "amazon-corretto-17.jdk", "17"},
		{"Corretto short", "corretto-17", "17"},
		{"Zulu", "zulu-21.0.1", "21.0.1"},
		{"GraalVM CE", "graalvm-ce-java17-22.3.0", "22.3.0"},
		{"GraalVM simple", "graalvm-25.jdk", "25"},
		{"GraalVM JDK style", "graalvm-jdk-21.0.1", "21.0.1"},
		{"OpenJDK", "openjdk-17.0.1", "17.0.1"},
		{"SapMachine", "sapmachine-17", "17"},
		{"Liberica", "liberica-21.jdk", "21"},
		{"SDKMAN bare version", "17.0.11-tem", "17.0.11"},
		{"SDKMAN version only", "21.0.1-amzn", "21.0.1"},
		{"SDKMAN Java 8", "8.0.412-tem", "8.0.412"},
		{"JDK no dash", "jdk17.0.1", "17.0.1"},
		{"Java prefix", "java-11", "11"},
		{"No version", "randomdir", ""},
		{"Empty-ish name", "lib", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionFromDirName("/fake/path/" + tt.dirName)
			if got != tt.want {
				t.Errorf("parseVersionFromDirName(%q) = %q, want %q", tt.dirName, got, tt.want)
			}
		})
	}
}

func TestSimplifyVendor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Oracle Corporation", "Oracle"},
		{"Eclipse Adoptium", "Temurin"},
		{"Eclipse Foundation", "Temurin"},
		{"Temurin", "Temurin"},
		{"Amazon", "Corretto"},
		{"Amazon.com Inc.", "Corretto"},
		{"Azul Systems, Inc.", "Zulu"},
		{"GraalVM", "GraalVM"},
		{"GraalVM Community", "GraalVM"},
		{"Microsoft", "Microsoft"},
		{"IBM", "Semeru"},
		{"IBM Semeru", "Semeru"},
		{"SAP", "SapMachine"},
		{"SAP SE", "SapMachine"},
		{"BellSoft", "BellSoft"},
		{"Alibaba", "Alibaba"},
		{"N/A", "N/A"},
		{"Unknown Vendor Corp", "Unknown Vendor Corp"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := simplifyVendor(tt.input)
			if got != tt.want {
				t.Errorf("simplifyVendor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatJavaStoreName(t *testing.T) {
	tests := []struct {
		name    string
		version string
		vendor  string
		want    string
	}{
		{"modern with vendor", "17.0.1", "Oracle", "Java 17 (Oracle)"},
		{"Java 8 old scheme no vendor", "1.8.0_301", "", "Java 8"},
		{"Java 7 old scheme no vendor", "1.7.0_80", "", "Java 7"},
		{"Java 6 old scheme", "1.6.0_45", "", "Java 6"},
		{"modern with Temurin", "21.0.3", "Temurin", "Java 21 (Temurin)"},
		{"GraalVM", "25.0.2", "GraalVM", "Java 25 (GraalVM)"},
		{"version only no vendor", "11.0.20", "", "Java 11"},
		{"no version no vendor", "", "", "Java cacerts"},
		{"no version with vendor", "", "Corretto", "Java (Corretto)"},
		{"single digit version", "9.0.4", "Zulu", "Java 9 (Zulu)"},
		{"EA version", "18-ea", "Oracle", "Java 18-ea (Oracle)"},
		{"Java 1 edge case (1.5)", "1.5.0", "", "Java 5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatJavaStoreName(tt.version, tt.vendor)
			if got != tt.want {
				t.Errorf("formatJavaStoreName(%q, %q) = %q, want %q",
					tt.version, tt.vendor, got, tt.want)
			}
		})
	}
}

func TestJavaMajorVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"17.0.1", "17"},
		{"1.8.0_301", "8"},
		{"1.7.0_80", "7"},
		{"1.6.0_45", "6"},
		{"1.5.0", "5"},
		{"21.0.3", "21"},
		{"9.0.4", "9"},
		{"11", "11"},
		{"1", "1"},
		{"18-ea", "18-ea"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := javaMajorVersion(tt.version)
			if got != tt.want {
				t.Errorf("javaMajorVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestIdentifyJDK(t *testing.T) {
	tests := []struct {
		name           string
		dirName        string
		releaseContent string
		wantVersion    string
		wantVendor     string
	}{
		{
			name:           "Oracle JDK 17",
			dirName:        "jdk-17.0.1",
			releaseContent: "JAVA_VERSION=\"17.0.1\"\nIMPLEMENTOR=\"Oracle Corporation\"\n",
			wantVersion:    "17.0.1",
			wantVendor:     "Oracle",
		},
		{
			name:           "GraalVM detected from dir name",
			dirName:        "graalvm-25.jdk",
			releaseContent: "JAVA_VERSION=\"25.0.2\"\nIMPLEMENTOR=\"Oracle Corporation\"\n",
			wantVersion:    "25.0.2",
			wantVendor:     "GraalVM",
		},
		{
			name:    "GraalVM detected from jvmci runtime version",
			dirName: "jdk-25",
			releaseContent: "JAVA_VERSION=\"25.0.2\"\n" +
				"IMPLEMENTOR=\"Oracle Corporation\"\n" +
				"JAVA_RUNTIME_VERSION=\"25.0.2+10-LTS-jvmci-b01\"\n",
			wantVersion: "25.0.2",
			wantVendor:  "GraalVM",
		},
		{
			name:    "GraalVM detected from implementor version",
			dirName: "jdk-21",
			releaseContent: "JAVA_VERSION=\"21.0.1\"\n" +
				"IMPLEMENTOR=\"Oracle Corporation\"\n" +
				"IMPLEMENTOR_VERSION=\"GraalVM CE 21.0.1+12.1\"\n",
			wantVersion: "21.0.1",
			wantVendor:  "GraalVM",
		},
		{
			name:           "Temurin",
			dirName:        "temurin-21",
			releaseContent: "JAVA_VERSION=\"21.0.1\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n",
			wantVersion:    "21.0.1",
			wantVendor:     "Temurin",
		},
		{
			name:           "Corretto",
			dirName:        "corretto-17",
			releaseContent: "JAVA_VERSION=\"17.0.5\"\nIMPLEMENTOR=\"Amazon\"\n",
			wantVersion:    "17.0.5",
			wantVendor:     "Corretto",
		},
		{
			name:           "Java 8 no IMPLEMENTOR",
			dirName:        "jdk1.8.0_301",
			releaseContent: "JAVA_VERSION=\"1.8.0_301\"\nOS_NAME=\"Darwin\"\n",
			wantVersion:    "1.8.0_301",
			wantVendor:     "",
		},
		{
			name:        "no release file fallback to dir name",
			dirName:     "jdk-17.0.1",
			wantVersion: "17.0.1",
			wantVendor:  "",
		},
		{
			name:           "BellSoft unknown vendor passthrough",
			dirName:        "liberica-21",
			releaseContent: "JAVA_VERSION=\"21.0.1\"\nIMPLEMENTOR=\"BellSoft\"\n",
			wantVersion:    "21.0.1",
			wantVendor:     "BellSoft",
		},
		{
			name:           "Zulu",
			dirName:        "zulu-17",
			releaseContent: "JAVA_VERSION=\"17.0.8\"\nIMPLEMENTOR=\"Azul Systems, Inc.\"\n",
			wantVersion:    "17.0.8",
			wantVendor:     "Zulu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			javaHome := filepath.Join(tmpDir, tt.dirName)
			if err := os.MkdirAll(javaHome, 0755); err != nil {
				t.Fatal(err)
			}

			if tt.releaseContent != "" {
				if err := os.WriteFile(filepath.Join(javaHome, "release"), []byte(tt.releaseContent), 0644); err != nil {
					t.Fatal(err)
				}
			}

			gotVersion, gotVendor := identifyJDK(javaHome)
			if gotVersion != tt.wantVersion {
				t.Errorf("identifyJDK() version = %q, want %q", gotVersion, tt.wantVersion)
			}
			if gotVendor != tt.wantVendor {
				t.Errorf("identifyJDK() vendor = %q, want %q", gotVendor, tt.wantVendor)
			}
		})
	}
}

func TestReadJavaStoresPreservesReadErrors(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome) // os.UserHomeDir() reads USERPROFILE on Windows
	t.Setenv("JAVA_HOME", "")

	makeStore := func(name string) {
		dir := filepath.Join(tmpHome, ".sdkman", "candidates", "java", name, "lib", "security")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cacerts"), []byte("dummy"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	makeStore("21.0.1-ok")
	makeStore("17.0.1-fail")

	reader := func(path string, password []byte) ([]*x509.Certificate, error) {
		if strings.Contains(path, "17.0.1-fail") {
			return nil, fmt.Errorf("boom")
		}
		return []*x509.Certificate{}, nil
	}

	stores, err := ReadJavaStores("", reader)
	if err != nil {
		t.Fatalf("ReadJavaStores returned error: %v", err)
	}

	var failStore, okStore *StoreContents
	for i := range stores {
		switch {
		case strings.Contains(stores[i].Info.Path, "17.0.1-fail"):
			failStore = &stores[i]
		case strings.Contains(stores[i].Info.Path, "21.0.1-ok"):
			okStore = &stores[i]
		}
	}

	if failStore == nil {
		t.Fatal("failed store missing from returned results, read error was lost")
	}
	if okStore == nil {
		t.Fatal("successful store missing from returned results")
	}

	if !hasReadErrorWarning(failStore.Info.Warnings) {
		t.Errorf("failed store warnings = %v, want a read error warning", failStore.Info.Warnings)
	}
	if hasReadErrorWarning(okStore.Info.Warnings) {
		t.Errorf("successful store unexpectedly carries read error warning: %v", okStore.Info.Warnings)
	}
}

func hasReadErrorWarning(warnings []string) bool {
	for _, w := range warnings {
		if strings.Contains(w, "read error") {
			return true
		}
	}
	return false
}

func TestIsGraalVM(t *testing.T) {
	tests := []struct {
		name               string
		javaHome           string
		runtimeVersion     string
		implementorVersion string
		want               bool
	}{
		{"graalvm in path", "/Library/Java/graalvm-25.jdk/Contents/Home", "", "", true},
		{"jvmci in runtime version", "/opt/jdk-25", "25.0.2+10-LTS-jvmci-b01", "", true},
		{"graalvm in implementor version", "/opt/jdk-21", "", "GraalVM CE 21.0.1+12.1", true},
		{"plain Oracle JDK", "/Library/Java/jdk-17.0.1.jdk/Contents/Home", "", "", false},
		{"Oracle with build info", "/opt/jdk-25", "25.0.2+10-LTS", "Oracle JDK", false},
		{"empty everything", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGraalVM(tt.javaHome, tt.runtimeVersion, tt.implementorVersion)
			if got != tt.want {
				t.Errorf("isGraalVM(%q, %q, %q) = %v, want %v",
					tt.javaHome, tt.runtimeVersion, tt.implementorVersion, got, tt.want)
			}
		})
	}
}
