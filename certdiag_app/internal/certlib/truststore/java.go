package truststore

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CacertsReader func(path string, password []byte) ([]*x509.Certificate, error)

// DefaultKeystorePassword is the one built-in password certdiag tries on a locked
// keystore: the JDK ships cacerts with it and Tomcat and Jenkins docs use it.
// Every other guess belongs in the user's config, never here.
var DefaultKeystorePassword = []byte("changeit")

type JavaInstallation struct {
	JavaHome string
	Version  string
	Vendor   string
}

func DiscoverJavaStores(explicitHome string) []StoreInfo {
	var homes []JavaInstallation
	if explicitHome != "" {
		homes = []JavaInstallation{{JavaHome: explicitHome}}
	} else {
		homes = findJavaInstallations()
	}

	homes = deduplicateJavaHomes(homes)

	var found []javaStore
	for _, jdk := range homes {
		if jdk.Version == "" || jdk.Vendor == "" {
			v, vendor := identifyJDK(jdk.JavaHome)
			if jdk.Version == "" {
				jdk.Version = v
			}
			if jdk.Vendor == "" {
				jdk.Vendor = vendor
			}
		}
		info := resolveJavaCacerts(jdk)
		if info != nil {
			found = append(found, javaStore{jdk: jdk, info: *info})
		}
	}

	return orderJavaStores(found)
}

type javaStore struct {
	jdk  JavaInstallation
	info StoreInfo
}

// orderJavaStores lists newest first, then by path, and disambiguates two
// installs that would carry the same label by naming their homes (M31 M17,
// E21): "Java 17 (Temurin)" twice tells the user nothing.
func orderJavaStores(found []javaStore) []StoreInfo {
	sort.SliceStable(found, func(i, j int) bool {
		if c := compareJavaVersions(found[i].jdk.Version, found[j].jdk.Version); c != 0 {
			return c > 0
		}
		return found[i].jdk.JavaHome < found[j].jdk.JavaHome
	})
	names := map[string]int{}
	for _, f := range found {
		names[f.info.Name]++
	}
	stores := make([]StoreInfo, 0, len(found))
	for _, f := range found {
		if names[f.info.Name] > 1 {
			f.info.Name = fmt.Sprintf("%s [%s]", f.info.Name, f.jdk.JavaHome)
		}
		stores = append(stores, f.info)
	}
	return stores
}

// compareJavaVersions orders "17.0.9" before "11.0.2" and "1.8.0_392" as 8.
func compareJavaVersions(a, b string) int {
	pa, pb := javaVersionParts(a), javaVersionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

func javaVersionParts(v string) []int {
	if v == "" {
		return nil
	}
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' || r == '+' || r == '-' })
	var parts []int
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			break
		}
		parts = append(parts, n)
	}
	// Legacy "1.8.0" numbering: the major is the second field.
	if len(parts) > 1 && parts[0] == 1 {
		parts = parts[1:]
	}
	return parts
}

func ReadJavaStores(explicitHome string, reader CacertsReader) ([]StoreContents, error) {
	infos := DiscoverJavaStores(explicitHome)
	if len(infos) == 0 {
		if explicitHome != "" {
			return nil, fmt.Errorf("no cacerts found at JAVA_HOME %s", explicitHome)
		}
		return nil, fmt.Errorf("no Java installations found")
	}

	var stores []StoreContents
	var readOK bool
	for _, info := range infos {
		certs, err := reader(info.Path, DefaultKeystorePassword)
		if err != nil {
			info.Warnings = append(info.Warnings, fmt.Sprintf("read error: %v", err))
			stores = append(stores, StoreContents{Info: info})
			continue
		}
		readOK = true
		info.CertCount = len(certs)
		stores = append(stores, StoreContents{
			Info:         info,
			Certificates: certs,
		})
	}

	if !readOK {
		return nil, fmt.Errorf("could not read any Java cacerts files")
	}

	return stores, nil
}

func resolveJavaCacerts(jdk JavaInstallation) *StoreInfo {
	cacertsPaths := []string{
		filepath.Join(jdk.JavaHome, "lib", "security", "cacerts"),
		filepath.Join(jdk.JavaHome, "jre", "lib", "security", "cacerts"),
	}

	for _, cacertsPath := range cacertsPaths {
		if _, err := os.Stat(cacertsPath); err != nil {
			continue
		}

		if jdk.Version == "" || jdk.Vendor == "" {
			v, vendor := identifyJDK(jdk.JavaHome)
			if jdk.Version == "" {
				jdk.Version = v
			}
			if jdk.Vendor == "" {
				jdk.Vendor = vendor
			}
		}

		name := formatJavaStoreName(jdk.Version, jdk.Vendor)
		dir := filepath.Dir(cacertsPath)
		jssePath := filepath.Join(dir, "jssecacerts")
		actualPath := cacertsPath

		var warnings []string
		if _, err := os.Stat(jssePath); err == nil {
			warnings = append(warnings, fmt.Sprintf("jssecacerts detected at %s -- Java uses jssecacerts instead of cacerts when both exist", jssePath))
			actualPath = jssePath
		}

		return &StoreInfo{
			Type:     StoreTypeJava,
			Name:     name,
			Path:     actualPath,
			Warnings: warnings,
		}
	}

	return nil
}

func findJavaInstallations() []JavaInstallation {
	var homes []JavaInstallation

	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		homes = append(homes, JavaInstallation{JavaHome: jh})
	}

	homeDir, _ := os.UserHomeDir()
	homes = append(homes, globJavaHomes(javaHomeGlobs(runtime.GOOS, homeDir, ""))...)

	if runtime.GOOS == "darwin" {
		for _, h := range parseJavaHomeTool(javaHomeToolOutput()) {
			homes = append(homes, JavaInstallation{JavaHome: h})
		}
	}

	return homes
}

// javaHomeGlobs lists where JDKs are installed on each platform. prefix is
// prepended to the system-wide paths so a test can point the search at a
// temporary tree; homeDir covers the per-user managers.
func javaHomeGlobs(goos, homeDir, prefix string) []string {
	var system []string
	switch goos {
	case "darwin":
		system = []string{
			"/Library/Java/JavaVirtualMachines/*/Contents/Home",
			"/opt/homebrew/opt/temurin*/libexec/openjdk.jdk/Contents/Home",
			"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
			"/usr/local/opt/temurin*/libexec/openjdk.jdk/Contents/Home",
			"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		}
	case "linux":
		system = []string{
			"/usr/lib/jvm/*",
			"/usr/lib64/jvm/*",
			"/usr/java/*",
			"/usr/local/*jdk*",
			"/opt/*jdk*",
			"/opt/java*",
		}
	case "windows":
		system = []string{
			`C:\Program Files\Java\jdk-*`,
			`C:\Program Files\Java\jre*`,
			`C:\Program Files\Eclipse Adoptium\jdk-*`,
			`C:\Program Files\Amazon Corretto\jdk*`,
			`C:\Program Files\Zulu\zulu-*`,
			`C:\Program Files\Microsoft\jdk-*`,
			`C:\Program Files\OpenJDK\*`,
			`C:\Program Files\BellSoft\*`,
			`C:\Program Files\Semeru\*`,
			`C:\Program Files\IBM\Semeru*`,
			`C:\Program Files\RedHat\java-*`,
			`C:\Program Files\SapMachine\*`,
			`C:\Program Files\JetBrains\*\jbr`,
			`C:\Program Files (x86)\Java\*`,
		}
	}
	globs := make([]string, 0, len(system)+4)
	for _, g := range system {
		globs = append(globs, prefix+g)
	}
	if homeDir != "" {
		globs = append(globs,
			filepath.Join(homeDir, ".sdkman", "candidates", "java", "*"),
			filepath.Join(homeDir, ".asdf", "installs", "java", "*"),
			filepath.Join(homeDir, ".local", "share", "mise", "installs", "java", "*"),
		)
		if goos == "darwin" {
			globs = append(globs, filepath.Join(homeDir, "Library", "Java", "JavaVirtualMachines", "*", "Contents", "Home"))
		}
	}
	return globs
}

func globJavaHomes(globs []string) []JavaInstallation {
	var homes []JavaInstallation
	for _, pattern := range globs {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			homes = append(homes, JavaInstallation{JavaHome: m})
		}
	}
	return homes
}

// javaHomeToolOutput runs macOS's java_home lister, which knows about JDKs
// registered outside the usual directories. Tests replace it.
var javaHomeToolOutput = func() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "/usr/libexec/java_home", "-V").CombinedOutput()
	return string(out)
}

// parseJavaHomeTool extracts the home paths from "java_home -V" output, whose
// lines end with the path after the version, architecture and vendor.
func parseJavaHomeTool(out string) []string {
	var homes []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		last := fields[len(fields)-1]
		if strings.HasPrefix(last, "/") && strings.HasSuffix(last, "/Contents/Home") {
			homes = append(homes, last)
		}
	}
	return homes
}

func deduplicateJavaHomes(homes []JavaInstallation) []JavaInstallation {
	seen := make(map[string]bool)
	var unique []JavaInstallation
	for _, jdk := range homes {
		resolved, err := filepath.EvalSymlinks(jdk.JavaHome)
		if err != nil {
			resolved = jdk.JavaHome
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		jdk.JavaHome = resolved
		unique = append(unique, jdk)
	}
	return unique
}

func identifyJDK(javaHome string) (version, vendor string) {
	releasePath := filepath.Join(javaHome, "release")
	f, err := os.Open(releasePath)
	if err != nil {
		return parseVersionFromDirName(javaHome), ""
	}
	defer f.Close()

	var runtimeVersion string
	var implementorVersion string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JAVA_VERSION=") {
			version = strings.Trim(strings.TrimPrefix(line, "JAVA_VERSION="), "\"")
		}
		if strings.HasPrefix(line, "IMPLEMENTOR=") {
			vendor = strings.Trim(strings.TrimPrefix(line, "IMPLEMENTOR="), "\"")
		}
		if strings.HasPrefix(line, "JAVA_RUNTIME_VERSION=") {
			runtimeVersion = strings.Trim(strings.TrimPrefix(line, "JAVA_RUNTIME_VERSION="), "\"")
		}
		if strings.HasPrefix(line, "IMPLEMENTOR_VERSION=") {
			implementorVersion = strings.Trim(strings.TrimPrefix(line, "IMPLEMENTOR_VERSION="), "\"")
		}
	}

	if version == "" {
		version = parseVersionFromDirName(javaHome)
	}
	if vendor != "" {
		vendor = simplifyVendor(vendor)
	}

	if vendor == "Oracle" && isGraalVM(javaHome, runtimeVersion, implementorVersion) {
		vendor = "GraalVM"
	}

	return version, vendor
}

func isGraalVM(javaHome, runtimeVersion, implementorVersion string) bool {
	if strings.Contains(strings.ToLower(javaHome), "graalvm") {
		return true
	}
	for _, v := range []string{runtimeVersion, implementorVersion} {
		lower := strings.ToLower(v)
		if strings.Contains(lower, "graalvm") || strings.Contains(lower, "jvmci") {
			return true
		}
	}
	return false
}

var versionRe = regexp.MustCompile(`(?:jdk-?|java-?|temurin-?|corretto-?|zulu-?|graalvm.*?-|sapmachine-?|liberica-?|openjdk-?)(\d+(?:\.\d+)*)`)
var sdkmanVersionRe = regexp.MustCompile(`^(\d+(?:\.\d+)*)`)

func parseVersionFromDirName(javaHome string) string {
	base := filepath.Base(javaHome)
	m := versionRe.FindStringSubmatch(base)
	if len(m) > 1 {
		return m[1]
	}
	m = sdkmanVersionRe.FindStringSubmatch(base)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func simplifyVendor(vendor string) string {
	lower := strings.ToLower(vendor)
	switch {
	case strings.Contains(lower, "graalvm"):
		return "GraalVM"
	case strings.Contains(lower, "eclipse") || strings.Contains(lower, "adoptium") || strings.Contains(lower, "temurin"):
		return "Temurin"
	case strings.Contains(lower, "amazon") || strings.Contains(lower, "corretto"):
		return "Corretto"
	case strings.Contains(lower, "azul") || strings.Contains(lower, "zulu"):
		return "Zulu"
	case strings.Contains(lower, "oracle"):
		return "Oracle"
	case strings.Contains(lower, "microsoft"):
		return "Microsoft"
	case strings.Contains(lower, "ibm") || strings.Contains(lower, "semeru"):
		return "Semeru"
	case strings.Contains(lower, "sap"):
		return "SapMachine"
	default:
		return vendor
	}
}

func formatJavaStoreName(version, vendor string) string {
	if version == "" && vendor == "" {
		return "Java cacerts"
	}
	parts := []string{"Java"}
	if version != "" {
		major := javaMajorVersion(version)
		parts = append(parts, major)
	}
	if vendor != "" {
		parts[len(parts)-1] += " (" + vendor + ")"
	}
	return strings.Join(parts, " ")
}

func javaMajorVersion(version string) string {
	v := strings.SplitN(version, ".", 3)
	if v[0] == "1" && len(v) > 1 {
		return v[1]
	}
	return v[0]
}
