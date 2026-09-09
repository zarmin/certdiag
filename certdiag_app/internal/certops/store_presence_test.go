package certops

import (
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

func TestPresenceMap_SingleStore(t *testing.T) {
	a := storeTestCert(t, "Root A")
	b := storeTestCert(t, "Root B")

	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc", a),
		storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", b),
	}
	p := ComputeStorePresence(stores)

	if got := p.TagsFor(a); len(got) != 1 || got[0] != "OS" {
		t.Errorf("expected [OS] for root A, got %v", got)
	}
	if got := p.TagsFor(b); len(got) != 1 || got[0] != "SSL" {
		t.Errorf("expected [SSL] for root B, got %v", got)
	}
}

func TestPresenceMap_AllStores(t *testing.T) {
	shared := storeTestCert(t, "Shared Root")

	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", shared),
		storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", shared),
	}
	p := ComputeStorePresence(stores)

	if got := p.TagsFor(shared); len(got) != 3 {
		t.Errorf("expected all 3 stores, got %v", got)
	}
	if !p.InAllStores(shared) {
		t.Error("expected InAllStores to be true")
	}
}

func TestPresenceMap_SubsetIsNotInAll(t *testing.T) {
	shared := storeTestCert(t, "Shared Root")
	javaOnly := storeTestCert(t, "Corporate Root")

	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc", shared),
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", shared, javaOnly),
	}
	p := ComputeStorePresence(stores)

	if p.InAllStores(javaOnly) {
		t.Error("a Java-only root must not count as present in all stores")
	}
	if got := p.TagsFor(javaOnly); len(got) != 1 || got[0] != "J21" {
		t.Errorf("expected [J21], got %v", got)
	}
}

func TestPresenceMap_UnknownCert(t *testing.T) {
	known := storeTestCert(t, "Known")
	unknown := storeTestCert(t, "Unknown")

	p := ComputeStorePresence([]truststore.StoreContents{
		storeFixture("OS", truststore.StoreTypeOS, "/kc", known),
	})

	if got := p.TagsFor(unknown); got != nil {
		t.Errorf("expected no tags for an unknown cert, got %v", got)
	}
	if p.InAllStores(unknown) {
		t.Error("an unknown cert is not in all stores")
	}
}

func TestPresenceMap_NilCert(t *testing.T) {
	p := ComputeStorePresence([]truststore.StoreContents{
		storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "R")),
	})
	if got := p.TagsFor(nil); got != nil {
		t.Errorf("expected nil for a nil cert, got %v", got)
	}
}

func TestPresenceMap_FingerprintNotSubject(t *testing.T) {
	// Same CN, different keys: these must never be conflated.
	a := storeTestCert(t, "GlobalSign Root CA")
	b := storeTestCert(t, "GlobalSign Root CA")

	stores := []truststore.StoreContents{
		storeFixture("OS", truststore.StoreTypeOS, "/kc", a),
		storeFixture("Java 21", truststore.StoreTypeJava, "/jdk21", b),
	}
	p := ComputeStorePresence(stores)

	if got := p.TagsFor(a); len(got) != 1 || got[0] != "OS" {
		t.Errorf("expected only [OS] for cert A, got %v", got)
	}
	if got := p.TagsFor(b); len(got) != 1 || got[0] != "J21" {
		t.Errorf("expected only [J21] for cert B, got %v", got)
	}
}

func TestPresenceMap_DuplicateWithinOneStoreCountsOnce(t *testing.T) {
	shared := storeTestCert(t, "Dup Root")

	p := ComputeStorePresence([]truststore.StoreContents{
		storeFixture("OS", truststore.StoreTypeOS, "/kc", shared, shared),
	})

	if got := p.TagsFor(shared); len(got) != 1 {
		t.Errorf("a cert listed twice in one store must yield one tag, got %v", got)
	}
}

func TestPresenceMap_KindModeStillNamesInstances(t *testing.T) {
	// The presence map is built from the raw stores, so it names instances
	// (J21a/J21b) even when the tree is grouped by kind. That is what makes
	// the STORES column useful in kind mode.
	shared := storeTestCert(t, "Shared Root")

	stores := []truststore.StoreContents{
		storeFixture("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21a", shared),
		storeFixture("Java 21 (Zulu)", truststore.StoreTypeJava, "/jdk21b", shared),
	}
	p := ComputeStorePresence(stores)

	got := p.TagsFor(shared)
	if len(got) != 2 {
		t.Fatalf("expected both JDK instances, got %v", got)
	}
	if got[0] != "J21a" || got[1] != "J21b" {
		t.Errorf("expected instance-level tags, got %v", got)
	}
}

// --- tags ---

func TestStoreTags_Basic(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc"),
		storeFixture("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21"),
		storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl"),
		storeFixture("ca-bundle.pem", truststore.StoreTypeCustom, "/tmp/ca-bundle.pem"),
	}
	p := ComputeStorePresence(stores)

	want := []string{"OS", "J21", "SSL", "F:ca-bundle.pem"}
	for i, w := range want {
		if p.Tags[i] != w {
			t.Errorf("tag %d: expected %q, got %q", i, w, p.Tags[i])
		}
	}
}

func TestStoreTags_JDKMajorVersionCollision(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("Java 21 (Temurin)", truststore.StoreTypeJava, "/jdk21a"),
		storeFixture("Java 21 (Zulu)", truststore.StoreTypeJava, "/jdk21b"),
		storeFixture("Java 17 (Corretto)", truststore.StoreTypeJava, "/jdk17"),
	}
	p := ComputeStorePresence(stores)

	if p.Tags[0] != "J21a" || p.Tags[1] != "J21b" {
		t.Errorf("expected colliding tags to be suffixed, got %v", p.Tags[:2])
	}
	// A tag with no collision keeps its plain form.
	if p.Tags[2] != "J17" {
		t.Errorf("expected J17 unsuffixed, got %q", p.Tags[2])
	}
}

func TestStoreTags_MultipleOSStores(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc1"),
		storeFixture("macOS System Keychain", truststore.StoreTypeOS, "/kc2"),
		storeFixture("macOS Login Keychain", truststore.StoreTypeOS, "/kc3"),
	}
	p := ComputeStorePresence(stores)

	want := []string{"OSa", "OSb", "OSc"}
	for i, w := range want {
		if p.Tags[i] != w {
			t.Errorf("tag %d: expected %q, got %q", i, w, p.Tags[i])
		}
	}
}

func TestStoreTags_JavaWithoutVersion(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("Java", truststore.StoreTypeJava, "/jdk"),
	}
	p := ComputeStorePresence(stores)

	if p.Tags[0] != "J" {
		t.Errorf("expected a bare J tag, got %q", p.Tags[0])
	}
}

func TestStoreTags_Stable(t *testing.T) {
	stores := []truststore.StoreContents{
		storeFixture("Java 21 (Temurin)", truststore.StoreTypeJava, "/a"),
		storeFixture("Java 21 (Zulu)", truststore.StoreTypeJava, "/b"),
		storeFixture("macOS System Roots", truststore.StoreTypeOS, "/kc"),
	}

	first := ComputeStorePresence(stores).Tags
	second := ComputeStorePresence(stores).Tags

	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Errorf("tags must be stable across runs: %v vs %v", first, second)
	}
}

func TestStorePresence_StoreCount(t *testing.T) {
	p := ComputeStorePresence([]truststore.StoreContents{
		storeFixture("a", truststore.StoreTypeOS, "/a"),
		storeFixture("b", truststore.StoreTypeJava, "/b"),
	})
	if p.StoreCount() != 2 {
		t.Errorf("expected 2, got %d", p.StoreCount())
	}
}

func TestStorePresence_EmptyIsSafe(t *testing.T) {
	p := ComputeStorePresence(nil)
	cert := storeTestCert(t, "Any")

	if got := p.TagsFor(cert); got != nil {
		t.Errorf("expected nil tags, got %v", got)
	}
	if p.InAllStores(cert) {
		t.Error("no stores loaded means nothing is in all stores")
	}
}
