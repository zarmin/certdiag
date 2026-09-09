package certops

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// stubReaders returns readers that never touch the real machine.
//
// Pair every use with hermeticOpts: an unset reader falls back to the real
// implementation, so a store type added later would silently start reading the
// user's keychain or browser profiles from inside the test suite.
func stubReaders(osStores []truststore.StoreContents, javaStores []truststore.StoreContents, ossl *truststore.StoreContents) StoreReaders {
	return StoreReaders{
		OS: func() ([]truststore.StoreContents, error) { return osStores, nil },
		Java: func(string, truststore.CacertsReader) ([]truststore.StoreContents, error) {
			return javaStores, nil
		},
		OpenSSL: func() (*truststore.StoreContents, error) { return ossl, nil },
	}
}

// hermeticOpts is the base options every store-load test must build on.
func hermeticOpts(readers StoreReaders) StoreLoadAllOptions {
	return StoreLoadAllOptions{Readers: readers, NoRealReads: true}
}

func withPasswords(opts StoreLoadAllOptions, pw []certlib.TaggedPassword) StoreLoadAllOptions {
	opts.Passwords = pw
	return opts
}

func TestStoreLoadAll_AllSucceed(t *testing.T) {
	a := storeTestCert(t, "OS Root")
	b := storeTestCert(t, "Java Root")
	c := storeTestCert(t, "SSL Root")

	ossl := storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", c)
	result, err := StoreLoadAll(hermeticOpts(stubReaders(
		[]truststore.StoreContents{storeFixture("OS", truststore.StoreTypeOS, "/kc", a)},
		[]truststore.StoreContents{storeFixture("Java 21", truststore.StoreTypeJava, "/jdk", b)},
		&ossl,
	)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stores) != 3 {
		t.Fatalf("expected 3 stores, got %d", len(result.Stores))
	}
}

func TestStoreLoadAll_PartialFailureIsNotFatal(t *testing.T) {
	a := storeTestCert(t, "OS Root")

	readers := StoreReaders{
		OS: func() ([]truststore.StoreContents, error) {
			return []truststore.StoreContents{storeFixture("OS", truststore.StoreTypeOS, "/kc", a)}, nil
		},
		Java: func(string, truststore.CacertsReader) ([]truststore.StoreContents, error) {
			return nil, errors.New("no Java installations found")
		},
		OpenSSL: func() (*truststore.StoreContents, error) {
			return nil, errors.New("openssl not found in PATH")
		},
	}

	result, err := StoreLoadAll(hermeticOpts(readers))
	if err != nil {
		t.Fatalf("one working store must be enough: %v", err)
	}
	if len(result.Stores) != 1 {
		t.Fatalf("expected the OS store, got %d", len(result.Stores))
	}
	if len(result.Warnings) < 2 {
		t.Errorf("expected both failures as warnings, got %v", result.Warnings)
	}
}

func TestStoreLoadAll_LockedStoreIsKept(t *testing.T) {
	// A store that read with an error is surfaced as an empty store carrying
	// the failure, so the TUI can render it as a locked group.
	locked := truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:     truststore.StoreTypeJava,
			Name:     "Java 21 (locked)",
			Path:     "/jdk/cacerts",
			Warnings: []string{"read error: bad password"},
		},
	}
	good := storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "OS Root"))

	result, err := StoreLoadAll(hermeticOpts(stubReaders(
		[]truststore.StoreContents{good},
		[]truststore.StoreContents{locked},
		nil,
	)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stores) != 2 {
		t.Fatalf("the locked store must still be returned, got %d", len(result.Stores))
	}
	joined := strings.Join(result.Warnings, " ")
	if !strings.Contains(joined, "bad password") {
		t.Errorf("expected the read error in warnings, got %v", result.Warnings)
	}
}

func TestStoreLoadAll_TotalFailure(t *testing.T) {
	readers := StoreReaders{
		OS: func() ([]truststore.StoreContents, error) {
			return nil, errors.New("keychain unreadable")
		},
		Java: func(string, truststore.CacertsReader) ([]truststore.StoreContents, error) {
			return nil, errors.New("no Java installations found")
		},
		OpenSSL: func() (*truststore.StoreContents, error) {
			return nil, errors.New("openssl not found")
		},
	}

	_, err := StoreLoadAll(hermeticOpts(readers))
	if err == nil {
		t.Fatal("expected an error when nothing could be read")
	}
	if !strings.Contains(err.Error(), "no trust store could be read") {
		t.Errorf("expected a clear message, got %q", err.Error())
	}
}

func TestStoreLoadAll_EmptyStoresOnlyIsFailure(t *testing.T) {
	// Readers that succeed but return no certificates at all mean the machine
	// has no usable trust configuration.
	readers := stubReaders(nil, nil, nil)

	if _, err := StoreLoadAll(hermeticOpts(readers)); err == nil {
		t.Fatal("expected an error when no certificates were read at all")
	}
}

func TestStoreLoadAll_ProgressCallbackOrder(t *testing.T) {
	var seen []string
	ossl := storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", storeTestCert(t, "R"))

	_, err := StoreLoadAll(StoreLoadAllOptions{
		NoRealReads: true,
		Readers:     stubReaders(nil, nil, &ossl),
		Progress:    func(name string) { seen = append(seen, name) },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"OS trust store", "Java cacerts", "OpenSSL bundle", "Browser profile stores", "Root CA snapshots"}
	if len(seen) != len(want) {
		t.Fatalf("expected %d progress calls, got %v", len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("progress %d: expected %q, got %q", i, want[i], seen[i])
		}
	}
}

func TestStoreLoadAll_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ossl := storeFixture("OpenSSL", truststore.StoreTypeOpenSSL, "/ssl", storeTestCert(t, "R"))
	opts := hermeticOpts(stubReaders(
		[]truststore.StoreContents{storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "R"))},
		nil, &ossl,
	))
	opts.Ctx = ctx
	_, err := StoreLoadAll(opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestStoreLoadAll_IncludeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "extra-ca.pem")

	cert := storeTestCert(t, "Bundle Root")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := StoreLoadAll(StoreLoadAllOptions{
		NoRealReads:  true,
		Readers:      stubReaders(nil, nil, nil),
		IncludeFiles: []string{path},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stores) != 1 {
		t.Fatalf("expected the custom bundle, got %d stores", len(result.Stores))
	}
	if result.Stores[0].Info.Type != truststore.StoreTypeCustom {
		t.Errorf("expected a custom store, got %q", result.Stores[0].Info.Type)
	}
	if result.Stores[0].Info.Name != "extra-ca.pem" {
		t.Errorf("expected the file name as store name, got %q", result.Stores[0].Info.Name)
	}
	if len(result.Stores[0].Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(result.Stores[0].Certificates))
	}
}

func TestStoreLoadAll_IncludeFileMissingIsWarning(t *testing.T) {
	good := storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "OS Root"))
	missing := filepath.Join(t.TempDir(), "nope.pem")

	result, err := StoreLoadAll(StoreLoadAllOptions{
		NoRealReads:  true,
		Readers:      stubReaders([]truststore.StoreContents{good}, nil, nil),
		IncludeFiles: []string{missing},
	})
	if err != nil {
		t.Fatalf("a bad --trust-file must not abort the load: %v", err)
	}
	if len(result.Stores) != 2 {
		t.Fatalf("expected the failed bundle to appear as a locked store, got %d", len(result.Stores))
	}
	if len(result.Stores[1].Certificates) != 0 {
		t.Error("expected no certificates for the failed bundle")
	}
	if len(result.Stores[1].Info.Warnings) == 0 {
		t.Error("expected the failure recorded on the store")
	}
}

func TestStoreLoadAll_PasswordsReachJavaReader(t *testing.T) {
	readers := StoreReaders{
		OS: func() ([]truststore.StoreContents, error) {
			return []truststore.StoreContents{
				storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "R")),
			}, nil
		},
		Java: func(_ string, reader truststore.CacertsReader) ([]truststore.StoreContents, error) {
			// The reader closure is what carries the session passwords.
			if reader == nil {
				t.Error("expected a cacerts reader to be supplied")
			}
			return nil, errors.New("no Java installations found")
		},
		OpenSSL: func() (*truststore.StoreContents, error) { return nil, errors.New("none") },
	}

	pw := []certlib.TaggedPassword{{Password: []byte("session-secret"), Source: certlib.PasswordSourceInteractive}}
	if _, err := StoreLoadAll(withPasswords(hermeticOpts(readers), pw)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJavaCacertsReader_TriesDefaultPasswordFirst(t *testing.T) {
	// The reader must offer "changeit" before session passwords, otherwise a
	// wrong session password could mask a readable store.
	reader := javaCacertsReader([]certlib.TaggedPassword{
		{Password: []byte("session"), Source: certlib.PasswordSourceInteractive},
	})

	missing := filepath.Join(t.TempDir(), "cacerts")
	if _, err := reader(missing, []byte("changeit")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestStoreReaders_DefaultsAreWired(t *testing.T) {
	// Zero-value readers must resolve to something callable rather than
	// panicking on a nil call, in both modes.
	var r StoreReaders
	for _, noReal := range []bool{false, true} {
		if r.osReader(noReal) == nil || r.javaReader(noReal) == nil ||
			r.opensslReader(noReal) == nil || r.nssReader(noReal) == nil ||
			r.bundleReader(noReal) == nil {
			t.Fatalf("expected every reader to resolve (noReal=%v)", noReal)
		}
	}
}

// TestStoreLoadAll_NoRealReadsIsHermetic is the guard that made this option
// exist: adding a store type must never let an unset reader reach the real
// machine from inside the suite. With NoRealReads and no readers at all the
// load must find nothing rather than the developer's own keychain.
func TestStoreLoadAll_NoRealReadsIsHermetic(t *testing.T) {
	_, err := StoreLoadAll(StoreLoadAllOptions{NoRealReads: true})
	if err == nil {
		t.Fatal("expected an error when every reader is stubbed out")
	}
	if !strings.Contains(err.Error(), "no trust store could be read") {
		t.Errorf("expected the no-store error, got %v", err)
	}
}

// TestStoreLoadAll_OnlyStubbedStoresAppear pins the property the seven
// retrofitted tests rely on: with NoRealReads, the result contains exactly the
// stubbed stores and nothing from the host.
func TestStoreLoadAll_OnlyStubbedStoresAppear(t *testing.T) {
	os1 := storeFixture("OS", truststore.StoreTypeOS, "/kc", storeTestCert(t, "OS Root"))

	result, err := StoreLoadAll(hermeticOpts(stubReaders(
		[]truststore.StoreContents{os1}, nil, nil,
	)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Stores) != 1 {
		t.Fatalf("expected only the stubbed OS store, got %d: %+v", len(result.Stores), storeNames(result.Stores))
	}
	for _, s := range result.Stores {
		switch s.Info.Type {
		case truststore.StoreTypeNSS, truststore.StoreTypeBundle:
			t.Errorf("a real %s store leaked into a hermetic test", s.Info.Type)
		}
	}
}

func storeNames(stores []truststore.StoreContents) []string {
	out := make([]string, 0, len(stores))
	for _, s := range stores {
		out = append(out, s.Info.Name)
	}
	return out
}
