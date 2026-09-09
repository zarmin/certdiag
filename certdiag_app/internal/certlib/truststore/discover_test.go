package truststore

import "testing"

// stubDiscovery swaps the platform discovery backends for the duration of a
// test, so composition can be asserted on any machine.
func stubDiscovery(t *testing.T, os []StoreInfo, java []StoreInfo, ossl *StoreInfo) {
	t.Helper()

	origOS, origJava, origSSL := discoverOSStoresFn, discoverJavaStoresFn, discoverOpenSSLStoreFn
	t.Cleanup(func() {
		discoverOSStoresFn = origOS
		discoverJavaStoresFn = origJava
		discoverOpenSSLStoreFn = origSSL
	})

	discoverOSStoresFn = func() []StoreInfo { return os }
	discoverJavaStoresFn = func(string) []StoreInfo { return java }
	discoverOpenSSLStoreFn = func() *StoreInfo { return ossl }
}

func TestDiscoverAllStores_Composition(t *testing.T) {
	stubDiscovery(t,
		[]StoreInfo{{Type: StoreTypeOS, Name: "System Roots"}},
		[]StoreInfo{
			{Type: StoreTypeJava, Name: "Java 21 (Temurin)"},
			{Type: StoreTypeJava, Name: "Java 17 (Corretto)"},
		},
		&StoreInfo{Type: StoreTypeOpenSSL, Name: "OpenSSL"},
	)

	got := DiscoverAllStores()
	if len(got) != 4 {
		t.Fatalf("expected 4 stores, got %d", len(got))
	}

	wantOrder := []StoreType{StoreTypeOS, StoreTypeJava, StoreTypeJava, StoreTypeOpenSSL}
	for i, want := range wantOrder {
		if got[i].Type != want {
			t.Errorf("position %d: expected %q, got %q", i, want, got[i].Type)
		}
	}
}

func TestDiscoverAllStores_AbsentKinds(t *testing.T) {
	stubDiscovery(t,
		[]StoreInfo{{Type: StoreTypeOS, Name: "System Roots"}},
		nil,
		nil,
	)

	got := DiscoverAllStores()
	if len(got) != 1 {
		t.Fatalf("expected only the OS store, got %d: %+v", len(got), got)
	}
	if got[0].Type != StoreTypeOS {
		t.Errorf("expected the OS store, got %q", got[0].Type)
	}
}

func TestDiscoverAllStores_NoneFound(t *testing.T) {
	stubDiscovery(t, nil, nil, nil)

	got := DiscoverAllStores()
	if len(got) != 0 {
		t.Errorf("expected no stores, got %d", len(got))
	}
}
