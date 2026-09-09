package truststore

// Discovery backends, indirected through variables so composition can be
// tested without touching the real machine.
var (
	discoverOSStoresFn     = DiscoverOSStores
	discoverJavaStoresFn   = DiscoverJavaStores
	discoverOpenSSLStoreFn = DiscoverOpenSSLStore
)

func DiscoverAllStores() []StoreInfo {
	var stores []StoreInfo

	osStores := discoverOSStoresFn()
	stores = append(stores, osStores...)

	javaStores := discoverJavaStoresFn("")
	stores = append(stores, javaStores...)

	if ossl := discoverOpenSSLStoreFn(); ossl != nil {
		stores = append(stores, *ossl)
	}

	return stores
}
