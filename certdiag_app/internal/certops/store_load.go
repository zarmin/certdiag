package certops

import (
	"context"
	"fmt"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// StoreReaders holds the store backends. Fields left nil fall back to the real
// implementations, so tests can inject stubs without touching the OS.
type StoreReaders struct {
	OS      func() ([]truststore.StoreContents, error)
	Java    func(explicitHome string, reader truststore.CacertsReader) ([]truststore.StoreContents, error)
	OpenSSL func() (*truststore.StoreContents, error)
	NSS     func() ([]truststore.StoreContents, error)
	Bundles func(dir string) ([]truststore.StoreContents, error)
}

// An unset reader falls back to the real machine. That is right in production
// and dangerous in a test: adding a new store type silently makes every test
// that stubbed only the old ones start reading the user's real keychain or
// browser profile. noReal makes an unset reader return nothing instead, so a
// test opts out of the whole class of accident once rather than per store.
func (r StoreReaders) osReader(noReal bool) func() ([]truststore.StoreContents, error) {
	if r.OS != nil {
		return r.OS
	}
	if noReal {
		return func() ([]truststore.StoreContents, error) { return nil, nil }
	}
	return truststore.ReadOSStore
}

func (r StoreReaders) javaReader(noReal bool) func(string, truststore.CacertsReader) ([]truststore.StoreContents, error) {
	if r.Java != nil {
		return r.Java
	}
	if noReal {
		return func(string, truststore.CacertsReader) ([]truststore.StoreContents, error) { return nil, nil }
	}
	return truststore.ReadJavaStores
}

func (r StoreReaders) opensslReader(noReal bool) func() (*truststore.StoreContents, error) {
	if r.OpenSSL != nil {
		return r.OpenSSL
	}
	if noReal {
		return func() (*truststore.StoreContents, error) { return nil, nil }
	}
	return truststore.ReadOpenSSLStore
}

func (r StoreReaders) nssReader(noReal bool) func() ([]truststore.StoreContents, error) {
	if r.NSS != nil {
		return r.NSS
	}
	if noReal {
		return func() ([]truststore.StoreContents, error) { return nil, nil }
	}
	return truststore.ReadNSSStores
}

func (r StoreReaders) bundleReader(noReal bool) func(string) ([]truststore.StoreContents, error) {
	if r.Bundles != nil {
		return r.Bundles
	}
	if noReal {
		return func(string) ([]truststore.StoreContents, error) { return nil, nil }
	}
	return readBundleStores
}

// readBundleStores loads the shipped root snapshots, preferring any refreshed
// copy the user installed with `certdiag store update`.
func readBundleStores(dir string) ([]truststore.StoreContents, error) {
	bundles, err := truststore.LoadBundles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]truststore.StoreContents, 0, len(bundles))
	for i := range bundles {
		out = append(out, bundles[i].StoreContents())
	}
	return out, nil
}

type StoreLoadAllOptions struct {
	Passwords    []certlib.TaggedPassword
	IncludeFiles []string
	JavaHome     string
	BundleDir    string
	SkipNSS      bool
	SkipBundles  bool
	// NoRealReads stops any unset reader from falling back to the real
	// machine. Tests set it; production never does.
	NoRealReads bool
	Readers     StoreReaders
	Progress    func(name string)
	Ctx         context.Context
}

type StoreLoadAllResult struct {
	Stores   []truststore.StoreContents
	Warnings []string
}

// StoreLoadAll reads every trust store on the machine. A store that cannot be
// read is kept as an empty StoreContents carrying the failure in Info.Warnings,
// so the caller can render it as a locked group. An error is only returned when
// nothing at all could be read.
func StoreLoadAll(opts StoreLoadAllOptions) (*StoreLoadAllResult, error) {
	ctx := opts.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	var stores []truststore.StoreContents
	var warnings []string
	readOK := false

	progress := func(name string) {
		if opts.Progress != nil {
			opts.Progress(name)
		}
	}

	cancelled := func() bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}

	progress("OS trust store")
	osStores, err := opts.Readers.osReader(opts.NoRealReads)()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("OS trust store: %v", err))
	} else {
		for _, s := range osStores {
			if len(s.Certificates) > 0 {
				readOK = true
			}
			stores = append(stores, s)
		}
	}

	if cancelled() {
		return nil, context.Canceled
	}

	progress("Java cacerts")
	javaStores, err := opts.Readers.javaReader(opts.NoRealReads)(opts.JavaHome, javaCacertsReader(opts.Passwords))
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Java: %v", err))
	} else {
		for _, s := range javaStores {
			if len(s.Certificates) > 0 {
				readOK = true
			}
			stores = append(stores, s)
		}
	}

	if cancelled() {
		return nil, context.Canceled
	}

	progress("OpenSSL bundle")
	ossl, err := opts.Readers.opensslReader(opts.NoRealReads)()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("OpenSSL: %v", err))
	} else if ossl != nil {
		if len(ossl.Certificates) > 0 {
			readOK = true
		}
		stores = append(stores, *ossl)
	}

	if !opts.SkipNSS {
		progress("Browser profile stores")
		nssStores, err := opts.Readers.nssReader(opts.NoRealReads)()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("NSS: %v", err))
		} else {
			for _, s := range nssStores {
				if len(s.Certificates) > 0 {
					readOK = true
				}
				stores = append(stores, s)
			}
		}
	}

	if cancelled() {
		return nil, context.Canceled
	}

	if !opts.SkipBundles {
		progress("Root CA snapshots")
		bundleStores, err := opts.Readers.bundleReader(opts.NoRealReads)(opts.BundleDir)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("bundles: %v", err))
		} else {
			for _, s := range bundleStores {
				if len(s.Certificates) > 0 {
					readOK = true
				}
				stores = append(stores, s)
			}
		}
	}

	if cancelled() {
		return nil, context.Canceled
	}

	for _, path := range opts.IncludeFiles {
		if cancelled() {
			return nil, context.Canceled
		}
		progress(path)
		sc, err := readCustomStore(path, opts.Passwords)
		if err != nil {
			stores = append(stores, truststore.StoreContents{
				Info: truststore.StoreInfo{
					Type:     truststore.StoreTypeCustom,
					Name:     customStoreName(path),
					Path:     path,
					Warnings: []string{fmt.Sprintf("read error: %v", err)},
				},
			})
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		sc.Info.Name = customStoreName(path)
		readOK = true
		stores = append(stores, *sc)
	}

	// A store that read successfully but holds nothing is indistinguishable
	// from a failed read unless it is called out. Surface it so the TUI can
	// show the group as notable rather than silently empty.
	for i := range stores {
		if len(stores[i].Certificates) == 0 && len(stores[i].Info.Warnings) == 0 {
			stores[i].Info.Warnings = append(stores[i].Info.Warnings,
				"store contains no certificates (wrong password, or genuinely empty)")
		}
	}

	for _, s := range stores {
		warnings = append(warnings, s.Info.Warnings...)
	}

	if !readOK {
		if len(warnings) > 0 {
			return nil, &OperationError{Op: "store", Message: fmt.Sprintf("no trust store could be read: %s", warnings[0])}
		}
		return nil, &OperationError{Op: "store", Message: "no trust store could be read"}
	}

	return &StoreLoadAllResult{Stores: stores, Warnings: warnings}, nil
}
