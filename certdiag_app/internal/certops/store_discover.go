package certops

import (
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/config"
)

// bundleDirOrEmpty resolves the installed-bundle directory, falling back to the
// embedded snapshots when the home directory is unavailable.
func bundleDirOrEmpty() string {
	dir, err := config.BundleDir()
	if err != nil {
		return ""
	}
	return dir
}

type StoreDiscoverResult struct {
	Stores   []truststore.StoreInfo
	Warnings []string
}

func StoreDiscover() (*StoreDiscoverResult, error) {
	stores := truststore.DiscoverAllStores()

	reader := javaCacertsReader(nil)
	for i, s := range stores {
		if s.Type == truststore.StoreTypeJava && s.CertCount == 0 {
			certs, err := reader(s.Path, truststore.DefaultKeystorePassword)
			if err == nil {
				stores[i].CertCount = len(certs)
			}
		}
	}

	stores = append(stores, truststore.DiscoverNSSStores()...)

	if bundles, err := truststore.LoadBundles(bundleDirOrEmpty()); err == nil {
		for i := range bundles {
			stores = append(stores, bundles[i].StoreContents().Info)
		}
	}

	var warnings []string
	for _, s := range stores {
		warnings = append(warnings, s.Warnings...)
	}

	return &StoreDiscoverResult{
		Stores:   stores,
		Warnings: warnings,
	}, nil
}
