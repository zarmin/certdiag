package certops

import (
	"crypto/x509"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

// Answering "would this endpoint work elsewhere" - in Java, in a browser, on a
// server with only the OpenSSL bundle - by verifying the served chain against
// each store separately. One verdict per store beats one verdict overall,
// because the interesting case is precisely when they disagree.

// RemoteTrustSelection names the stores the verdict table should cover. The OS
// store is the default; the rest are opt-in, so nothing loads unless asked.
type RemoteTrustSelection struct {
	OS       bool
	Java     bool
	JavaHome string
	OpenSSL  bool
	Mozilla  bool
	Chrome   bool
	File     string
}

// Any reports whether any store beyond the default was asked for.
func (s RemoteTrustSelection) Any() bool {
	return s.OS || s.Java || s.OpenSSL || s.Mozilla || s.Chrome || s.File != "" || s.JavaHome != ""
}

// RemoteStoreVerdict is one row of the table.
type RemoteStoreVerdict struct {
	Store    string   `json:"store" yaml:"store"`
	Trusted  bool     `json:"trusted" yaml:"trusted"`
	Anchor   string   `json:"anchor,omitempty" yaml:"anchor,omitempty"`
	Reason   string   `json:"reason,omitempty" yaml:"reason,omitempty"`
	Warnings []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// LoadStoresForSelection reads the stores a selection needs, once per
// invocation. Callers keep the result and verify every target against it.
func LoadStoresForSelection(sel RemoteTrustSelection, loadOpts StoreLoadAllOptions) (*StoreLoadAllResult, error) {
	loadOpts.JavaHome = sel.JavaHome
	loadOpts.SkipNSS = true
	loadOpts.SkipBundles = !sel.Mozilla && !sel.Chrome
	if sel.File != "" {
		loadOpts.IncludeFiles = append(loadOpts.IncludeFiles, sel.File)
	}
	return StoreLoadAll(loadOpts)
}

// VerifyRemoteAgainstStores verifies one served chain against each selected
// store among the already-loaded ones. The hostname is checked too: a chain
// that is valid for a different name is not a pass, and reporting it as one
// would be worse than useless.
func VerifyRemoteAgainstStores(certs []*x509.Certificate, hostname string, sel RemoteTrustSelection, stores []truststore.StoreContents) ([]RemoteStoreVerdict, []string) {
	if len(certs) == 0 {
		return nil, nil
	}

	var out []RemoteStoreVerdict
	var warnings []string
	for i := range stores {
		s := stores[i]
		if !selectionIncludes(sel, s.Info) {
			continue
		}
		result := truststore.VerifyChain(certs, s.Info, truststore.BuildCertPool(s.Certificates), hostname)

		verdict := RemoteStoreVerdict{
			Store:    s.Info.Name,
			Trusted:  result.Trusted,
			Reason:   result.Reason,
			Warnings: s.Info.Warnings,
		}
		if result.TrustAnchor != nil {
			verdict.Anchor = certlib.FormatDNName(result.TrustAnchor.Subject)
		}
		out = append(out, verdict)
		warnings = append(warnings, s.Info.Warnings...)
	}
	return out, warnings
}

// selectionIncludes decides whether a loaded store was asked for. A store type
// that was not selected is skipped rather than reported as untrusted, because
// "not asked" and "does not trust" are different answers.
func selectionIncludes(sel RemoteTrustSelection, info truststore.StoreInfo) bool {
	switch info.Type {
	case truststore.StoreTypeOS:
		return sel.OS
	case truststore.StoreTypeJava:
		return sel.Java || sel.JavaHome != ""
	case truststore.StoreTypeOpenSSL:
		return sel.OpenSSL
	case truststore.StoreTypeBundle:
		switch info.ID {
		case truststore.BundleMozilla:
			return sel.Mozilla
		case truststore.BundleChrome:
			return sel.Chrome
		}
		return false
	case truststore.StoreTypeCustom:
		return sel.File != ""
	}
	return false
}
