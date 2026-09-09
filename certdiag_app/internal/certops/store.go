package certops

import (
	"crypto/x509"
	"os"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type StoreListOptions struct {
	StoreType truststore.StoreType
	JavaHome  string
	FilePath  string
	Passwords []certlib.TaggedPassword
	Query     string
	BundleID  string
	BundleDir string
}

type StoreListResult struct {
	Stores   []truststore.StoreContents
	Warnings []string
}

func StoreList(opts StoreListOptions) (*StoreListResult, error) {
	var stores []truststore.StoreContents
	var warnings []string

	switch opts.StoreType {
	case truststore.StoreTypeOS:
		s, err := truststore.ReadOSStore()
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		stores = s

	case truststore.StoreTypeJava:
		s, err := truststore.ReadJavaStores(opts.JavaHome, javaCacertsReader(opts.Passwords))
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		stores = s

	case truststore.StoreTypeOpenSSL:
		s, err := truststore.ReadOpenSSLStore()
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		stores = []truststore.StoreContents{*s}

	case truststore.StoreTypeNSS:
		s, err := truststore.ReadNSSStores()
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		if len(s) == 0 {
			return nil, &OperationError{Op: "store", Message: "no browser profile databases found"}
		}
		stores = s

	case truststore.StoreTypeBundle:
		if opts.BundleID == "" {
			bundles, err := truststore.LoadBundles(opts.BundleDir)
			if err != nil {
				return nil, &OperationError{Op: "store", Message: err.Error()}
			}
			for i := range bundles {
				stores = append(stores, bundles[i].StoreContents())
			}
			break
		}
		b, err := truststore.LoadBundle(opts.BundleID, opts.BundleDir)
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		stores = []truststore.StoreContents{b.StoreContents()}

	case truststore.StoreTypeCustom:
		if opts.FilePath == "" {
			return nil, &OperationError{Op: "store", Message: "--trust-file requires a path"}
		}
		s, err := readCustomStore(opts.FilePath, opts.Passwords)
		if err != nil {
			return nil, &OperationError{Op: "store", Message: err.Error()}
		}
		stores = []truststore.StoreContents{*s}

	default:
		return nil, &OperationError{Op: "store", Message: "unknown store type"}
	}

	if opts.Query != "" {
		for i := range stores {
			stores[i] = filterStoreContents(stores[i], opts.Query)
		}
	}

	for _, s := range stores {
		for _, w := range s.Info.Warnings {
			warnings = append(warnings, w)
		}
	}

	return &StoreListResult{Stores: stores, Warnings: warnings}, nil
}

func javaCacertsReader(passwords []certlib.TaggedPassword) truststore.CacertsReader {
	return func(path string, defaultPassword []byte) ([]*x509.Certificate, error) {
		tagged := []certlib.TaggedPassword{
			{Password: defaultPassword, Source: certlib.PasswordSourceNone},
		}
		tagged = append(tagged, passwords...)
		tagged = append(tagged, certlib.TaggedPassword{Password: []byte(""), Source: certlib.PasswordSourceNone})

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		container, err := certlib.ReadFileBySignature(path, data, tagged)
		if err != nil {
			return nil, err
		}

		var certs []*x509.Certificate
		for _, item := range container.Items {
			if item.Type == certlib.ContentCertificate && item.Certificate != nil {
				certs = append(certs, item.Certificate)
			}
		}
		return certs, nil
	}
}

func readCustomStore(path string, passwords []certlib.TaggedPassword) (*truststore.StoreContents, error) {
	tagged := append([]certlib.TaggedPassword{}, passwords...)
	tagged = append(tagged, certlib.BuiltInPasswords()...)
	tagged = append(tagged, certlib.TaggedPassword{Password: []byte(""), Source: certlib.PasswordSourceNone})

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	container, err := certlib.ReadFileBySignature(path, data, tagged)
	if err != nil {
		container, err = certlib.ReadFile(path, tagged)
		if err != nil {
			return nil, err
		}
	}

	var certs []*x509.Certificate
	for _, item := range container.Items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil {
			certs = append(certs, item.Certificate)
		}
	}

	return &truststore.StoreContents{
		Info: truststore.StoreInfo{
			Type:      truststore.StoreTypeCustom,
			Name:      "Custom",
			Path:      path,
			CertCount: len(certs),
		},
		Certificates: certs,
	}, nil
}

func filterStoreContents(sc truststore.StoreContents, query string) truststore.StoreContents {
	q := strings.ToLower(query)
	var filtered []*x509.Certificate
	for _, cert := range sc.Certificates {
		if matchesCert(cert, q) {
			filtered = append(filtered, cert)
		}
	}
	sc.Certificates = filtered
	sc.Info.CertCount = len(filtered)
	return sc
}

func matchesCert(cert *x509.Certificate, query string) bool {
	fields := []string{
		cert.Subject.CommonName,
		cert.Issuer.CommonName,
		cert.Subject.String(),
		cert.Issuer.String(),
		cert.SerialNumber.Text(16),
	}
	for _, org := range cert.Subject.Organization {
		fields = append(fields, org)
	}
	for _, dns := range cert.DNSNames {
		fields = append(fields, dns)
	}

	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), query) {
			return true
		}
	}
	return false
}
