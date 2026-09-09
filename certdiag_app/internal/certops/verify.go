package certops

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type VerifyOptions struct {
	Target    string
	StoreType truststore.StoreType
	JavaHome  string
	FilePath  string
	Passwords []certlib.TaggedPassword
	// BundleID selects which shipped snapshot to verify against when
	// StoreType is StoreTypeBundle.
	BundleID  string
	BundleDir string
	// Readers is the store-read seam and NoRealReads stops an unset reader
	// falling back to the real machine. Tests set both.
	Readers     StoreReaders
	NoRealReads bool
	// Dial configures the connection when Target is a host, exactly as the
	// remote commands dial (STARTTLS, proxy, SNI, timeout, client cert).
	Dial certlib.TLSDialOptions
}

type VerifyResult struct {
	Result   truststore.VerifyResult
	Warnings []string
}

func Verify(opts VerifyOptions) (*VerifyResult, error) {
	var certs []*x509.Certificate
	var hostname string

	// The spelling decides, never the file system: host:port or a URL is
	// dialed by the same code the remote commands use, anything else is a
	// file. A mistyped file name is an error, not a connection.
	if certlib.IsRemoteTargetSyntax(opts.Target) {
		target, err := certlib.ParseTarget(opts.Target)
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		if opts.Dial.Starttls != certlib.StarttlsNone && target.Port == 443 && !strings.Contains(opts.Target, ":") {
			target.Port = certlib.DefaultStarttlsPort(opts.Dial.Starttls)
		}
		fetched, err := certlib.DialTLS(target, opts.Dial)
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		certs = fetched.Certificates
		if len(certs) == 0 {
			return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("no certificates received from %s", target.Address())}
		}
		hostname = target.Host
		if opts.Dial.ServerName != "" {
			hostname = opts.Dial.ServerName
		}
	} else {
		filePath := opts.Target
		if _, err := os.Stat(filePath); err != nil {
			return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("%v (a remote endpoint is written host:port or https://host)", err)}
		}
		tagged := append([]certlib.TaggedPassword{}, opts.Passwords...)
		tagged = append(tagged, certlib.TaggedPassword{Password: []byte(""), Source: certlib.PasswordSourceNone})

		container, err := certlib.ReadFile(filePath, tagged)
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("read %s: %v", filePath, err)}
		}

		for _, item := range container.Items {
			if item.Type == certlib.ContentCertificate && item.Certificate != nil {
				certs = append(certs, item.Certificate)
			}
		}

		if len(certs) == 0 {
			return nil, &OperationError{Op: "verify", Message: fmt.Sprintf("no certificates found in %s", filePath)}
		}
	}

	var storeInfo truststore.StoreInfo
	var pool *x509.CertPool
	var warnings []string

	switch opts.StoreType {
	case truststore.StoreTypeOS:
		storeInfo = truststore.StoreInfo{
			Type: truststore.StoreTypeOS,
			Name: "OS Trust Store",
		}
		// An explicit pool built from the store's own contents, never nil: a
		// nil pool routes x509.Verify to the platform verifier, whose answer
		// differs per OS version and which refuses to evaluate a CA at all.
		// This is the same engine the TRUST column uses, so the two agree on
		// the same bytes (M30a option A).
		pool = osAnchorPool(StoreLoadAllOptions{Readers: opts.Readers, NoRealReads: opts.NoRealReads})
		if pool == nil {
			return nil, &OperationError{Op: "verify", Message: "could not read the OS trust store"}
		}

	case truststore.StoreTypeJava:
		stores, err := truststore.ReadJavaStores(opts.JavaHome, javaCacertsReader(opts.Passwords))
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		allCerts := mergeStoreCerts(stores)
		pool = truststore.BuildCertPool(allCerts)
		storeInfo = stores[0].Info
		for _, s := range stores {
			warnings = append(warnings, s.Info.Warnings...)
		}

	case truststore.StoreTypeOpenSSL:
		s, err := truststore.ReadOpenSSLStore()
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		pool = truststore.BuildCertPool(s.Certificates)
		storeInfo = s.Info
		warnings = append(warnings, s.Info.Warnings...)

	case truststore.StoreTypeBundle:
		b, err := truststore.LoadBundle(opts.BundleID, opts.BundleDir)
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		sc := b.StoreContents()
		pool = truststore.BuildCertPool(b.Trusted)
		storeInfo = sc.Info
		warnings = append(warnings, sc.Info.Warnings...)

	case truststore.StoreTypeCustom:
		if opts.FilePath == "" {
			return nil, &OperationError{Op: "verify", Message: "--trust-file requires a path"}
		}
		s, err := readCustomStore(opts.FilePath, opts.Passwords)
		if err != nil {
			return nil, &OperationError{Op: "verify", Message: err.Error()}
		}
		pool = truststore.BuildCertPool(s.Certificates)
		storeInfo = s.Info
		warnings = append(warnings, s.Info.Warnings...)

	default:
		return nil, &OperationError{Op: "verify", Message: "unknown store type"}
	}

	vr := truststore.VerifyChain(certs, storeInfo, pool, hostname)

	return &VerifyResult{
		Result:   vr,
		Warnings: warnings,
	}, nil
}

func mergeStoreCerts(stores []truststore.StoreContents) []*x509.Certificate {
	var all []*x509.Certificate
	for _, s := range stores {
		all = append(all, s.Certificates...)
	}
	return all
}
