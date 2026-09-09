package certops

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// withEmptyPasswordFallback returns a copy of the password slice with an
// empty-password entry appended, used for formats that may have no password.
func withEmptyPasswordFallback(passwords []certlib.TaggedPassword) []certlib.TaggedPassword {
	tagged := append([]certlib.TaggedPassword{}, passwords...)
	return append(tagged, certlib.TaggedPassword{
		Password: []byte(""),
		Source:   certlib.PasswordSourceNone,
	})
}

// readAndValidate reads a file and returns an error if it contains no items.
// Surfaces ParseErrors when the container is empty but parsed without read error.
func readAndValidate(path string, passwords []certlib.TaggedPassword) (*certlib.CertContainer, error) {
	container, err := certlib.ReadFile(path, passwords)
	if err != nil {
		return nil, fmt.Errorf("read input file failed: %w", err)
	}
	if len(container.Items) == 0 {
		if len(container.ParseErrors) > 0 {
			return nil, fmt.Errorf("%s", strings.Join(container.ParseErrors, "; "))
		}
		return nil, fmt.Errorf("no items found in input file")
	}
	return container, nil
}

func loadPrivateKey(path string, passwords []certlib.TaggedPassword) (crypto.PrivateKey, error) {
	tagged := withEmptyPasswordFallback(passwords)

	container, err := certlib.ReadFile(path, tagged)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	for _, item := range container.Items {
		if item.Type == certlib.ContentPrivateKey && item.PrivateKey != nil {
			return item.PrivateKey, nil
		}
	}

	return nil, fmt.Errorf("no private key found in %s", path)
}

func loadCertificate(path string, passwords []certlib.TaggedPassword) (*x509.Certificate, error) {
	tagged := withEmptyPasswordFallback(passwords)

	container, err := certlib.ReadFile(path, tagged)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	for _, item := range container.Items {
		if item.Type == certlib.ContentCertificate && item.Certificate != nil {
			return item.Certificate, nil
		}
	}

	return nil, fmt.Errorf("no certificate found in %s", path)
}

func loadCSR(path string) (*x509.CertificateRequest, error) {
	container, err := certlib.ReadFile(path, []certlib.TaggedPassword{
		{Password: []byte(""), Source: certlib.PasswordSourceNone},
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	for _, item := range container.Items {
		if item.Type == certlib.ContentCSR && item.CSR != nil {
			return item.CSR, nil
		}
	}

	return nil, fmt.Errorf("no CSR found in %s", path)
}
