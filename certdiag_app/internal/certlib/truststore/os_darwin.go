//go:build darwin

package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var macKeychains = []struct {
	path string
	name string
}{
	{"/System/Library/Keychains/SystemRootCertificates.keychain", "macOS System Roots"},
	{"/Library/Keychains/System.keychain", "macOS System Keychain"},
}

func ReadOSStore() ([]StoreContents, error) {
	var stores []StoreContents

	homeDir, _ := os.UserHomeDir()

	keychains := make([]struct{ path, name string }, len(macKeychains))
	copy(keychains, macKeychains[:])
	if homeDir != "" {
		keychains = append(keychains, struct{ path, name string }{
			filepath.Join(homeDir, "Library", "Keychains", "login.keychain-db"),
			"macOS Login Keychain",
		})
	}

	for _, kc := range keychains {
		if _, err := os.Stat(kc.path); err != nil {
			continue
		}

		certs, err := readKeychainCerts(kc.path)
		if err != nil {
			continue
		}

		if len(certs) == 0 {
			continue
		}

		stores = append(stores, StoreContents{
			Info: StoreInfo{
				Type:      StoreTypeOS,
				Name:      kc.name,
				Path:      kc.path,
				CertCount: len(certs),
			},
			Certificates: certs,
		})
	}

	if len(stores) == 0 {
		return nil, fmt.Errorf("no macOS keychains found")
	}

	var allCerts []*x509.Certificate
	for _, s := range stores {
		allCerts = append(allCerts, s.Certificates...)
	}
	trustMap := LoadTrustSettings(allCerts)

	for i := range stores {
		stores[i].TrustMap = make(map[string]CertTrust)
		for _, cert := range stores[i].Certificates {
			fp := CertFingerprint(cert)
			if t, ok := trustMap[fp]; ok {
				stores[i].TrustMap[fp] = t
			}
		}
	}

	return stores, nil
}

func DiscoverOSStores() []StoreInfo {
	var stores []StoreInfo

	homeDir, _ := os.UserHomeDir()

	keychains := make([]struct{ path, name string }, len(macKeychains))
	copy(keychains, macKeychains[:])
	if homeDir != "" {
		keychains = append(keychains, struct{ path, name string }{
			filepath.Join(homeDir, "Library", "Keychains", "login.keychain-db"),
			"macOS Login Keychain",
		})
	}

	for _, kc := range keychains {
		if _, err := os.Stat(kc.path); err != nil {
			continue
		}

		certs, err := readKeychainCerts(kc.path)
		if err != nil {
			continue
		}

		stores = append(stores, StoreInfo{
			Type:      StoreTypeOS,
			Name:      kc.name,
			Path:      kc.path,
			CertCount: len(certs),
		})
	}

	return stores
}

func readKeychainCerts(keychainPath string) ([]*x509.Certificate, error) {
	out, err := exec.Command("security", "find-certificate", "-a", "-p", keychainPath).Output()
	if err != nil {
		return nil, fmt.Errorf("security find-certificate failed for %s: %w", keychainPath, err)
	}

	return parsePEMCerts(out)
}

func parsePEMCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
