//go:build linux

package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

var certDirs = []string{
	"/etc/ssl/certs",
}

func ReadOSStore() ([]StoreContents, error) {
	envFile := os.Getenv("SSL_CERT_FILE")
	if envFile != "" {
		certs, err := readPEMFile(envFile)
		if err != nil {
			return nil, fmt.Errorf("SSL_CERT_FILE %s: %w", envFile, err)
		}
		return []StoreContents{{
			Info: StoreInfo{
				Type:      StoreTypeOS,
				Name:      "SSL_CERT_FILE",
				Path:      envFile,
				CertCount: len(certs),
			},
			Certificates: certs,
		}}, nil
	}

	for _, path := range certFiles {
		certs, err := readPEMFile(path)
		if err != nil {
			continue
		}
		if len(certs) == 0 {
			continue
		}
		return []StoreContents{{
			Info: StoreInfo{
				Type:      StoreTypeOS,
				Name:      "Linux System CAs",
				Path:      path,
				CertCount: len(certs),
			},
			Certificates: certs,
		}}, nil
	}

	envDir := os.Getenv("SSL_CERT_DIR")
	dirs := certDirs
	if envDir != "" {
		dirs = strings.Split(envDir, ":")
	}

	for _, dir := range dirs {
		certs, err := readPEMDir(dir)
		if err != nil || len(certs) == 0 {
			continue
		}
		return []StoreContents{{
			Info: StoreInfo{
				Type:      StoreTypeOS,
				Name:      "Linux System CAs",
				Path:      dir,
				CertCount: len(certs),
			},
			Certificates: certs,
		}}, nil
	}

	return nil, fmt.Errorf("no system CA bundle found; on minimal/container images, install the ca-certificates package or set SSL_CERT_FILE")
}

func DiscoverOSStores() []StoreInfo {
	envFile := os.Getenv("SSL_CERT_FILE")
	if envFile != "" {
		certs, err := readPEMFile(envFile)
		if err == nil && len(certs) > 0 {
			return []StoreInfo{{
				Type:      StoreTypeOS,
				Name:      "SSL_CERT_FILE",
				Path:      envFile,
				CertCount: len(certs),
			}}
		}
	}

	for _, path := range certFiles {
		certs, err := readPEMFile(path)
		if err != nil || len(certs) == 0 {
			continue
		}
		return []StoreInfo{{
			Type:      StoreTypeOS,
			Name:      "Linux System CAs",
			Path:      path,
			CertCount: len(certs),
		}}
	}

	return nil
}

func readPEMFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

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

func readPEMDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".pem" && ext != ".crt" {
			continue
		}
		fileCerts, err := readPEMFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		certs = append(certs, fileCerts...)
	}
	return certs, nil
}
