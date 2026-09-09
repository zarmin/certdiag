package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func DiscoverOpenSSLStore() *StoreInfo {
	dir, err := opensslDir()
	if err != nil {
		return nil
	}

	certPath := filepath.Join(dir, "cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		certPath = filepath.Join(dir, "certs", "ca-certificates.crt")
		if _, err := os.Stat(certPath); err != nil {
			return nil
		}
	}

	certs, err := readOpenSSLPEM(certPath)
	if err != nil || len(certs) == 0 {
		return nil
	}

	return &StoreInfo{
		Type:      StoreTypeOpenSSL,
		Name:      "OpenSSL",
		Path:      certPath,
		CertCount: len(certs),
	}
}

func ReadOpenSSLStore() (*StoreContents, error) {
	dir, err := opensslDir()
	if err != nil {
		return nil, fmt.Errorf("openssl not found in PATH: %w", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		certPath = filepath.Join(dir, "certs", "ca-certificates.crt")
		if _, err := os.Stat(certPath); err != nil {
			return nil, fmt.Errorf("no cert bundle found in OPENSSLDIR %s", dir)
		}
	}

	certs, err := readOpenSSLPEM(certPath)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", certPath)
	}

	return &StoreContents{
		Info: StoreInfo{
			Type:      StoreTypeOpenSSL,
			Name:      "OpenSSL",
			Path:      certPath,
			CertCount: len(certs),
		},
		Certificates: certs,
	}, nil
}

func opensslDir() (string, error) {
	out, err := exec.Command("openssl", "version", "-d").Output()
	if err != nil {
		return "", err
	}
	return ParseOpenSSLDir(string(out))
}

func ParseOpenSSLDir(output string) (string, error) {
	line := strings.TrimSpace(output)
	prefix := "OPENSSLDIR: "
	idx := strings.Index(line, prefix)
	if idx == -1 {
		return "", fmt.Errorf("unexpected openssl version -d output: %s", line)
	}

	dir := line[idx+len(prefix):]
	dir = strings.Trim(dir, "\"")
	if dir == "" {
		return "", fmt.Errorf("empty OPENSSLDIR in output: %s", line)
	}

	return dir, nil
}

func readOpenSSLPEM(path string) ([]*x509.Certificate, error) {
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
