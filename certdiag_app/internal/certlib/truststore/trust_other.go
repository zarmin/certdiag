//go:build !darwin && !windows

package truststore

import "crypto/x509"

func LoadTrustSettings(certs []*x509.Certificate) map[string]CertTrust {
	return nil
}
