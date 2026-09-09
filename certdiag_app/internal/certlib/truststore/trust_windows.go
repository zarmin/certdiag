//go:build windows

package truststore

import "crypto/x509"

func LoadTrustSettings(certs []*x509.Certificate) map[string]CertTrust {
	disallowed, err := readWindowsStore("Disallowed")
	if err != nil || len(disallowed) == 0 {
		return nil
	}

	denySet := make(map[string]bool)
	for _, cert := range disallowed {
		denySet[CertFingerprint(cert)] = true
	}

	trustMap := make(map[string]CertTrust)
	for _, cert := range certs {
		fp := CertFingerprint(cert)
		if denySet[fp] {
			trustMap[fp] = CertTrust{Overall: TrustDenied}
		}
	}

	return trustMap
}
