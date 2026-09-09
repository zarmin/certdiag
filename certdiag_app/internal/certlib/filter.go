package certlib

import (
	"path/filepath"
	"strings"
)

func FilterContainers(containers []*CertContainer, query string) []*CertContainer {
	if query == "" {
		return containers
	}

	query = strings.ToLower(query)
	var result []*CertContainer

	for _, container := range containers {
		if containerMatches(container, query) {
			result = append(result, container)
		}
	}

	return result
}

func containerMatches(container *CertContainer, query string) bool {
	filename := strings.ToLower(filepath.Base(container.FilePath))
	if strings.Contains(filename, query) {
		return true
	}

	for _, item := range container.Items {
		if itemMatches(&item, query) {
			return true
		}
	}

	return false
}

func itemMatches(item *CertItem, query string) bool {
	switch item.Type {
	case ContentCertificate:
		if item.Certificate == nil {
			return false
		}
		cert := item.Certificate

		serial := strings.ToLower(cert.SerialNumber.String())
		if strings.Contains(serial, query) {
			return true
		}

		serialHex := strings.ToLower(FormatSerial(cert.SerialNumber))
		if strings.Contains(serialHex, query) {
			return true
		}

		cn := strings.ToLower(cert.Subject.CommonName)
		if strings.Contains(cn, query) {
			return true
		}

		for _, dns := range cert.DNSNames {
			if strings.Contains(strings.ToLower(dns), query) {
				return true
			}
		}

		for _, ip := range cert.IPAddresses {
			if strings.Contains(ip.String(), query) {
				return true
			}
		}

		for _, email := range cert.EmailAddresses {
			if strings.Contains(strings.ToLower(email), query) {
				return true
			}
		}

		for _, uri := range cert.URIs {
			if strings.Contains(strings.ToLower(uri.String()), query) {
				return true
			}
		}

		othernames, err := ParseOthernameSANs(cert)
		if err == nil {
			for _, on := range othernames {
				if strings.Contains(strings.ToLower(on.Value), query) {
					return true
				}
			}
		}

		subj := strings.ToLower(FormatDNName(cert.Subject))
		if strings.Contains(subj, query) {
			return true
		}

	case ContentCSR:
		if item.CSR == nil {
			return false
		}
		csr := item.CSR

		cn := strings.ToLower(csr.Subject.CommonName)
		if strings.Contains(cn, query) {
			return true
		}

		for _, dns := range csr.DNSNames {
			if strings.Contains(strings.ToLower(dns), query) {
				return true
			}
		}

		subj := strings.ToLower(FormatDNName(csr.Subject))
		if strings.Contains(subj, query) {
			return true
		}
	}

	if item.Alias != "" {
		if strings.Contains(strings.ToLower(item.Alias), query) {
			return true
		}
	}

	return false
}
