package tui

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type prefillData struct {
	org     string
	country string
	extraDN string
	sans    string
	isCA    bool
	ku      string
	eku     string
}

func prefillFromCert(cert *x509.Certificate) prefillData {
	var d prefillData
	if len(cert.Subject.Organization) > 0 {
		d.org = cert.Subject.Organization[0]
	}
	if len(cert.Subject.Country) > 0 {
		d.country = cert.Subject.Country[0]
	}
	d.extraDN = formatExtraDN(cert.Subject)
	sans := certlib.FormatSANs(cert)
	d.sans = formatSANsForForm(sans)
	d.isCA = cert.IsCA
	d.ku = certlib.FormatKeyUsageInternal(cert.KeyUsage)
	d.eku = certlib.FormatExtKeyUsageInternal(cert.ExtKeyUsage)
	return d
}

func prefillFromCSR(csr *x509.CertificateRequest) prefillData {
	var d prefillData
	if len(csr.Subject.Organization) > 0 {
		d.org = csr.Subject.Organization[0]
	}
	if len(csr.Subject.Country) > 0 {
		d.country = csr.Subject.Country[0]
	}
	d.extraDN = formatExtraDN(csr.Subject)
	d.sans = formatCSRSANsForForm(csr)
	return d
}

func formatExtraDN(subj pkix.Name) string {
	var parts []string
	for _, ou := range subj.OrganizationalUnit {
		parts = append(parts, "OU="+ou)
	}
	for _, l := range subj.Locality {
		parts = append(parts, "L="+l)
	}
	for _, st := range subj.Province {
		parts = append(parts, "ST="+st)
	}
	if subj.SerialNumber != "" {
		parts = append(parts, "SERIALNUMBER="+subj.SerialNumber)
	}
	for _, sa := range subj.StreetAddress {
		parts = append(parts, "STREET="+sa)
	}
	for _, pc := range subj.PostalCode {
		parts = append(parts, "POSTALCODE="+pc)
	}
	return strings.Join(parts, ",")
}

func formatSANsForForm(sans []string) string {
	var parts []string
	for _, s := range sans {
		lower := strings.ToLower(s)
		if strings.HasPrefix(lower, "dns:") {
			parts = append(parts, "dns:"+s[4:])
		} else if strings.HasPrefix(lower, "ip:") {
			parts = append(parts, "ip:"+s[3:])
		} else if strings.HasPrefix(lower, "email:") {
			parts = append(parts, "email:"+s[6:])
		} else if strings.HasPrefix(lower, "uri:") {
			parts = append(parts, "uri:"+s[4:])
		} else {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

func formatCSRSANsForForm(csr *x509.CertificateRequest) string {
	var parts []string
	for _, dns := range csr.DNSNames {
		parts = append(parts, "dns:"+dns)
	}
	for _, ip := range csr.IPAddresses {
		parts = append(parts, "ip:"+ip.String())
	}
	for _, email := range csr.EmailAddresses {
		parts = append(parts, "email:"+email)
	}
	for _, uri := range csr.URIs {
		parts = append(parts, "uri:"+uri.String())
	}
	return strings.Join(parts, ",")
}

func applyPrefill(f *formModel, data prefillData, isCertForm bool) {
	if data.org != "" {
		f.fieldByName(fieldKeyOrg).SetValue(data.org)
	}
	if data.country != "" {
		f.fieldByName(fieldKeyCountry).SetValue(data.country)
	}
	if data.extraDN != "" {
		f.fieldByName(fieldKeyExtraDn).SetValue(data.extraDN)
	}
	if data.sans != "" {
		f.fieldByName(fieldKeySans).SetValue(data.sans)
	}
	if !isCertForm {
		return
	}
	if data.isCA {
		f.fieldByName(fieldKeyCertType).SetValue(labelCA)
	}
	if data.ku != "" {
		f.fieldByName(fieldKeyKeyUsage).SetValue(data.ku)
	}
	if data.eku != "" {
		f.fieldByName(fieldKeyExtKeyUsage).SetValue(data.eku)
	}
	f.syncValueRuleDeps()
}
