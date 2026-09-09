package truststore

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
)

type StoreType string

const (
	StoreTypeOS      StoreType = "os"
	StoreTypeJava    StoreType = "java"
	StoreTypeOpenSSL StoreType = "openssl"
	StoreTypeCustom  StoreType = "custom"
)

type StoreInfo struct {
	Type      StoreType
	Name      string
	Path      string
	CertCount int
	Warnings  []string
	// ID identifies a store within its type, currently the bundle id
	// ("mozilla", "chrome"). Empty for stores that need no sub-identity.
	ID string
}

type TrustStatus string

const (
	TrustTrusted TrustStatus = "Trusted"
	TrustDenied  TrustStatus = "Denied"
	TrustUnset   TrustStatus = "Unset"
)

type TrustPolicy struct {
	Purpose string
	Status  TrustStatus
}

type CertTrust struct {
	Overall  TrustStatus
	Policies []TrustPolicy
}

type StoreContents struct {
	Info         StoreInfo
	Certificates []*x509.Certificate
	TrustMap     map[string]CertTrust
}

func CertFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h)
}

func (sc *StoreContents) GetTrust(cert *x509.Certificate) CertTrust {
	if sc.TrustMap == nil {
		return CertTrust{Overall: TrustUnset}
	}
	fp := CertFingerprint(cert)
	if t, ok := sc.TrustMap[fp]; ok {
		return t
	}
	return CertTrust{Overall: TrustUnset}
}

type VerifyResult struct {
	Trusted     bool
	Chain       []*x509.Certificate
	TrustAnchor *x509.Certificate
	Store       StoreInfo
	Error       error
	Reason      string
	Suggestions []string
	Hostname    string
}

func BuildCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func ClassifyVerifyError(err error, hostname string) (string, []string) {
	if err == nil {
		return "", nil
	}

	switch e := err.(type) {
	case x509.UnknownAuthorityError:
		return "unknown authority -- no CA in the trust store issued this certificate",
			[]string{
				"The issuing CA may be a private/corporate CA not in the trust store",
				"Check if an intermediate certificate is missing from the server's chain",
				"Use --trust-file to verify against a custom CA bundle",
			}

	case x509.CertificateInvalidError:
		if e.Reason == x509.Expired {
			now := time.Now()
			if now.Before(e.Cert.NotBefore) {
				return fmt.Sprintf("certificate not yet valid (cert: %s)", e.Cert.Subject.CommonName),
					[]string{fmt.Sprintf("Certificate becomes valid on %s", e.Cert.NotBefore.Format("2006-01-02"))}
			}
			return fmt.Sprintf("certificate expired (cert: %s)", e.Cert.Subject.CommonName),
				[]string{fmt.Sprintf("Certificate expired on %s", e.Cert.NotAfter.Format("2006-01-02"))}
		}
		return fmt.Sprintf("certificate invalid: %v", e), nil

	case x509.HostnameError:
		return fmt.Sprintf("hostname mismatch -- certificate is not valid for %s", hostname),
			[]string{fmt.Sprintf("Certificate is for %v, not %s", e.Certificate.DNSNames, hostname)}

	default:
		return err.Error(),
			[]string{"An intermediate certificate may be missing from the chain"}
	}
}
