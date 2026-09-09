package certlib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

const clockSkewBackdate = time.Hour

func CreateSelfSignedCert(key crypto.PrivateKey, opts CertGenOptions) (*x509.Certificate, []byte, error) {
	pub := publicKey(key)
	if pub == nil {
		return nil, nil, fmt.Errorf("unsupported private key type")
	}

	template, err := buildTemplate(pub, opts)
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse created certificate: %w", err)
	}

	return cert, der, nil
}

func CreateSignedCert(key crypto.PrivateKey, opts CertGenOptions) (*x509.Certificate, []byte, error) {
	if opts.SignerCert == nil || opts.SignerKey == nil {
		return nil, nil, fmt.Errorf("signer certificate and key are required")
	}

	pub := publicKey(key)
	if pub == nil {
		return nil, nil, fmt.Errorf("unsupported private key type")
	}

	template, err := buildTemplate(pub, opts)
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, template, opts.SignerCert, pub, opts.SignerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse created certificate: %w", err)
	}

	return cert, der, nil
}

func CreateCSR(key crypto.PrivateKey, opts CertGenOptions) (*x509.CertificateRequest, []byte, error) {
	pub := publicKey(key)
	if pub == nil {
		return nil, nil, fmt.Errorf("unsupported private key type")
	}

	template := &x509.CertificateRequest{
		Subject:            opts.Subject,
		DNSNames:           opts.SANs.DNSNames,
		IPAddresses:        opts.SANs.IPAddresses,
		EmailAddresses:     opts.SANs.EmailAddresses,
		URIs:               opts.SANs.URIs,
		SignatureAlgorithm: sigAlgo(key),
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse created CSR: %w", err)
	}

	return csr, der, nil
}

func SignCSR(csr *x509.CertificateRequest, caKey crypto.PrivateKey, caCert *x509.Certificate, opts CertGenOptions) (*x509.Certificate, []byte, error) {
	if csr == nil {
		return nil, nil, fmt.Errorf("CSR is required")
	}
	if caCert == nil || caKey == nil {
		return nil, nil, fmt.Errorf("CA certificate and key are required")
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	opts.Subject = csr.Subject
	opts.SANs = SANList{
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	template, err := buildTemplate(csr.PublicKey, opts)
	if err != nil {
		return nil, nil, err
	}

	// Preserve the CSR subject verbatim, including non-standard attributes
	// (emailAddress, domainComponent) that pkix.Name re-marshaling would drop.
	template.RawSubject = csr.RawSubject

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign CSR: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	return cert, der, nil
}

func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

func generateSerial(reader io.Reader) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(reader, max)
		if err != nil {
			return nil, fmt.Errorf("generate serial: %w", err)
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

func buildTemplate(pubKey crypto.PublicKey, opts CertGenOptions) (*x509.Certificate, error) {
	serial := opts.Serial
	if serial == nil {
		var err error
		serial, err = generateSerial(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	now := opts.NotBefore
	explicitNotBefore := !now.IsZero()
	if !explicitNotBefore {
		now = time.Now()
	}

	days := opts.Days
	if days <= 0 {
		days = 365
	}
	notAfter := now.Add(time.Duration(days) * 24 * time.Hour)
	// Backdate only auto-generated (now-based) certs for clock-skew tolerance.
	// An explicit --not-before is authoritative and must be honored exactly.
	notBefore := now
	if !explicitNotBefore {
		notBefore = now.Add(-clockSkewBackdate)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               opts.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              opts.KeyUsage,
		ExtKeyUsage:           opts.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
		DNSNames:              opts.SANs.DNSNames,
		IPAddresses:           opts.SANs.IPAddresses,
		EmailAddresses:        opts.SANs.EmailAddresses,
		URIs:                  opts.SANs.URIs,
	}

	if opts.IsCA {
		if opts.PathLength < 0 {
			template.MaxPathLen = -1
			template.MaxPathLenZero = false
		} else if opts.PathLength == 0 {
			template.MaxPathLen = 0
			template.MaxPathLenZero = true
		} else {
			template.MaxPathLen = opts.PathLength
			template.MaxPathLenZero = false
		}
	}

	template.CRLDistributionPoints = opts.CRLDistributionPoints
	template.OCSPServer = opts.OCSPServer
	template.IssuingCertificateURL = opts.IssuingCertificateURL
	template.PolicyIdentifiers = opts.PolicyIdentifiers
	template.Policies = opts.Policies
	if len(template.Policies) == 0 && len(opts.PolicyIdentifiers) > 0 {
		for _, oid := range opts.PolicyIdentifiers {
			ints := make([]uint64, len(oid))
			for i, v := range oid {
				ints[i] = uint64(v)
			}
			if o, err := x509.OIDFromInts(ints); err == nil {
				template.Policies = append(template.Policies, o)
			}
		}
	}
	template.PermittedDNSDomainsCritical = opts.PermittedDNSDomainsCritical
	template.PermittedDNSDomains = opts.PermittedDNSDomains
	template.ExcludedDNSDomains = opts.ExcludedDNSDomains
	template.PermittedIPRanges = opts.PermittedIPRanges
	template.ExcludedIPRanges = opts.ExcludedIPRanges
	template.PermittedEmailAddresses = opts.PermittedEmailAddresses
	template.ExcludedEmailAddresses = opts.ExcludedEmailAddresses
	template.PermittedURIDomains = opts.PermittedURIDomains
	template.ExcludedURIDomains = opts.ExcludedURIDomains

	// Set SubjectKeyId from public key
	skid, err := computeSKID(pubKey)
	if err != nil {
		return nil, fmt.Errorf("compute subject key id: %w", err)
	}
	template.SubjectKeyId = skid

	return template, nil
}

func computeSKID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// Extract the raw public key bits from SubjectPublicKeyInfo
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	h := sha1.Sum(spki.PublicKey.Bytes)
	return h[:], nil
}

func sigAlgo(key crypto.PrivateKey) x509.SignatureAlgorithm {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		if bits >= 4096 {
			return x509.SHA512WithRSA
		}
		return x509.SHA256WithRSA
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA256
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
