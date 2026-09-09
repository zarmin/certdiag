package certlib

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"time"
)

type FileFormat string

const (
	FormatPEM    FileFormat = "pem"
	FormatDER    FileFormat = "der"
	FormatPKCS12 FileFormat = "pkcs12"
	FormatJKS    FileFormat = "jks"
	FormatPKCS7  FileFormat = "pkcs7"
)

func (f FileFormat) IsBundleFormat() bool {
	return f == FormatPKCS12 || f == FormatJKS || f == FormatPKCS7
}

type ContentType string

const (
	ContentCertificate ContentType = "certificate"
	ContentPrivateKey  ContentType = "private_key"
	ContentPublicKey   ContentType = "public_key"
	ContentCSR         ContentType = "csr"
)

type PasswordSource string

const (
	PasswordSourceNone                PasswordSource = ""
	PasswordSourceByFilenamePlain     PasswordSource = "by_filename (plaintext)"
	PasswordSourceByFilenameEncrypted PasswordSource = "by_filename (encrypted)"
	PasswordSourceCLI                 PasswordSource = "arg"
	PasswordSourcePasswordFile        PasswordSource = "password file"
	PasswordSourceCommonPlaintext     PasswordSource = "common plaintext"
	PasswordSourceCommonEncrypted     PasswordSource = "common encrypted"
	PasswordSourceEnvVar              PasswordSource = "env var"
	PasswordSourceInteractive         PasswordSource = "interactive"
	PasswordSourceBuiltIn             PasswordSource = "built-in default"
)

type TaggedPassword struct {
	Password []byte
	Source   PasswordSource
}

type CertSource string

const (
	SourceFile       CertSource = "file"
	SourceRemote     CertSource = "remote"
	SourceAIA        CertSource = "aia"
	SourcePcap       CertSource = "pcap"
	SourceTrustStore CertSource = "truststore"
)

type CertContainer struct {
	FilePath       string
	Label          string // human label; when set, UIs show this instead of the path
	FileSize       int64
	FileModTime    time.Time
	FileAccessTime time.Time
	FileCreateTime time.Time
	Format         FileFormat
	Source         CertSource
	RawData        []byte
	Password       []byte
	UnlockSources  []PasswordSource
	Items          []CertItem
	ParseErrors    []string
	RelationsOnly  bool
}

type CertItem struct {
	Type          ContentType
	Alias         string
	RawBytes      []byte
	Certificate   *x509.Certificate
	PrivateKey    crypto.PrivateKey
	PublicKey     crypto.PublicKey
	CSR           *x509.CertificateRequest
	Encrypted     bool
	EntryPassword []byte   // per-entry password for JKS private key entries
	Chain         [][]byte // DER of issuer certs attached to a key entry (JKS PrivateKeyEntry chain beyond the leaf)
}

type RelationType string

const (
	RelationSignedBy RelationType = "signed_by"
	RelationKeyCert  RelationType = "key_cert_pair"
	RelationKeyCSR   RelationType = "key_csr_pair"
	RelationCSRCert  RelationType = "csr_cert_pair"
	RelationSameCert RelationType = "same_cert"
)

type RelationDirection string

const (
	DirectionOutgoing RelationDirection = "outgoing"
	DirectionIncoming RelationDirection = "incoming"
)

// RelationDisplayKey returns a machine-readable display key for a relation type+direction.
func RelationDisplayKey(rt RelationType, dir RelationDirection) string {
	switch {
	case rt == RelationSignedBy && dir == DirectionOutgoing:
		return "signed_by"
	case rt == RelationSignedBy && dir == DirectionIncoming:
		return "issuer_of"
	case rt == RelationKeyCert && dir == DirectionOutgoing:
		return "key_cert_pair"
	case rt == RelationKeyCert && dir == DirectionIncoming:
		return "key_cert_pair"
	case rt == RelationKeyCSR && dir == DirectionOutgoing:
		return "key_csr_pair"
	case rt == RelationKeyCSR && dir == DirectionIncoming:
		return "key_csr_pair"
	case rt == RelationCSRCert && dir == DirectionOutgoing:
		return "csr_cert_pair"
	case rt == RelationCSRCert && dir == DirectionIncoming:
		return "csr_cert_pair"
	case rt == RelationSameCert:
		return "same_cert"
	default:
		return string(rt)
	}
}

type ItemRef struct {
	ContainerIdx int
	ItemIdx      int
	FilePath     string
	Alias        string
}

type CertRelation struct {
	Type   RelationType
	Source ItemRef
	Target ItemRef
}

type ResolvedRelation struct {
	Type      RelationType
	Direction RelationDirection
	Peer      ItemRef
	Label     string
}

type RelationIndex map[ItemRef][]ResolvedRelation

type CertStore struct {
	Containers []CertContainer
	Relations  []CertRelation
	// Skipped lists what a directory scan could not read: unreadable
	// directories, broken links, oversized or unparseable files with a
	// certificate extension. Populated by the scanner only, so "no
	// certificate there" and "could not read it" stay distinguishable.
	Skipped []SkippedFile
}

// SkippedFile is one path a scan passed over, and why.
type SkippedFile struct {
	Path   string `json:"path" yaml:"path"`
	Reason string `json:"reason" yaml:"reason"`
}

func NewCertStore() *CertStore {
	return &CertStore{
		Containers: make([]CertContainer, 0),
		Relations:  make([]CertRelation, 0),
	}
}

func (s *CertStore) AddContainer(c CertContainer) {
	s.Containers = append(s.Containers, c)
}

type PasswordProvider interface {
	PasswordsForFile(filePath string) []TaggedPassword
}

type WriteOptions struct {
	OutputPath   string
	OutputFormat FileFormat
	Password     []byte
	Alias        string
	Overwrite    bool
	EncryptPEM   bool
}

type KeyGenOptions struct {
	Algorithm string // "rsa", "ecdsa", "ed25519"
	KeySize   int    // RSA bits (2048, 3072, 4096)
	Curve     string // ECDSA curve ("p256", "p384", "p521")
}

type CertGenOptions struct {
	Subject     pkix.Name
	SANs        SANList
	Days        int
	NotBefore   time.Time
	IsCA        bool
	PathLength  int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	Serial      *big.Int
	SignerCert  *x509.Certificate
	SignerKey   crypto.PrivateKey

	CRLDistributionPoints []string
	OCSPServer            []string
	IssuingCertificateURL []string
	PolicyIdentifiers     []asn1.ObjectIdentifier
	Policies              []x509.OID

	PermittedDNSDomainsCritical bool
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string
}

type SANList struct {
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
}

func (s SANList) IsEmpty() bool {
	return len(s.DNSNames) == 0 && len(s.IPAddresses) == 0 &&
		len(s.EmailAddresses) == 0 && len(s.URIs) == 0
}

// SafeItem returns the CertItem at the given ref, or nil if out of bounds.
func (s *CertStore) SafeItem(ref ItemRef) *CertItem {
	if ref.ContainerIdx < 0 || ref.ContainerIdx >= len(s.Containers) {
		return nil
	}
	c := &s.Containers[ref.ContainerIdx]
	if ref.ItemIdx < 0 || ref.ItemIdx >= len(c.Items) {
		return nil
	}
	return &c.Items[ref.ItemIdx]
}

func (s *CertStore) TotalItems() int {
	count := 0
	for _, c := range s.Containers {
		count += len(c.Items)
	}
	return count
}
