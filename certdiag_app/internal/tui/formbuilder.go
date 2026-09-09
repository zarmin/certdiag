package tui

import (
	"crypto/x509"
	"strconv"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func inputPasswordsFromMeta(form *formModel) []certlib.TaggedPassword {
	if pw := form.getMeta("input_password"); pw != "" {
		return []certlib.TaggedPassword{{Password: []byte(pw), Source: certlib.PasswordSourceInteractive}}
	}
	return nil
}

type filePickedMsg struct {
	fieldName string
	path      string
}

func (f *formModel) handleFilePicked(msg filePickedMsg) {
	for i, name := range f.fieldNames {
		if name == msg.fieldName {
			f.fields[i].SetValue(msg.path)
			// The picker satisfied the field; a "required" error from an
			// earlier submit must not outlive the value that fixes it.
			f.validateField(i)
			return
		}
	}
}

type formKind int

const (
	formNone formKind = iota
	formCreateKey
	formCreateCert
	formCreateCSR
	formSignCSR
	formConvert
	formExtract
	formRenew
	formBundle
	formReencrypt
	formRemovePassphrase
	formRemote
	formPcapAnalyze
	formProxySetup
	formTrustStore
)

const (
	keySourceGenerate = "Generate new"
	keySourceExisting = "Use existing"
	keySourceReuse    = "Reuse existing"

	labelRSA     = "RSA"
	labelECDSA   = "ECDSA"
	labelEd25519 = "Ed25519"

	labelP256 = "P-256"
	labelP384 = "P-384"
	labelP521 = "P-521"

	labelPEM    = "PEM"
	labelDER    = "DER"
	labelPKCS12 = "PKCS#12"
	labelPKCS7  = "PKCS#7"
	labelJKS    = "JKS"

	labelSignWithCA = "Sign with CA"
	labelAutosign   = "Autosign"

	labelCA = "CA"

	labelIndividualFiles = "Individual files"
	labelBundlePEM       = "Bundle (PEM)"

	labelCertsOnly = "Certificates only"
	labelKeysOnly  = "Keys only"

	labelNewFile           = "New file"
	labelOverwriteOriginal = "Overwrite original"
	labelRemovePassword    = "Remove password"

	warnNoSignatureScan = "Signature scanning is disabled. Without it, the file can only be identified by its extension, not its content."
)

var (
	algoOptions    = []string{labelECDSA, labelRSA, labelEd25519}
	curveOptions   = []string{labelP256, labelP384, labelP521}
	keySizeOptions = []string{"2048", "4096"}

	// Save extension hints per content type (used in confirm mode by file pickers).
	extsPEM     = []string{".pem", ".crt", ".cer", ".key", ".pub", ".ca-bundle", ".cert", ".chain"}
	extsDERCert = []string{".der", ".crt", ".cer"}
	extsDERKey  = []string{".der", ".key"}
	extsPKCS12  = []string{".p12", ".pfx"}
	extsPKCS7   = []string{".p7b", ".p7c"}
	extsJKS     = []string{".jks"}
	extsCSR     = []string{".csr", ".pem"}

	// Combined lists for fields where PEM/DER format is selectable.
	extsCertOutput   = []string{".pem", ".crt", ".cer", ".cert", ".ca-bundle", ".chain", ".der"}
	extsKeyOutput    = []string{".pem", ".key", ".der"}
	extsBundleOutput = []string{".pem", ".crt", ".cer", ".key", ".pub", ".ca-bundle", ".cert", ".chain"}
)

func extsForFormat(format string) []string {
	switch format {
	case labelPEM:
		return extsPEM
	case labelDER:
		return extsDERCert
	case labelPKCS12:
		return extsPKCS12
	case labelPKCS7:
		return extsPKCS7
	case labelJKS:
		return extsJKS
	default:
		return nil
	}
}

func autoExtForFormat(format string) string {
	switch format {
	case labelPEM:
		return ".pem"
	case labelDER:
		return ".der"
	case labelPKCS12:
		return ".p12"
	case labelPKCS7:
		return ".p7b"
	case labelJKS:
		return ".jks"
	default:
		return ""
	}
}

func extsForFileFormat(f certlib.FileFormat) []string {
	switch f {
	case certlib.FormatPEM:
		return extsPEM
	case certlib.FormatDER:
		return extsDERCert
	case certlib.FormatPKCS12:
		return extsPKCS12
	case certlib.FormatPKCS7:
		return extsPKCS7
	case certlib.FormatJKS:
		return extsJKS
	default:
		return nil
	}
}

func extsForExtract(ct certlib.ContentType, format string) []string {
	if format == labelDER {
		switch ct {
		case certlib.ContentPrivateKey:
			return extsDERKey
		default:
			return extsDERCert
		}
	}
	switch ct {
	case certlib.ContentCSR:
		return extsCSR
	case certlib.ContentPrivateKey:
		return extsKeyOutput
	default:
		return extsCertOutput
	}
}

func algoInternal(label string) string {
	return strings.ToLower(label)
}

func curveInternal(label string) string {
	return strings.ReplaceAll(strings.ToLower(label), "-", "")
}

type FormResultMsg struct {
	Success    bool
	Message    string
	Err        error
	FileExists bool
	Passwords  [][]byte
}

func radioIndex(options []string, value string) int {
	for i, o := range options {
		if strings.EqualFold(o, value) {
			return i
		}
	}
	return 0
}

func curveRadioIndex(options []string, value string) int {
	norm := strings.ToLower(strings.ReplaceAll(value, "-", ""))
	for i, o := range options {
		if strings.ToLower(strings.ReplaceAll(o, "-", "")) == norm {
			return i
		}
	}
	return 0
}

func sizeRadioIndex(options []string, size int) int {
	s := strconv.Itoa(size)
	for i, o := range options {
		if o == s {
			return i
		}
	}
	return 0
}

func (f *formModel) setExtensionWarning(msg string) {
	for _, field := range f.fields {
		if fp, ok := field.(*filePickerField); ok {
			fp.extensionWarning = msg
		}
	}
}

var kuOptions = []multiCheckOption{
	{"DigSig", "digitalSignature"},
	{"ContCom", "contentCommitment"},
	{"KeyEnc", "keyEncipherment"},
	{"DataEnc", "dataEncipherment"},
	{"KeyAgree", "keyAgreement"},
	{"CertSign", "certSign"},
	{"CRLSign", "crlSign"},
	{"EncOnly", "encipherOnly"},
	{"DecOnly", "decipherOnly"},
}

var ekuOptions = []multiCheckOption{
	{"Any", "any"},
	{"Server", "serverAuth"},
	{"Client", "clientAuth"},
	{"CodeSign", "codeSigning"},
	{"Email", "emailProtection"},
	{"TimeStamp", "timeStamping"},
	{"OCSP", "ocspSigning"},
}

const (
	kuDefaultLeaf  = "digitalSignature,keyEncipherment"
	kuDefaultCA    = "certSign,crlSign"
	ekuDefaultLeaf = "serverAuth,clientAuth"
)

func parseFormKeyUsage(form *formModel) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	ku, err := certlib.ParseKeyUsage(form.fieldValue(fieldKeyKeyUsage))
	if err != nil {
		return 0, nil, err
	}
	eku, err := certlib.ParseExtKeyUsage(form.fieldValue(fieldKeyExtKeyUsage))
	if err != nil {
		return 0, nil, err
	}
	return ku, eku, nil
}

func buildForm(kind formKind, scanPath string, node *TreeNode, subjectOrg, subjectCountry string, keyDefaults certlib.KeyGenOptions, defaultDays, defaultCADays int) *formModel {
	form := buildFormForKind(kind, scanPath, node, subjectOrg, subjectCountry, keyDefaults, defaultDays, defaultCADays)
	if form != nil && formHasOpenSSLEquivalent(kind) {
		form.opensslEligible = true
	}
	return form
}

// formHasOpenSSLEquivalent reports whether a form kind maps to an openssl (or
// keytool) command that the 'o' shortcut can show.
func formHasOpenSSLEquivalent(kind formKind) bool {
	switch kind {
	case formCreateKey, formCreateCert, formCreateCSR, formSignCSR, formConvert:
		return true
	}
	return false
}

func buildFormForKind(kind formKind, scanPath string, node *TreeNode, subjectOrg, subjectCountry string, keyDefaults certlib.KeyGenOptions, defaultDays, defaultCADays int) *formModel {
	switch kind {
	case formCreateKey:
		return buildCreateKeyForm(scanPath, keyDefaults)
	case formCreateCert:
		return buildCreateCertForm(scanPath, node, subjectOrg, subjectCountry, keyDefaults, defaultDays, defaultCADays)
	case formCreateCSR:
		return buildCreateCSRForm(scanPath, node, subjectOrg, subjectCountry, keyDefaults)
	case formSignCSR:
		return buildSignCSRForm(scanPath, node, defaultDays, defaultCADays)
	case formConvert:
		return buildConvertForm(scanPath, node)
	case formRenew:
		return buildRenewForm(scanPath, node, keyDefaults, defaultDays)
	case formExtract:
		return buildExtractForm(scanPath, node)
	case formReencrypt:
		return buildReencryptForm(scanPath, node)
	case formRemovePassphrase:
		return buildRemovePassphraseForm(scanPath, node)
	default:
		return nil
	}
}

// Form field-key identifiers (see the no-bare-string-identifiers rule).
const (
	fieldKeyAlgo            = "algo"
	fieldKeyAlias           = "alias"
	fieldKeyBundleOut       = "bundle_out"
	fieldKeyCaCert          = "ca_cert"
	fieldKeyCaKey           = "ca_key"
	fieldKeyCertOut         = "cert_out"
	fieldKeyCertType        = "cert_type"
	fieldKeyClientAlias     = "client_alias"
	fieldKeyClientCert      = "client_cert"
	fieldKeyClientJks       = "client_jks"
	fieldKeyClientKey       = "client_key"
	fieldKeyClientP12       = "client_p12"
	fieldKeyClientPassword  = "client_password"
	fieldKeyCn              = "cn"
	fieldKeyConfirmPassword = "confirm_password"
	fieldKeyCountry         = "country"
	fieldKeyCsrOut          = "csr_out"
	fieldKeyCurve           = "curve"
	fieldKeyDays            = "days"
	fieldKeyEncrypt         = "encrypt"
	fieldKeyEncryptKey      = "encrypt_key"
	fieldKeyEncryptPassword = "encrypt_password"
	fieldKeyExtKeyUsage     = "ext_key_usage"
	fieldKeyExtraDn         = "extra_dn"
	fieldKeyFormat          = "format"
	fieldKeyInclude         = "include"
	fieldKeyIpVersion       = "ip_version"
	fieldKeyItemAliases     = "item_aliases"
	fieldKeyKeyOut          = "key_out"
	fieldKeyKeyPath         = "key_path"
	fieldKeyKeySource       = "key_source"
	fieldKeyKeyUsage        = "key_usage"
	fieldKeyLegacy          = "legacy"
	fieldKeyMtlsMode        = "mtls_mode"
	fieldKeyNewPassword     = "new_password"
	fieldKeyOrg             = "org"
	fieldKeyOutput          = "output"
	fieldKeyOutputDir       = "output_dir"
	fieldKeyOutputFile      = "output_file"
	fieldKeyOutputMode      = "output_mode"
	fieldKeyPassword        = "password"
	fieldKeyPathLen         = "path_len"
	fieldKeyPermittedNames  = "permitted_names"
	fieldKeyExcludedNames   = "excluded_names"
	fieldKeyPcapAggressive  = "pcap_aggressive"
	fieldKeyPcapFile        = "pcap_file"
	fieldKeyPkcs12Notice    = "pkcs12_notice"
	fieldKeyProxyAggressive = "proxy_aggressive"
	fieldKeyProxyListen     = "proxy_listen"
	fieldKeyProxyTarget     = "proxy_target"
	fieldKeyRemovePassword  = "remove_password"
	fieldKeySans            = "sans"
	fieldKeySigning         = "signing"
	fieldKeySize            = "size"
	fieldKeySni             = "sni"
	fieldKeyStarttls        = "starttls"
	fieldKeySubmit          = "submit"
	fieldKeyTarget          = "target"
	fieldKeyTip             = "tip"
	fieldKeyTlsVersion      = "tls_version"
	fieldKeyTypeFilter      = "type_filter"
)
