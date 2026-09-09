package config

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"gopkg.in/yaml.v3"
)

const exampleConfig = `# certdiag configuration file
# Automatically loaded from ~/.certdiag/certdiag.yaml
# Override with: -c /path/to/config  or  CERTDIAG_CONFIG=/path/to/config
#
# Password resolution order (for each file scanned):
#   1. by_filename matches (glob or exact path)
#   2. CLI -p flags
#   3. common_plaintext / common_encrypted entries
#   4. CERTDIAG_PASSWORD_* environment variables
#
# To encrypt a password for this file:
#   certdiag password encrypt --master-password <key> --password <pw>
#   (master password can also be set via CERTDIAG_MASTER_KEY env var)

kind: certdiag-config
version: "1"

# defaults:
#   key:
#     algorithm: "ecdsa"        # "rsa", "ecdsa", "ed25519"
#     rsa_key_size: 2048        # 2048, 3072, 4096
#     ecdsa_curve: "p256"       # "p256", "p384", "p521"
#   cert:
#     days: 365                 # leaf cert validity
#     ca_days: 3650             # CA cert validity
#   subject:
#     organization: ""          # TUI default is "Example Org"; set "" to disable it
#     country: ""
#   output:
#     format: "pem"
#     overwrite_confirm: true
#     fingerprint_format: "hex"  # "hex", "hex-colon", or "base64"
#                                # display only - JSON/YAML always use plain hex
#   keystore:
#     pkcs12_algorithm: "modern"
#   tui:
#     recursive: false          # scan directories recursively
#     max_depth: 0              # recursion depth limit (0 = unlimited)
#     file_signature_scan: false # detect certs by magic bytes, not extension
#     auto_discover: false      # auto-discover related files in same directory
#     path_display: "filename"  # "filename", "relative", or "absolute"
#     columns:                  # visible columns in TUI tree (use [C] in TUI to edit)
#       - subject               # default on: subject, issuer, expiry, algo
#       - issuer
#       - expiry
#       - algo
#       # - valid_from          # certificate validity start date
#       # - sans                # subject alternative names (multi-line)
#       # - usage               # key usage flags
#       # - relations           # chain / signing relationships (multi-line)
#       # - fp_sha256           # SHA-256 fingerprint (also fp_md5, fp_sha1,
#       # - fp_sha1             #   fp_sha384, fp_sha512)

passwords:
  # Passwords tried for ALL scanned files (after filename-specific matches)
  # "changeit" is built in and always tried last, no need to list it here
  # WARNING: plaintext passwords are visible in this file - restrict file permissions
  # common_plaintext:
  #   - "password"
  #   - "password123"

  # Encrypted passwords - generated with 'certdiag password encrypt'
  # Decryption requires --master-password flag or CERTDIAG_MASTER_KEY env var
  # common_encrypted:
  #   - "base64encryptedblob=="

  # Per-file passwords matched FIRST before common entries
  # Use 'filename' for glob matching against the file basename
  # Use 'filepath' for an exact absolute path match
  # by_filename:
  #   - filename: "*.p12"
  #     plaintext_password: "p12password"
  #
  #   - filename: "keystore*.jks"
  #     encrypted_password: "base64encryptedblob=="
  #
  #   - filepath: "/etc/ssl/private/server.p12"
  #     plaintext_password: "serverpassword"
`

// EnsureConfig creates the config file from the example template if it does
// not exist yet. Only an explicit user action calls it (`config init`, saving
// options in the TUI): a read-only diagnostic never writes to $HOME on its own.
func EnsureConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return WriteExampleConfig(path)
}

// WriteExampleConfig writes the example template to path, replacing whatever
// is there. The file can hold passwords, so it is created 0600.
func WriteExampleConfig(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(exampleConfig), 0o600)
}

var (
	ErrInvalidKind    = errors.New("invalid config: kind must be 'certdiag-config'")
	ErrInvalidVersion = errors.New("invalid config: unsupported version")
)

type ConfigFile struct {
	Kind      string          `yaml:"kind"`
	Version   string          `yaml:"version"`
	Defaults  DefaultsConfig  `yaml:"defaults,omitempty"`
	Passwords PasswordsConfig `yaml:"passwords"`
}

type DefaultsConfig struct {
	Key      KeyDefaults      `yaml:"key,omitempty"`
	Cert     CertDefaults     `yaml:"cert,omitempty"`
	Subject  SubjectDefaults  `yaml:"subject,omitempty"`
	Output   OutputDefaults   `yaml:"output,omitempty"`
	Keystore KeystoreDefaults `yaml:"keystore,omitempty"`
	TUI      TUIConfig        `yaml:"tui,omitempty"`
	Check    CheckConfig      `yaml:"check,omitempty"`
	Remote   RemoteConfig     `yaml:"remote,omitempty"`
	AIA      AIAConfig        `yaml:"aia,omitempty"`
}

// AIAConfig controls Authority Information Access fetching. Everything here is
// off by default: AIA reaches the network, and certdiag only does that when
// asked.
type AIAConfig struct {
	Enabled bool `yaml:"enabled,omitempty"`
	// Cache keeps fetched certificates in ~/.certdiag/aia. It stores bytes,
	// never verdicts, and every surface that uses one says so with its date.
	Cache bool `yaml:"cache,omitempty"`
	// CacheTTL is a fixed lifetime, not an HTTP cache header: simpler to
	// explain and to reason about when an answer looks stale.
	CacheTTL string `yaml:"cache_ttl,omitempty"`
}

type RemoteConfig struct {
	Timeout  string `yaml:"timeout,omitempty"`
	Parallel int    `yaml:"parallel,omitempty"`
	Proxy    string `yaml:"proxy,omitempty"`
}

type CheckConfig struct {
	ExpiryWarnDays     int      `yaml:"expiry_warn_days,omitempty"`
	ExpiryCriticalDays int      `yaml:"expiry_critical_days,omitempty"`
	DisabledChecks     []string `yaml:"disabled_checks,omitempty"`
}

type TUIConfig struct {
	Columns            []string `yaml:"columns,omitempty"`
	Recursive          *bool    `yaml:"recursive,omitempty"`
	MaxDepth           int      `yaml:"max_depth,omitempty"`
	FileSignatureScan  *bool    `yaml:"file_signature_scan,omitempty"`
	AutoDiscover       *bool    `yaml:"auto_discover,omitempty"`
	PathDisplay        string   `yaml:"path_display,omitempty"`
	TrustStoreColumns  []string `yaml:"trust_store_columns,omitempty"`
	TrustStoreGrouping string   `yaml:"trust_store_grouping,omitempty"`
}

type KeyDefaults struct {
	Algorithm  string `yaml:"algorithm,omitempty"`
	RSAKeySize int    `yaml:"rsa_key_size,omitempty"`
	ECDSACurve string `yaml:"ecdsa_curve,omitempty"`
}

type CertDefaults struct {
	Days        int      `yaml:"days,omitempty"`
	CADays      int      `yaml:"ca_days,omitempty"`
	KeyUsage    []string `yaml:"key_usage,omitempty"`
	ExtKeyUsage []string `yaml:"ext_key_usage,omitempty"`
}

type SubjectDefaults struct {
	Organization       *string `yaml:"organization,omitempty"`
	OrganizationalUnit string  `yaml:"organizational_unit,omitempty"`
	Country            string  `yaml:"country,omitempty"`
	State              string  `yaml:"state,omitempty"`
	Locality           string  `yaml:"locality,omitempty"`
}

type OutputDefaults struct {
	Format           string `yaml:"format,omitempty"`
	OverwriteConfirm *bool  `yaml:"overwrite_confirm,omitempty"`
	// FingerprintFormat is display-only: JSON and YAML always use plain hex.
	FingerprintFormat string `yaml:"fingerprint_format,omitempty"`
	// Trust turns on trust evaluation for every scan without --trust. Off by
	// default: a plain scan must not pay for reading the OS trust store.
	Trust bool `yaml:"trust,omitempty"`
}

type KeystoreDefaults struct {
	PKCS12Algorithm    string `yaml:"pkcs12_algorithm,omitempty"`
	FriendlyNameFromCN *bool  `yaml:"friendly_name_from_cn,omitempty"`
}

type PasswordsConfig struct {
	CommonPlaintext []string           `yaml:"common_plaintext"`
	CommonEncrypted []string           `yaml:"common_encrypted"`
	ByFilename      []FilenamePassword `yaml:"by_filename"`
}

type FilenamePassword struct {
	Filename          string `yaml:"filename"`
	Filepath          string `yaml:"filepath"`
	PlaintextPassword string `yaml:"plaintext_password"`
	EncryptedPassword string `yaml:"encrypted_password"`
}

func LoadConfig(configPath string) (*ConfigFile, error) {
	path, explicit, legacy, err := resolvePath(configPath)
	if err != nil || path == "" {
		return nil, nil
	}
	if legacy {
		noteLegacyConfig(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// A missing default file means defaults; nothing is written.
		if os.IsNotExist(err) && !explicit {
			return nil, nil
		}
		return nil, err
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Kind != "certdiag-config" {
		return nil, ErrInvalidKind
	}
	if cfg.Version != "1" {
		return nil, ErrInvalidVersion
	}

	cfg.ValidateDefaults()

	return &cfg, nil
}

func (c *ConfigFile) MatchByFilename(filePath string) []FilenamePassword {
	if c == nil {
		return nil
	}

	basename := filepath.Base(filePath)
	var matches []FilenamePassword

	for _, entry := range c.Passwords.ByFilename {
		if entry.Filename != "" {
			matched, err := filepath.Match(entry.Filename, basename)
			if err == nil && matched {
				matches = append(matches, entry)
			}
		}
		if entry.Filepath != "" && entry.Filepath == filePath {
			matches = append(matches, entry)
		}
	}

	return matches
}

func (c *ConfigFile) HasEncryptedPasswords() bool {
	if c == nil {
		return false
	}

	if len(c.Passwords.CommonEncrypted) > 0 {
		return true
	}

	for _, entry := range c.Passwords.ByFilename {
		if entry.EncryptedPassword != "" {
			return true
		}
	}

	return false
}

var (
	validAlgorithms    = map[string]bool{"rsa": true, "ecdsa": true, "ed25519": true}
	validRSAKeySizes   = map[int]bool{2048: true, 3072: true, 4096: true}
	validECDSACurves   = map[string]bool{"p256": true, "p384": true, "p521": true}
	validOutputFormats = map[string]bool{"pem": true, "der": true}
	validPKCS12Algos   = map[string]bool{"modern": true, "legacy": true}

	validPathDisplayModes = map[string]bool{"filename": true, "relative": true, "absolute": true}

	validFingerprintFormats = func() map[string]bool {
		m := make(map[string]bool, len(certlib.FingerprintFormats))
		for _, f := range certlib.FingerprintFormats {
			m[string(f)] = true
		}
		return m
	}()

	validTUIColumns = withFingerprintColumns(map[string]bool{
		"subject": true, "issuer": true, "expiry": true, "algo": true,
		"valid_from": true, "sans": true, "usage": true, "relations": true,
		"warnings": true,
	})
	// Trust store view offers the shared columns plus two store-only ones.
	validStoreColumns = withFingerprintColumns(map[string]bool{
		"subject": true, "issuer": true, "expiry": true, "algo": true,
		"valid_from": true, "sans": true, "usage": true, "relations": true,
		"warnings": true, "trust": true, "stores": true,
	})
	validStoreGrouping = map[string]bool{"instance": true, "kind": true}

	defaultTUIColumns   = []string{"subject", "issuer", "expiry", "algo"}
	defaultStoreColumns = []string{"subject", "expiry", "algo", "stores"}
)

func (c *ConfigFile) ValidateDefaults() {
	d := &c.Defaults

	if d.Key.Algorithm != "" {
		if !validAlgorithms[strings.ToLower(d.Key.Algorithm)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.key.algorithm %q, ignoring\n", d.Key.Algorithm)
			d.Key.Algorithm = ""
		} else {
			d.Key.Algorithm = strings.ToLower(d.Key.Algorithm)
		}
	}

	if d.Key.RSAKeySize != 0 && !validRSAKeySizes[d.Key.RSAKeySize] {
		fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.key.rsa_key_size %d, ignoring\n", d.Key.RSAKeySize)
		d.Key.RSAKeySize = 0
	}

	if d.Key.ECDSACurve != "" {
		if !validECDSACurves[strings.ToLower(d.Key.ECDSACurve)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.key.ecdsa_curve %q, ignoring\n", d.Key.ECDSACurve)
			d.Key.ECDSACurve = ""
		} else {
			d.Key.ECDSACurve = strings.ToLower(d.Key.ECDSACurve)
		}
	}

	if d.Cert.Days < 0 {
		fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.cert.days %d, ignoring\n", d.Cert.Days)
		d.Cert.Days = 0
	}

	if d.Cert.CADays < 0 {
		fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.cert.ca_days %d, ignoring\n", d.Cert.CADays)
		d.Cert.CADays = 0
	}

	if d.Output.FingerprintFormat != "" {
		if !validFingerprintFormats[strings.ToLower(d.Output.FingerprintFormat)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.output.fingerprint_format %q, ignoring\n", d.Output.FingerprintFormat)
			d.Output.FingerprintFormat = ""
		} else {
			d.Output.FingerprintFormat = strings.ToLower(d.Output.FingerprintFormat)
		}
	}

	if d.Output.Format != "" {
		if !validOutputFormats[strings.ToLower(d.Output.Format)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.output.format %q, ignoring\n", d.Output.Format)
			d.Output.Format = ""
		} else {
			d.Output.Format = strings.ToLower(d.Output.Format)
		}
	}

	if d.Keystore.PKCS12Algorithm != "" {
		if !validPKCS12Algos[strings.ToLower(d.Keystore.PKCS12Algorithm)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.keystore.pkcs12_algorithm %q, ignoring\n", d.Keystore.PKCS12Algorithm)
			d.Keystore.PKCS12Algorithm = ""
		} else {
			d.Keystore.PKCS12Algorithm = strings.ToLower(d.Keystore.PKCS12Algorithm)
		}
	}

	if d.TUI.PathDisplay != "" {
		if !validPathDisplayModes[strings.ToLower(d.TUI.PathDisplay)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.tui.path_display %q, ignoring\n", d.TUI.PathDisplay)
			d.TUI.PathDisplay = ""
		} else {
			d.TUI.PathDisplay = strings.ToLower(d.TUI.PathDisplay)
		}
	}

	if d.TUI.MaxDepth < 0 {
		fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.tui.max_depth %d, ignoring\n", d.TUI.MaxDepth)
		d.TUI.MaxDepth = 0
	}

	var filteredCols []string
	for _, col := range d.TUI.Columns {
		if !validTUIColumns[strings.ToLower(col)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: unknown tui column %q, ignoring\n", col)
		} else {
			filteredCols = append(filteredCols, strings.ToLower(col))
		}
	}
	d.TUI.Columns = filteredCols

	var filteredStoreCols []string
	for _, col := range d.TUI.TrustStoreColumns {
		if !validStoreColumns[strings.ToLower(col)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: unknown tui trust_store column %q, ignoring\n", col)
		} else {
			filteredStoreCols = append(filteredStoreCols, strings.ToLower(col))
		}
	}
	d.TUI.TrustStoreColumns = filteredStoreCols

	if d.TUI.TrustStoreGrouping != "" {
		if !validStoreGrouping[strings.ToLower(d.TUI.TrustStoreGrouping)] {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.tui.trust_store_grouping %q, using instance\n", d.TUI.TrustStoreGrouping)
			d.TUI.TrustStoreGrouping = "instance"
		} else {
			d.TUI.TrustStoreGrouping = strings.ToLower(d.TUI.TrustStoreGrouping)
		}
	}
}

func (c *ConfigFile) GetKeyDefaults() certlib.KeyGenOptions {
	opts := certlib.KeyGenOptions{
		Algorithm: "ecdsa",
		KeySize:   2048,
		Curve:     "p256",
	}
	if c == nil {
		return opts
	}
	if c.Defaults.Key.Algorithm != "" {
		opts.Algorithm = c.Defaults.Key.Algorithm
	}
	if c.Defaults.Key.RSAKeySize != 0 {
		opts.KeySize = c.Defaults.Key.RSAKeySize
	}
	if c.Defaults.Key.ECDSACurve != "" {
		opts.Curve = c.Defaults.Key.ECDSACurve
	}
	return opts
}

func (c *ConfigFile) GetSubjectDefaults() pkix.Name {
	if c == nil {
		return pkix.Name{}
	}
	var name pkix.Name
	d := c.Defaults.Subject
	if d.Organization != nil && *d.Organization != "" {
		name.Organization = []string{*d.Organization}
	}
	if d.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{d.OrganizationalUnit}
	}
	if d.Country != "" {
		name.Country = []string{d.Country}
	}
	if d.State != "" {
		name.Province = []string{d.State}
	}
	if d.Locality != "" {
		name.Locality = []string{d.Locality}
	}
	return name
}

type CertDefaultsResult struct {
	Days        int
	CADays      int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
}

func (c *ConfigFile) GetCertDefaults() CertDefaultsResult {
	result := CertDefaultsResult{
		Days:   365,
		CADays: 3650,
	}
	if c == nil {
		return result
	}
	if c.Defaults.Cert.Days > 0 {
		result.Days = c.Defaults.Cert.Days
	}
	if c.Defaults.Cert.CADays > 0 {
		result.CADays = c.Defaults.Cert.CADays
	}
	if len(c.Defaults.Cert.KeyUsage) > 0 {
		ku, err := certlib.ParseKeyUsageList(c.Defaults.Cert.KeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.cert.key_usage: %v\n", err)
		} else {
			result.KeyUsage = ku
		}
	}
	if len(c.Defaults.Cert.ExtKeyUsage) > 0 {
		eku, err := certlib.ParseExtKeyUsageList(c.Defaults.Cert.ExtKeyUsage)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certdiag: config warning: invalid defaults.cert.ext_key_usage: %v\n", err)
		} else {
			result.ExtKeyUsage = eku
		}
	}
	return result
}

type TUIScanDefaults struct {
	Recursive         bool
	MaxDepth          int
	FileSignatureScan bool
	AutoDiscover      bool
	PathDisplay       string
}

func GetTUIScanDefaults(cfg *ConfigFile) TUIScanDefaults {
	var d TUIScanDefaults
	if cfg == nil {
		return d
	}
	t := cfg.Defaults.TUI
	if t.Recursive != nil {
		d.Recursive = *t.Recursive
	}
	d.MaxDepth = t.MaxDepth
	if t.FileSignatureScan != nil {
		d.FileSignatureScan = *t.FileSignatureScan
	}
	if t.AutoDiscover != nil {
		d.AutoDiscover = *t.AutoDiscover
	}
	d.PathDisplay = t.PathDisplay
	if d.PathDisplay == "" {
		d.PathDisplay = "filename"
	}
	return d
}

// withFingerprintColumns adds the per-algorithm fingerprint column ids, kept in
// sync with certlib.FingerprintAlgos rather than written out by hand.
func withFingerprintColumns(m map[string]bool) map[string]bool {
	for _, a := range certlib.FingerprintAlgos {
		m["fp_"+string(a)] = true
	}
	return m
}

// FingerprintFormat resolves the configured display format, defaulting to hex.
func FingerprintFormat(cfg *ConfigFile) certlib.FingerprintFormat {
	if cfg == nil {
		return certlib.FingerprintHex
	}
	return certlib.ParseFingerprintFormat(cfg.Defaults.Output.FingerprintFormat)
}

func ActiveColumns(cfg *ConfigFile) []string {
	if cfg == nil || len(cfg.Defaults.TUI.Columns) == 0 {
		return defaultTUIColumns
	}
	return cfg.Defaults.TUI.Columns
}

func ActiveStoreColumns(cfg *ConfigFile) []string {
	if cfg == nil || len(cfg.Defaults.TUI.TrustStoreColumns) == 0 {
		return defaultStoreColumns
	}
	return cfg.Defaults.TUI.TrustStoreColumns
}

func StoreGrouping(cfg *ConfigFile) string {
	if cfg == nil || cfg.Defaults.TUI.TrustStoreGrouping == "" {
		return "instance"
	}
	return cfg.Defaults.TUI.TrustStoreGrouping
}
