package opensslcmd

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

const (
	noteEncryptKDF   = "certdiag encrypts with PBKDF2-HMAC-SHA256 (600000 iterations), AES-256-CBC; openssl's default KDF iteration count differs"
	noteRandomSerial = "certdiag uses a random 128-bit serial; add -set_serial to pin an exact value"
	noteBackdate     = "certdiag backdates notBefore by 1h for clock-skew tolerance; openssl uses the current time"
	noteSKID         = "certdiag always adds a subjectKeyIdentifier; add -addext subjectKeyIdentifier=hash to reproduce it"
	notePKCS8Key     = "certdiag writes private keys as PKCS#8 (BEGIN PRIVATE KEY); genpkey matches, genrsa/ec would emit PKCS#1/SEC1"
	noteNotBefore    = "-not_before requires OpenSSL 3.4 or newer; older openssl uses the current time and cannot set an explicit notBefore"
)

// KeyGen returns the openssl genpkey command equivalent to certdiag's key
// generation. outPath == "" means output to stdout.
func KeyGen(opts certlib.KeyGenOptions, outPath string, format certlib.FileFormat, encrypt bool) Command {
	c := Command{Tool: ToolOpenSSL, Args: []string{"genpkey"}}

	switch strings.ToLower(opts.Algorithm) {
	case "rsa":
		c.Args = append(c.Args, "-algorithm", "RSA", "-pkeyopt", fmt.Sprintf("rsa_keygen_bits:%d", opts.KeySize))
	case "ecdsa":
		curve, ok := opensslCurve(opts.Curve)
		if !ok {
			c.Notes = append(c.Notes, fmt.Sprintf("unknown ECDSA curve %q", opts.Curve))
		}
		c.Args = append(c.Args, "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:"+curve)
	case "ed25519":
		c.Args = append(c.Args, "-algorithm", "ED25519")
	default:
		c.Notes = append(c.Notes, fmt.Sprintf("unknown algorithm %q", opts.Algorithm))
	}

	// certdiag never emits an encrypted DER key: create-key rejects the
	// combination and create-cert/create-csr write the DER key unencrypted. Match
	// that instead of emitting genpkey -aes-256-cbc -outform DER.
	if encrypt && format != certlib.FormatDER {
		c.Args = append(c.Args, "-aes-256-cbc")
		c.Notes = append(c.Notes, noteEncryptKDF, "add -pass pass:YOURPASS to avoid the interactive passphrase prompt")
	} else if encrypt && format == certlib.FormatDER {
		c.Notes = append(c.Notes, "DER output cannot carry an encrypted key; certdiag writes the DER key unencrypted (create-key rejects this combination)")
	}
	if format == certlib.FormatDER {
		c.Args = append(c.Args, "-outform", "DER")
	}
	if outPath != "" {
		c.Args = append(c.Args, "-out", outPath)
	}
	c.Notes = append(c.Notes, notePKCS8Key)
	return c
}

// CSR returns the openssl req -new command for a certificate signing request
// built from an existing key at keyPath.
func CSR(subject pkix.Name, sans certlib.SANList, keyPath, outPath string, format certlib.FileFormat) Command {
	c := Command{Tool: ToolOpenSSL, Args: []string{"req", "-new"}}
	if keyPath != "" {
		c.Args = append(c.Args, "-key", keyPath)
	}
	subj, notes := opensslSubject(subject)
	c.Args = append(c.Args, "-subj", subj)
	c.Notes = append(c.Notes, notes...)
	if ext := sanExtension(sans); ext != "" {
		c.Args = append(c.Args, "-addext", ext)
	}
	if format == certlib.FormatDER {
		c.Args = append(c.Args, "-outform", "DER")
	}
	if outPath != "" {
		c.Args = append(c.Args, "-out", outPath)
	}
	return c
}

// CertSpec captures the resolved parameters of a certificate creation. The
// caller resolves KeyUsage/ExtKeyUsage defaults (as certops does) before
// building this.
type CertSpec struct {
	Subject     pkix.Name
	SANs        certlib.SANList
	Days        int
	NotBefore   time.Time
	IsCA        bool
	PathLength  int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	Serial      *big.Int
	KeyPath     string
	OutputPath  string
	Format      certlib.FileFormat
}

// SelfSignedCert returns the openssl req -x509 command for a self-signed
// certificate created from the key at spec.KeyPath.
func SelfSignedCert(spec CertSpec) Command {
	c := Command{Tool: ToolOpenSSL, Args: []string{"req", "-x509"}}
	if spec.KeyPath != "" {
		c.Args = append(c.Args, "-key", spec.KeyPath)
	}
	subj, notes := opensslSubject(spec.Subject)
	c.Args = append(c.Args, "-subj", subj)
	c.Notes = append(c.Notes, notes...)

	c.Args = append(c.Args, "-days", strconv.Itoa(effectiveDays(spec.Days)))
	c.Args = appendExtensions(c.Args, spec)

	if spec.Serial != nil {
		c.Args = append(c.Args, "-set_serial", "0x"+spec.Serial.Text(16))
	} else {
		c.Notes = append(c.Notes, noteRandomSerial)
	}
	if !spec.NotBefore.IsZero() {
		c.Args = append(c.Args, "-not_before", spec.NotBefore.UTC().Format("20060102150405Z"))
		c.Notes = append(c.Notes, noteNotBefore)
	} else {
		c.Notes = append(c.Notes, noteBackdate)
	}
	if spec.Format == certlib.FormatDER {
		c.Args = append(c.Args, "-outform", "DER")
	}
	if spec.OutputPath != "" {
		c.Args = append(c.Args, "-out", spec.OutputPath)
	}
	c.Notes = append(c.Notes, noteSKID)
	return c
}

// SignExtSpec carries the extensions certdiag applies to a signed certificate.
// openssl x509 -req has no -addext, so these are reproduced with -extfile.
type SignExtSpec struct {
	IsCA        bool
	PathLength  int
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	NotBefore   time.Time
}

// SignCSR returns the openssl x509 -req command that signs an existing CSR with
// a CA cert and key. When serial is nil, -CAcreateserial is used. When exts is
// non-nil, certdiag's basicConstraints/keyUsage/EKU are emitted via -extfile
// (x509 -req cannot take -addext), so a CA certificate stays a CA.
func SignCSR(csrPath, caCertPath, caKeyPath, outPath string, days int, serial *big.Int, format certlib.FileFormat, exts *SignExtSpec) Command {
	c := Command{Tool: ToolOpenSSL, Args: []string{
		"x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath,
	}}
	if serial != nil {
		c.Args = append(c.Args, "-set_serial", "0x"+serial.Text(16))
	} else {
		c.Args = append(c.Args, "-CAcreateserial")
		c.Notes = append(c.Notes, noteRandomSerial)
	}
	c.Args = append(c.Args, "-days", strconv.Itoa(effectiveDays(days)))
	c.Args = append(c.Args, "-copy_extensions", "copy")

	if exts != nil {
		const section = "v3_certdiag"
		c.Args = append(c.Args, "-extfile", "ext.cnf", "-extensions", section)
		lines := []string{basicConstraintsExtension(exts.IsCA, exts.PathLength)}
		if e := keyUsageExtension(exts.KeyUsage); e != "" {
			lines = append(lines, e)
		}
		if e := extKeyUsageExtension(exts.ExtKeyUsage); e != "" {
			lines = append(lines, e)
		}
		c.Notes = append(c.Notes,
			"certdiag copies the CSR subject and SANs (-copy_extensions copy)",
			fmt.Sprintf("create ext.cnf with a [%s] section containing: %s", section, strings.Join(lines, " / ")))
	} else {
		c.Notes = append(c.Notes,
			"certdiag copies the CSR subject and SANs verbatim; -copy_extensions copy approximates this")
	}

	// certdiag backdates notBefore for clock skew unless an explicit one is set.
	if exts != nil && !exts.NotBefore.IsZero() {
		c.Notes = append(c.Notes, "certdiag sets an explicit notBefore; openssl x509 -req uses the current time")
	} else {
		c.Notes = append(c.Notes, noteBackdate)
	}

	if format == certlib.FormatDER {
		c.Args = append(c.Args, "-outform", "DER")
	}
	if outPath != "" {
		c.Args = append(c.Args, "-out", outPath)
	}
	return c
}

func appendExtensions(args []string, spec CertSpec) []string {
	exts := []string{basicConstraintsExtension(spec.IsCA, spec.PathLength)}
	if ext := keyUsageExtension(spec.KeyUsage); ext != "" {
		exts = append(exts, ext)
	}
	if ext := extKeyUsageExtension(spec.ExtKeyUsage); ext != "" {
		exts = append(exts, ext)
	}
	if ext := sanExtension(spec.SANs); ext != "" {
		exts = append(exts, ext)
	}
	for _, e := range exts {
		args = append(args, "-addext", e)
	}
	return args
}

func effectiveDays(days int) int {
	if days <= 0 {
		return 365
	}
	return days
}
