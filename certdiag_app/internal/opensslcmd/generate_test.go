package opensslcmd

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func TestKeyGen(t *testing.T) {
	tests := []struct {
		name    string
		opts    certlib.KeyGenOptions
		out     string
		format  certlib.FileFormat
		encrypt bool
		want    string
	}{
		{
			name: "rsa",
			opts: certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 4096},
			out:  "key.pem",
			want: "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out key.pem",
		},
		{
			name: "ecdsa p384",
			opts: certlib.KeyGenOptions{Algorithm: "ecdsa", Curve: "p384"},
			out:  "key.pem",
			want: "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out key.pem",
		},
		{
			name: "ed25519 stdout",
			opts: certlib.KeyGenOptions{Algorithm: "ed25519"},
			want: "openssl genpkey -algorithm ED25519",
		},
		{
			name:   "rsa der",
			opts:   certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048},
			out:    "key.der",
			format: certlib.FormatDER,
			want:   "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER -out key.der",
		},
		{
			name:    "rsa encrypted",
			opts:    certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048},
			out:     "key.pem",
			encrypt: true,
			want:    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -out key.pem",
		},
		{
			// M9: DER never carries an encrypted key in certdiag, so no
			// -aes-256-cbc even when encrypt is requested.
			name:    "der encrypted omits cipher",
			opts:    certlib.KeyGenOptions{Algorithm: "rsa", KeySize: 2048},
			out:     "key.der",
			format:  certlib.FormatDER,
			encrypt: true,
			want:    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER -out key.der",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyGen(tt.opts, tt.out, tt.format, tt.encrypt).String()
			if got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestCSRSubjectOrderAndSANs(t *testing.T) {
	name, _ := certlib.ParseDN("CN=example.com,O=My Org,C=US")
	sans, _ := certlib.ParseSANString("DNS:example.com,IP:127.0.0.1,email:a@b.com")

	got := CSR(name, sans, "key.pem", "req.csr", certlib.FormatPEM).String()
	// Go's ToRDNSequence order: C, O, ..., CN. Space in "My Org" forces quoting.
	want := "openssl req -new -key key.pem -subj '/C=US/O=My Org/CN=example.com' " +
		"-addext subjectAltName=DNS:example.com,IP:127.0.0.1,email:a@b.com -out req.csr"
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

// TestCSRSubjectRDNOrder is the M7 regression: the -subj RDN order must match
// pkix.Name.ToRDNSequence (C, ST, L, O, OU, CN), not the old C, O, OU, L, ST.
func TestCSRSubjectRDNOrder(t *testing.T) {
	name, _ := certlib.ParseDN("CN=host,O=Org,OU=Unit,L=City,ST=State,C=US")
	got := CSR(name, certlib.SANList{}, "key.pem", "req.csr", certlib.FormatPEM).String()
	want := "openssl req -new -key key.pem -subj /C=US/ST=State/L=City/O=Org/OU=Unit/CN=host -out req.csr"
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

func TestSelfSignedCertExtensions(t *testing.T) {
	name, _ := certlib.ParseDN("CN=leaf.local")
	sans, _ := certlib.ParseSANString("DNS:leaf.local")
	spec := CertSpec{
		Subject:     name,
		SANs:        sans,
		Days:        365,
		IsCA:        false,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		Serial:      big.NewInt(0x1234),
		KeyPath:     "key.pem",
		OutputPath:  "cert.pem",
	}
	got := SelfSignedCert(spec).String()
	want := "openssl req -x509 -key key.pem -subj /CN=leaf.local -days 365 " +
		"-addext basicConstraints=critical,CA:FALSE " +
		"-addext keyUsage=critical,digitalSignature,keyEncipherment " +
		"-addext extendedKeyUsage=serverAuth,clientAuth " +
		"-addext subjectAltName=DNS:leaf.local " +
		"-set_serial 0x1234 -out cert.pem"
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

func TestSelfSignedCertCA(t *testing.T) {
	name, _ := certlib.ParseDN("CN=My CA")
	spec := CertSpec{
		Subject:    name,
		Days:       3650,
		IsCA:       true,
		PathLength: 0,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		KeyPath:    "ca.key",
		OutputPath: "ca.crt",
	}
	got := SelfSignedCert(spec).String()
	if !strings.Contains(got, "-addext basicConstraints=critical,CA:TRUE,pathlen:0") {
		t.Errorf("missing CA basicConstraints with pathlen: %s", got)
	}
	if !strings.Contains(got, "-subj '/CN=My CA'") {
		t.Errorf("expected quoted subject with space: %s", got)
	}
}

// TestSelfSignedCertNotBefore is the M8 regression: emitting -not_before must
// carry a note that it needs OpenSSL 3.4+.
func TestSelfSignedCertNotBefore(t *testing.T) {
	name, _ := certlib.ParseDN("CN=x")
	cmd := SelfSignedCert(CertSpec{Subject: name, Days: 30, NotBefore: time.Unix(1700000000, 0), KeyPath: "k.pem", OutputPath: "c.pem"})
	if !strings.Contains(cmd.String(), "-not_before ") {
		t.Fatalf("expected -not_before in args: %s", cmd.String())
	}
	joined := strings.Join(cmd.Notes, "\n")
	if !strings.Contains(joined, "OpenSSL 3.4") {
		t.Errorf("expected an OpenSSL 3.4 version note:\n%s", joined)
	}
}

func TestSignCSR(t *testing.T) {
	got := SignCSR("req.csr", "ca.crt", "ca.key", "out.crt", 730, nil, certlib.FormatPEM, nil).String()
	want := "openssl x509 -req -in req.csr -CA ca.crt -CAkey ca.key -CAcreateserial " +
		"-days 730 -copy_extensions copy -out out.crt"
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}

	withSerial := SignCSR("req.csr", "ca.crt", "ca.key", "", 365, big.NewInt(255), certlib.FormatPEM, nil).String()
	if !strings.Contains(withSerial, "-set_serial 0xff") {
		t.Errorf("expected -set_serial 0xff: %s", withSerial)
	}
	if strings.Contains(withSerial, "-CAcreateserial") {
		t.Errorf("should not use -CAcreateserial when a serial is given: %s", withSerial)
	}

	// LOW: the nil-serial path notes the random-serial and backdate divergences.
	nilSerial := SignCSR("req.csr", "ca.crt", "ca.key", "out.crt", 365, nil, certlib.FormatPEM, nil)
	notes := strings.Join(nilSerial.Notes, "\n")
	if !strings.Contains(notes, "random") {
		t.Errorf("nil-serial sign should note the random serial divergence:\n%s", notes)
	}
	if !strings.Contains(notes, "backdate") {
		t.Errorf("sign should note notBefore backdating:\n%s", notes)
	}
}

// TestSignCSRWithCAExtensions is the HIGH-6 regression: signing a CSR as a CA
// must emit certdiag's basicConstraints (CA:TRUE) and keyUsage via -extfile,
// so the openssl artifact is actually a CA. x509 -req has no -addext.
func TestSignCSRWithCAExtensions(t *testing.T) {
	cmd := SignCSR("req.csr", "ca.crt", "ca.key", "out.crt", 365, nil, certlib.FormatPEM, &SignExtSpec{
		IsCA:       true,
		PathLength: 0,
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	s := cmd.String()
	if !strings.Contains(s, "-extfile ext.cnf -extensions v3_certdiag") {
		t.Errorf("expected -extfile recipe for CA extensions: %s", s)
	}
	joined := strings.Join(cmd.Notes, "\n")
	if !strings.Contains(joined, "basicConstraints=critical,CA:TRUE,pathlen:0") {
		t.Errorf("notes must spell out CA basicConstraints:\n%s", joined)
	}
	if !strings.Contains(joined, "keyUsage=critical,keyCertSign,cRLSign") {
		t.Errorf("notes must spell out the CA keyUsage:\n%s", joined)
	}
}

func TestConvert(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		inFmt   certlib.FileFormat
		out     string
		outFmt  certlib.FileFormat
		include string
		legacy  bool
		want    string
	}{
		{
			name: "pem cert to der", in: "cert.pem", inFmt: certlib.FormatPEM,
			out: "cert.der", outFmt: certlib.FormatDER, include: "all",
			want: "openssl x509 -in cert.pem -outform DER -out cert.der",
		},
		{
			name: "der to pem", in: "cert.der", inFmt: certlib.FormatDER,
			out: "cert.pem", outFmt: certlib.FormatPEM, include: "all",
			want: "openssl x509 -in cert.der -inform DER -out cert.pem",
		},
		{
			name: "pem to pkcs7", in: "certs.pem", inFmt: certlib.FormatPEM,
			out: "certs.p7b", outFmt: certlib.FormatPKCS7, include: "all",
			want: "openssl crl2pkcs7 -nocrl -certfile certs.pem -out certs.p7b",
		},
		{
			name: "pkcs7 to pem", in: "certs.p7b", inFmt: certlib.FormatPKCS7,
			out: "certs.pem", outFmt: certlib.FormatPEM, include: "all",
			want: "openssl pkcs7 -in certs.p7b -print_certs -out certs.pem",
		},
		{
			name: "pem to pkcs12", in: "bundle.pem", inFmt: certlib.FormatPEM,
			out: "out.p12", outFmt: certlib.FormatPKCS12, include: "all",
			want: "openssl pkcs12 -export -in bundle.pem -out out.p12 -passout pass:OUTPUT_PASSWORD",
		},
		{
			name: "pem to pkcs12 legacy", in: "bundle.pem", inFmt: certlib.FormatPEM,
			out: "out.p12", outFmt: certlib.FormatPKCS12, include: "all", legacy: true,
			want: "openssl pkcs12 -export -in bundle.pem -out out.p12 -passout pass:OUTPUT_PASSWORD -legacy -descert",
		},
		{
			name: "pem to jks uses keytool", in: "cert.pem", inFmt: certlib.FormatPEM,
			out: "store.jks", outFmt: certlib.FormatJKS, include: "all",
			want: "keytool -importkeystore -srckeystore cert.pem -srcstoretype PKCS12 -destkeystore store.jks -deststoretype JKS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := Convert(tt.in, tt.inFmt, tt.out, tt.outFmt, tt.include, tt.legacy)
			if len(cmds) == 0 {
				t.Fatal("no commands generated")
			}
			if got := cmds[0].String(); got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

// TestConvertJKSToNonKeystore is the HIGH-5 regression: JKS -> PEM/DER/PKCS7 must
// not emit "-deststoretype JKS" (which would write a JKS keystore under the
// requested filename). Those go through a PKCS#12 intermediate, then openssl.
func TestConvertJKSToNonKeystore(t *testing.T) {
	t.Run("jks to pem", func(t *testing.T) {
		cmds := Convert("store.jks", certlib.FormatJKS, "out.pem", certlib.FormatPEM, "all", false)
		if len(cmds) < 2 {
			t.Fatalf("expected a multi-step recipe, got %d command(s)", len(cmds))
		}
		joined := renderAll(cmds)
		if strings.Contains(joined, "-deststoretype JKS") {
			t.Errorf("JKS->PEM must not write a JKS keystore:\n%s", joined)
		}
		if strings.Contains(joined, "-destkeystore out.pem") {
			t.Errorf("openssl output must land in out.pem, not keytool:\n%s", joined)
		}
		last := cmds[len(cmds)-1]
		if last.Tool != ToolOpenSSL || !strings.Contains(last.String(), "out.pem") {
			t.Errorf("final step should be openssl writing out.pem, got: %s", last.String())
		}
	})

	t.Run("jks to der", func(t *testing.T) {
		cmds := Convert("store.jks", certlib.FormatJKS, "out.der", certlib.FormatDER, "all", false)
		joined := renderAll(cmds)
		if strings.Contains(joined, "-deststoretype JKS") {
			t.Errorf("JKS->DER must not write a JKS keystore:\n%s", joined)
		}
		last := cmds[len(cmds)-1]
		if !strings.Contains(last.String(), "-outform DER -out out.der") {
			t.Errorf("final step should produce DER, got: %s", last.String())
		}
	})
}

// TestConvertNonPEMInput is the M5 regression: DER/PKCS12/PKCS7 outputs from a
// non-PEM input must not emit an openssl command that reads the wrong container
// type; they go through a PEM intermediate.
func TestConvertNonPEMInput(t *testing.T) {
	cases := []struct {
		name           string
		in             string
		inFmt          certlib.FileFormat
		out            string
		outFmt         certlib.FileFormat
		wantFinalHas   string
		badFirstArgHas string // the naive single-command form we must NOT emit
	}{
		{"der to pkcs12", "cert.der", certlib.FormatDER, "out.p12", certlib.FormatPKCS12,
			"pkcs12 -export -in intermediate.pem", "-export -in cert.der"},
		{"pkcs12 to pkcs7", "bundle.p12", certlib.FormatPKCS12, "out.p7b", certlib.FormatPKCS7,
			"crl2pkcs7 -nocrl -certfile intermediate.pem", "-certfile bundle.p12"},
		{"pkcs7 to der", "bundle.p7b", certlib.FormatPKCS7, "out.der", certlib.FormatDER,
			"x509 -in intermediate.pem -outform DER", "x509 -in bundle.p7b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := Convert(tc.in, tc.inFmt, tc.out, tc.outFmt, "all", false)
			if len(cmds) < 2 {
				t.Fatalf("expected a PEM-intermediate recipe, got %d command(s): %s", len(cmds), renderAll(cmds))
			}
			joined := renderAll(cmds)
			if strings.Contains(joined, tc.badFirstArgHas) {
				t.Errorf("emitted a command that reads the wrong container type:\n%s", joined)
			}
			if !strings.Contains(cmds[len(cmds)-1].String(), tc.wantFinalHas) {
				t.Errorf("final command = %q, want it to contain %q", cmds[len(cmds)-1].String(), tc.wantFinalHas)
			}
		})
	}
}

func renderAll(cmds []Command) string {
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString(c.String())
		b.WriteString("\n")
	}
	return b.String()
}

// TestConvertIncludeKeys is the LOW regression: --include keys must extract the
// private key (openssl pkey), not emit a cert-extraction command.
func TestConvertIncludeKeys(t *testing.T) {
	cmds := Convert("bundle.pem", certlib.FormatPEM, "keys.pem", certlib.FormatPEM, "keys", false)
	got := renderAll(cmds)
	if !strings.Contains(got, "openssl pkey -in bundle.pem -out keys.pem") {
		t.Errorf("--include keys should use openssl pkey, got:\n%s", got)
	}
	if strings.Contains(got, "x509") {
		t.Errorf("--include keys must not emit a cert-extraction command:\n%s", got)
	}
}

// TestNoEquivalentRendersAsComment is the LOW regression: an unsupported
// conversion must render as a comment, never a bare runnable "openssl" line.
func TestNoEquivalentRendersAsComment(t *testing.T) {
	cmds := Convert("in.pem", certlib.FormatPEM, "out.unknown", certlib.FileFormat("unknown"), "all", false)
	rendered := Render(cmds...)
	for _, line := range strings.Split(rendered, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "openssl" {
			t.Errorf("rendered a bare runnable 'openssl' line:\n%s", rendered)
		}
	}
	if !strings.Contains(rendered, "# note:") {
		t.Errorf("expected a note comment for an unsupported conversion:\n%s", rendered)
	}
}

func TestInspect(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		ct     certlib.ContentType
		format certlib.FileFormat
		want   string
	}{
		{"cert pem", "cert.pem", certlib.ContentCertificate, certlib.FormatPEM, "openssl x509 -in cert.pem -text -noout"},
		{"cert der", "cert.der", certlib.ContentCertificate, certlib.FormatDER, "openssl x509 -in cert.der -text -noout -inform DER"},
		{"key", "key.pem", certlib.ContentPrivateKey, certlib.FormatPEM, "openssl pkey -in key.pem -text -noout"},
		{"csr", "req.csr", certlib.ContentCSR, certlib.FormatPEM, "openssl req -in req.csr -text -noout"},
		{"pkcs12", "store.p12", certlib.ContentCertificate, certlib.FormatPKCS12, "openssl pkcs12 -in store.p12 -info -nodes"},
		{"pkcs7", "certs.p7b", certlib.ContentCertificate, certlib.FormatPKCS7, "openssl pkcs7 -in certs.p7b -print_certs -text -noout"},
		{"jks", "store.jks", certlib.ContentCertificate, certlib.FormatJKS, "keytool -list -v -keystore store.jks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Inspect(tt.path, tt.ct, tt.format).String(); got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestRemoteFetch(t *testing.T) {
	tests := []struct {
		name string
		spec RemoteSpec
		want string
	}{
		{
			name: "default sni",
			spec: RemoteSpec{Host: "example.com", Port: 443, ShowCerts: true},
			want: "openssl s_client -connect example.com:443 -servername example.com -showcerts",
		},
		{
			name: "explicit sni and starttls",
			spec: RemoteSpec{Host: "mail.example.com", Port: 587, SNI: "sni.example.com", Starttls: "smtp"},
			want: "openssl s_client -connect mail.example.com:587 -servername sni.example.com -starttls smtp",
		},
		{
			name: "no sni",
			spec: RemoteSpec{Host: "1.2.3.4", Port: 8443, DisableSNI: true},
			want: "openssl s_client -connect 1.2.3.4:8443 -noservername",
		},
		{
			// LOW: an IPv6 literal must be bracketed in -connect.
			name: "ipv6 literal bracketed",
			spec: RemoteSpec{Host: "::1", Port: 443, DisableSNI: true},
			want: "openssl s_client -connect '[::1]:443' -noservername",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RemoteFetch(tt.spec).String(); got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestRenderNotesDeduped(t *testing.T) {
	a := Command{Tool: ToolOpenSSL, Args: []string{"genpkey"}, Notes: []string{"shared", "one"}}
	b := Command{Tool: ToolOpenSSL, Args: []string{"req"}, Notes: []string{"shared", "two"}}
	out := Render(a, b)
	if strings.Count(out, "# note: shared") != 1 {
		t.Errorf("shared note should appear once:\n%s", out)
	}
	for _, want := range []string{"openssl genpkey", "openssl req", "# note: one", "# note: two"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
