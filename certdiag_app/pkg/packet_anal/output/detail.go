package output

import (
	"crypto/x509"
	"fmt"
	"io"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tls"
)

func PrintDetail(w io.Writer, s *session.Session, index int) {
	fmt.Fprintf(w, "Session #%d: %s -> %s\n", index, s.ClientAddr, s.ServerAddr)

	if !s.StartTime.IsZero() {
		fmt.Fprintf(w, "  Timestamp:  %s\n", s.StartTime.Format("2006-01-02 15:04:05.000000"))
	}
	fmt.Fprintf(w, "  Status:     %s\n", s.Status)
	if s.Diagnostic != "" {
		fmt.Fprintf(w, "  Diagnostic: %s\n", s.Diagnostic)
	}
	fmt.Fprintln(w)

	printPreamble(w, s)
	printClientHello(w, s)
	printServerHello(w, s)
	printCertificates(w, s)
	printAppData(w, s)
	printFlags(w, s)
}

func printAppData(w io.Writer, s *session.Session) {
	if !s.AppDataDecrypted {
		return
	}
	fmt.Fprintln(w, "  Decrypted application data:")
	if len(s.DecryptedClientData) > 0 {
		fmt.Fprintf(w, "    client -> server: %s\n", session.SummarizeAppData(s.DecryptedClientData))
	}
	if len(s.DecryptedServerData) > 0 {
		fmt.Fprintf(w, "    server -> client: %s\n", session.SummarizeAppData(s.DecryptedServerData))
	}
	fmt.Fprintln(w)
}

func printPreamble(w io.Writer, s *session.Session) {
	if len(s.ClientPreamble) == 0 && len(s.ServerPreamble) == 0 {
		return
	}
	if len(s.ClientPreamble) > 0 {
		fmt.Fprintf(w, "  Client preamble (%d bytes, TLS starts at offset %d):\n",
			len(s.ClientPreamble), s.ClientTLSOffset)
		fmt.Fprintf(w, "    %s\n", sanitizePreamble(s.ClientPreamble))
	}
	if len(s.ServerPreamble) > 0 {
		fmt.Fprintf(w, "  Server preamble (%d bytes, TLS starts at offset %d):\n",
			len(s.ServerPreamble), s.ServerTLSOffset)
		fmt.Fprintf(w, "    %s\n", sanitizePreamble(s.ServerPreamble))
	}
	fmt.Fprintln(w)
}

func sanitizePreamble(data []byte) string {
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			out[i] = b
		} else if b == '\n' || b == '\r' {
			out[i] = ' '
		} else {
			out[i] = '.'
		}
	}
	return string(out)
}

func printClientHello(w io.Writer, s *session.Session) {
	ch := s.ClientHello
	if ch == nil {
		fmt.Fprintln(w, "  ClientHello: (not received)")
		return
	}

	fmt.Fprintln(w, "  ClientHello:")
	fmt.Fprintf(w, "    Version:          %s (record: %s)\n", ch.Version, s.RecordVersion)

	if ch.SNI != "" {
		fmt.Fprintf(w, "    SNI:              %s\n", ch.SNI)
	}
	if s.JA3 != "" {
		fmt.Fprintf(w, "    JA3:              %s\n", s.JA3)
	}
	if s.JA4 != "" {
		fmt.Fprintf(w, "    JA4:              %s\n", s.JA4)
	}

	// Cipher suites
	fmt.Fprintf(w, "    Cipher suites (%d):", len(ch.CipherSuites))
	if len(ch.CipherSuites) <= 6 {
		for _, cs := range ch.CipherSuites {
			fmt.Fprintf(w, " %s", tls.CipherSuiteName(cs))
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w)
		for _, cs := range ch.CipherSuites {
			info := tls.LookupCipherSuite(cs)
			weak := ""
			if info.Weak {
				weak = " (weak)"
			}
			fmt.Fprintf(w, "      %s%s\n", info.Name, weak)
		}
	}

	// Supported versions
	if len(ch.SupportedVersions) > 0 {
		var vers []string
		for _, v := range ch.SupportedVersions {
			vers = append(vers, v.String())
		}
		fmt.Fprintf(w, "    Supported versions: %s\n", strings.Join(vers, ", "))
	}

	// Supported groups
	if len(ch.SupportedGroups) > 0 {
		var groups []string
		for _, g := range ch.SupportedGroups {
			groups = append(groups, tls.NamedGroupName(g))
		}
		fmt.Fprintf(w, "    Supported groups: %s\n", strings.Join(groups, ", "))
	}

	// Signature algorithms
	if len(ch.SignatureAlgs) > 0 {
		var algs []string
		for _, a := range ch.SignatureAlgs {
			algs = append(algs, tls.SignatureAlgorithmName(a))
		}
		fmt.Fprintf(w, "    Sig algorithms:   %s\n", strings.Join(algs, ", "))
	}

	// ALPN
	if len(ch.ALPNProtocols) > 0 {
		fmt.Fprintf(w, "    ALPN:             %s\n", strings.Join(ch.ALPNProtocols, ", "))
	}

	fmt.Fprintln(w)
}

func printServerHello(w io.Writer, s *session.Session) {
	sh := s.ServerHello
	if sh == nil {
		fmt.Fprintln(w, "  ServerHello: (not received)")
		return
	}

	fmt.Fprintln(w, "  ServerHello:")
	negotiated := sh.NegotiatedVersion()
	if sh.SupportedVersion != nil {
		fmt.Fprintf(w, "    Version:      %s (wire: %s, supported_versions: %s)\n",
			negotiated, sh.Version, sh.SupportedVersion)
	} else {
		fmt.Fprintf(w, "    Version:      %s\n", negotiated)
	}

	info := tls.LookupCipherSuite(sh.CipherSuite)
	weak := ""
	if info.Weak {
		weak = " (weak)"
	}
	fmt.Fprintf(w, "    Cipher suite: %s%s\n", info.Name, weak)
	fmt.Fprintln(w)
}

func printCertificates(w io.Writer, s *session.Session) {
	certs := s.Certificates
	if certs == nil {
		if s.TLS13CertEncrypted || (s.NegotiatedVersion != nil && *s.NegotiatedVersion == tls.VersionTLS13) {
			msg := "  Certificate: (encrypted in TLS 1.3 - supply --keylog to decrypt)"
			if s.DecryptError != "" {
				msg = fmt.Sprintf("  Certificate: (TLS 1.3, decryption failed: %s)", s.DecryptError)
			}
			fmt.Fprintln(w, msg)
		} else {
			fmt.Fprintln(w, "  Certificate: (not received)")
		}
		return
	}

	label := "Certificate chain"
	if s.CertsDecrypted {
		label = "Certificate chain (decrypted via keylog)"
	}
	fmt.Fprintf(w, "  %s (%d certs):\n", label, len(certs.Certificates))
	for i, der := range certs.Certificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			fmt.Fprintf(w, "    [%d] (parse error: %v)\n", i, err)
			continue
		}
		fmt.Fprintf(w, "    [%d] Subject: %s\n", i, cert.Subject.CommonName)
		fmt.Fprintf(w, "        Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Fprintf(w, "        Valid:   %s - %s\n",
			cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
		if len(cert.DNSNames) > 0 {
			fmt.Fprintf(w, "        SANs:   %s\n", strings.Join(cert.DNSNames, ", "))
		}
	}
	fmt.Fprintln(w)
}

func printFlags(w io.Writer, s *session.Session) {
	var flags []string
	if s.HasServerKeyExchange {
		flags = append(flags, "ephemeral key exchange")
	}
	if s.HasCertificateRequest {
		flags = append(flags, "mTLS (server requested client cert)")
	}
	if s.HasClientCertificate {
		flags = append(flags, "client sent certificate")
	}
	if len(flags) > 0 {
		fmt.Fprintf(w, "  Flags: %s\n", strings.Join(flags, ", "))
	}
}
