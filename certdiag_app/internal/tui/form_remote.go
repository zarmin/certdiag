package tui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

const (
	labelStarttlsNone     = "None"
	labelStarttlsSMTP     = "SMTP"
	labelStarttlsIMAP     = "IMAP"
	labelStarttlsPOP3     = "POP3"
	labelStarttlsFTP      = "FTP"
	labelStarttlsLDAP     = "LDAP"
	labelStarttlsMySQL    = "MySQL"
	labelStarttlsPostgres = "PostgreSQL"

	labelTLSAuto = "Auto"
	labelTLS10   = "TLS 1.0"
	labelTLS11   = "TLS 1.1"
	labelTLS12   = "TLS 1.2"
	labelTLS13   = "TLS 1.3"

	labelIPAny = "Any"
	labelIPv4  = "IPv4"
	labelIPv6  = "IPv6"

	labelMTLSNone = "None"
	labelMTLSPEM  = "PEM cert+key"
	labelMTLSP12  = "PKCS#12"
	labelMTLSJKS  = "JKS"
)

var (
	starttlsOptions = []string{
		labelStarttlsNone, labelStarttlsSMTP, labelStarttlsIMAP,
		labelStarttlsPOP3, labelStarttlsFTP, labelStarttlsLDAP,
		labelStarttlsMySQL, labelStarttlsPostgres,
	}

	tlsVersionOptions = []string{
		labelTLSAuto, labelTLS10, labelTLS11, labelTLS12, labelTLS13,
	}

	ipVersionOptions = []string{labelIPAny, labelIPv4, labelIPv6}

	mtlsModeOptions = []string{labelMTLSNone, labelMTLSPEM, labelMTLSP12, labelMTLSJKS}
)

func starttlsFromLabel(label string) string {
	switch label {
	case labelStarttlsSMTP:
		return "smtp"
	case labelStarttlsIMAP:
		return "imap"
	case labelStarttlsPOP3:
		return "pop3"
	case labelStarttlsFTP:
		return "ftp"
	case labelStarttlsLDAP:
		return "ldap"
	case labelStarttlsMySQL:
		return "mysql"
	case labelStarttlsPostgres:
		return "postgres"
	default:
		return ""
	}
}

func tlsVersionFromLabel(label string) string {
	switch label {
	case labelTLS10:
		return "tls1.0"
	case labelTLS11:
		return "tls1.1"
	case labelTLS12:
		return "tls1.2"
	case labelTLS13:
		return "tls1.3"
	default:
		return ""
	}
}

func buildRemoteForm() *formModel {
	f := newFormModel("Remote Certificate Fetch")

	// Connection fields
	targetIdx := f.addField(fieldKeyTarget, newTextInputField("Target", "hostname, host:port, or https://url", true, nil))
	starttlsIdx := f.addField(fieldKeyStarttls, newRadioGroupField("STARTTLS", starttlsOptions, 0))
	tlsIdx := f.addField(fieldKeyTlsVersion, newRadioGroupField("TLS Version", tlsVersionOptions, 0))
	sniIdx := f.addField(fieldKeySni, newTextInputField("SNI Override", "server name for TLS handshake", false, nil))
	ipIdx := f.addField(fieldKeyIpVersion, newRadioGroupField("IP Version", ipVersionOptions, 0))

	// mTLS fields
	mtlsIdx := f.addField(fieldKeyMtlsMode, newRadioGroupField("Client Auth", mtlsModeOptions, 0))
	certIdx := f.addField(fieldKeyClientCert, newTextInputField("Client Cert", "path to PEM certificate", false, nil))
	keyIdx := f.addField(fieldKeyClientKey, newTextInputField("Client Key", "path to PEM private key", false, nil))
	p12Idx := f.addField(fieldKeyClientP12, newTextInputField("PKCS#12 File", "path to .p12 or .pfx file", false, nil))
	jksIdx := f.addField(fieldKeyClientJks, newTextInputField("JKS File", "path to .jks file", false, nil))
	aliasIdx := f.addField(fieldKeyClientAlias, newTextInputField("Alias", "entry alias in container", false, nil))
	pwIdx := f.addField(fieldKeyClientPassword, newPasswordInputField("Password", "container password", false, nil))
	// A server that does not send its full chain is the common case AIA exists
	// for, so the option belongs where the fetch is configured.
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Connect"))

	// Sections
	f.addSection("Connection", []int{targetIdx, starttlsIdx, tlsIdx, sniIdx, ipIdx})
	f.addSection("Client Certificate (mTLS)", []int{mtlsIdx, certIdx, keyIdx, p12Idx, jksIdx, aliasIdx, pwIdx})
	f.addSection("", []int{submitIdx})

	// Visibility rules for mTLS fields
	f.addVisibilityRule(certIdx, mtlsIdx, func(v string) bool { return v == labelMTLSPEM })
	f.addVisibilityRule(keyIdx, mtlsIdx, func(v string) bool { return v == labelMTLSPEM })
	f.addVisibilityRule(p12Idx, mtlsIdx, func(v string) bool { return v == labelMTLSP12 })
	f.addVisibilityRule(jksIdx, mtlsIdx, func(v string) bool { return v == labelMTLSJKS })
	f.addVisibilityRule(aliasIdx, mtlsIdx, func(v string) bool { return v == labelMTLSP12 || v == labelMTLSJKS })
	f.addVisibilityRule(pwIdx, mtlsIdx, func(v string) bool { return v != labelMTLSNone })

	f.evaluateVisibility()
	f.initFocus()

	return f
}

type RemoteFetchResultMsg struct {
	Result    *certops.FetchRemoteCertResult
	Passwords [][]byte
	Err       error
	// Opts are the options that produced this result, kept so the view can
	// re-run the same fetch without walking the user back through the form.
	Opts certops.FetchRemoteCertOptions
}

// errFetchCancelled marks a fetch the user stopped; it is not an error to show.
var errFetchCancelled = errors.New("cancelled")

func submitRemoteFetch(ctx context.Context, form *formModel, passwords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		target := strings.TrimSpace(form.fieldValue(fieldKeyTarget))
		if target == "" {
			return RemoteFetchResultMsg{Err: fmt.Errorf("target is required")}
		}

		opts := certops.FetchRemoteCertOptions{
			Targets:    []string{target},
			TLSVersion: tlsVersionFromLabel(form.fieldValue(fieldKeyTlsVersion)),
			Hostname:   strings.TrimSpace(form.fieldValue(fieldKeySni)),
			Starttls:   starttlsFromLabel(form.fieldValue(fieldKeyStarttls)),
			Timeout:    10 * time.Second,
			Parallel:   1,
		}

		switch form.fieldValue(fieldKeyIpVersion) {
		case labelIPv4:
			opts.IPv4Only = true
		case labelIPv6:
			opts.IPv6Only = true
		}

		// mTLS
		var usedClientPassword []byte
		mtlsMode := form.fieldValue(fieldKeyMtlsMode)
		if mtlsMode != labelMTLSNone {
			typedPassword := form.fieldValue(fieldKeyClientPassword)

			var certOpts certlib.ClientCertOptions

			switch mtlsMode {
			case labelMTLSPEM:
				certOpts.CertPath = strings.TrimSpace(form.fieldValue(fieldKeyClientCert))
				certOpts.KeyPath = strings.TrimSpace(form.fieldValue(fieldKeyClientKey))
				if certOpts.CertPath == "" || certOpts.KeyPath == "" {
					return RemoteFetchResultMsg{Err: fmt.Errorf("client cert and key paths are required for PEM mTLS")}
				}

			case labelMTLSP12:
				certOpts.P12Path = strings.TrimSpace(form.fieldValue(fieldKeyClientP12))
				if certOpts.P12Path == "" {
					return RemoteFetchResultMsg{Err: fmt.Errorf("PKCS#12 file path is required")}
				}
				certOpts.Alias = strings.TrimSpace(form.fieldValue(fieldKeyClientAlias))

			case labelMTLSJKS:
				certOpts.JKSPath = strings.TrimSpace(form.fieldValue(fieldKeyClientJks))
				if certOpts.JKSPath == "" {
					return RemoteFetchResultMsg{Err: fmt.Errorf("JKS file path is required")}
				}
				certOpts.Alias = strings.TrimSpace(form.fieldValue(fieldKeyClientAlias))
			}

			// Try the typed password first, then fall back to any session-cached
			// password so an encrypted client-cert container can be unlocked.
			candidates := [][]byte{[]byte(typedPassword)}
			for _, p := range passwords {
				candidates = append(candidates, p.Password)
			}

			var cert tls.Certificate
			var loadErr error
			for _, cand := range candidates {
				certOpts.Password = cand
				cert, loadErr = certlib.LoadClientCert(certOpts)
				if loadErr == nil {
					if len(cand) > 0 {
						usedClientPassword = cand
					}
					break
				}
			}
			if loadErr != nil {
				return RemoteFetchResultMsg{Err: fmt.Errorf("loading client cert: %w", loadErr)}
			}

			opts.ClientCerts = []tls.Certificate{cert}
		}

		ch := make(chan RemoteFetchResultMsg, 1)
		go func() {
			result, err := certops.FetchRemoteCert(opts)
			ch <- RemoteFetchResultMsg{Result: result, Err: err}
		}()

		select {
		case <-ctx.Done():
			return RemoteFetchResultMsg{Err: errFetchCancelled}
		case msg := <-ch:
			if len(usedClientPassword) > 0 {
				msg.Passwords = [][]byte{usedClientPassword}
			}
			msg.Opts = opts
			return msg
		}
	}
}
