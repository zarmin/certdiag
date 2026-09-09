package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/opensslcmd"
)

// openSSLForForm builds the equivalent openssl command(s) from the active form's
// current field values, reusing the same option builders the form submits with.
func (m RootModel) openSSLForForm() ([]opensslcmd.Command, error) {
	switch m.activeFormKind {
	case formCreateKey:
		opts, err := buildCreateKeyOptions(m.activeForm)
		if err != nil {
			return nil, err
		}
		return certops.OpenSSLForGenerateKey(opts), nil
	case formCreateCert:
		opts, _, err := buildCreateCertOptions(m.activeForm, m.scanPath, m.passwordCache.tagged())
		if err != nil {
			return nil, err
		}
		return certops.OpenSSLForCreateCert(opts), nil
	case formCreateCSR:
		opts, err := buildCreateCSROptions(m.activeForm, m.passwordCache.tagged())
		if err != nil {
			return nil, err
		}
		return certops.OpenSSLForCreateCSR(opts), nil
	case formSignCSR:
		opts, err := buildSignCSROptions(m.activeForm, m.scanPath, m.passwordCache.tagged())
		if err != nil {
			return nil, err
		}
		return certops.OpenSSLForSignCSR(opts), nil
	case formConvert:
		opts, err := buildConvertOptions(m.activeForm, m.passwordCache.tagged())
		if err != nil {
			return nil, err
		}
		return certops.OpenSSLForConvert(opts), nil
	}
	return nil, nil
}

// showDetailOpenSSL opens a popup with the openssl command that reproduces the
// current detail view: an inspect command for a local file, or an s_client
// command for a remote endpoint.
func (m RootModel) showDetailOpenSSL() (tea.Model, tea.Cmd) {
	if m.detail != nil && m.detail.source != "" {
		rt, err := certlib.ParseTarget(m.detail.source)
		if err != nil {
			return m, m.notify(notifyError, "openssl equivalent: "+err.Error())
		}
		cmd := opensslcmd.RemoteFetch(opensslcmd.RemoteSpec{
			Host: rt.Host, Port: rt.Port, SNI: rt.SNI, ShowCerts: true,
		})
		m.popup = openSSLPopup([]opensslcmd.Command{cmd})
		return m, nil
	}

	if m.detail == nil || m.detail.node.Container == nil || m.detail.node.Container.FilePath == "" {
		return m, m.notify(notifyNotice, "no local file to show an openssl command for")
	}
	c := m.detail.node.Container
	ct := certlib.ContentCertificate
	if m.detail.node.Item != nil {
		ct = m.detail.node.Item.Type
	}
	m.popup = openSSLPopup([]opensslcmd.Command{opensslcmd.Inspect(c.FilePath, ct, c.Format)})
	return m, nil
}

// openSSLPopup renders the equivalent commands into a copyable popup. The full
// block (commands plus notes) is stored in message for clipboard copy.
func openSSLPopup(cmds []opensslcmd.Command) popupState {
	block := opensslcmd.Render(cmds...)
	return popupState{
		kind:    popupCommand,
		title:   "openssl equivalent",
		message: block,
		lines:   strings.Split(block, "\n"),
	}
}
