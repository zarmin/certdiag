package tui

import (
	"bytes"
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type passwordCache struct {
	passwords [][]byte
}

func newPasswordCache() *passwordCache {
	return &passwordCache{}
}

func (pc *passwordCache) add(pw []byte) {
	if pw == nil {
		return
	}
	for _, existing := range pc.passwords {
		if bytes.Equal(existing, pw) {
			return
		}
	}
	cp := make([]byte, len(pw))
	copy(cp, pw)
	pc.passwords = append(pc.passwords, cp)
}

func (pc *passwordCache) tagged() []certlib.TaggedPassword {
	out := make([]certlib.TaggedPassword, len(pc.passwords))
	for i, pw := range pc.passwords {
		out[i] = certlib.TaggedPassword{Password: pw, Source: certlib.PasswordSourceInteractive}
	}
	return out
}

func (pc *passwordCache) len() int {
	return len(pc.passwords)
}

type savedPasswordProvider struct {
	base  certlib.PasswordProvider
	cache *passwordCache
}

func (p *savedPasswordProvider) PasswordsForFile(filePath string) []certlib.TaggedPassword {
	var pws []certlib.TaggedPassword
	if p.base != nil {
		pws = append(pws, p.base.PasswordsForFile(filePath)...)
	}
	pws = append(pws, p.cache.tagged()...)
	return pws
}

type passwordModel struct {
	textInput  textinput.Model
	active     bool
	targetNode TreeNode
}

func newPasswordModel() passwordModel {
	ti := textinput.New()
	ti.Prompt = "Password: "
	ti.CharLimit = 256
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	return passwordModel{
		textInput: ti,
	}
}

func (p *passwordModel) activate(node TreeNode) tea.Cmd {
	p.active = true
	p.targetNode = node
	p.textInput.SetValue("")

	// Contextual prompt for per-entry unlock within an already-unlocked JKS bundle
	if node.IsChild && node.Item != nil && node.Item.Alias != "" &&
		node.Container != nil && node.Container.Password != nil {
		format := node.Container.Format
		if format == certlib.FormatJKS {
			p.textInput.Prompt = fmt.Sprintf("Password for entry '%s' #%d: ", node.Item.Alias, node.ItemIdx)
			return p.textInput.Focus()
		}
	}
	p.textInput.Prompt = "Password: "
	return p.textInput.Focus()
}

func (p *passwordModel) value() []byte {
	return []byte(p.textInput.Value())
}

func (p *passwordModel) close() {
	p.active = false
	p.textInput.SetValue("")
	p.textInput.Blur()
}

func (p *passwordModel) update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	p.textInput, cmd = p.textInput.Update(msg)
	return cmd
}

func (p *passwordModel) view(width int) string {
	p.textInput.Width = width - 12
	return p.textInput.View()
}
