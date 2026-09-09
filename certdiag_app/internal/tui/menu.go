package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type menuItem struct {
	key   string   // hotkey display: "k", "c", etc.
	label string   // "Create Key"
	kind  formKind // what form to open
}

type menuModel struct {
	title  string
	items  []menuItem
	cursor int
	active bool
	tip    string
}

func (m *menuModel) activate(title string, items []menuItem, tip string, initialCursor ...int) {
	m.title = title
	m.items = items
	m.cursor = 0
	if len(initialCursor) > 0 && initialCursor[0] >= 0 && initialCursor[0] < len(items) {
		m.cursor = initialCursor[0]
	}
	m.active = true
	m.tip = tip
}

func (m *menuModel) close() {
	m.active = false
	m.items = nil
}

func (m *menuModel) update(msg tea.KeyMsg) (selected *menuItem, done bool) {
	switch {
	case isKeyClose(msg):
		return nil, true

	case isKeyEnter(msg):
		if len(m.items) > 0 && m.cursor < len(m.items) {
			return &m.items[m.cursor], true
		}
		return nil, true

	case isKeyUp(msg):
		if m.cursor > 0 {
			m.cursor--
		} else {
			m.cursor = len(m.items) - 1
		}
		return nil, false

	case isKeyDown(msg):
		if m.cursor < len(m.items)-1 {
			m.cursor++
		} else {
			m.cursor = 0
		}
		return nil, false
	}

	// Check hotkeys (single letter keys that aren't arrow/special)
	key := msg.String()
	if len(key) == 1 {
		for i := range m.items {
			if strings.EqualFold(m.items[i].key, key) {
				return &m.items[i], true
			}
		}
	}

	return nil, false
}

func (m *menuModel) view(width, height int) string {
	if !m.active || len(m.items) == 0 {
		return ""
	}

	boxW := 40
	if boxW > width-4 {
		boxW = width - 4
	}
	if boxW < 20 {
		boxW = 20
	}

	var sb strings.Builder
	sb.WriteString(styleModalTitle.Render(m.title))
	sb.WriteString("\n\n")

	for i, item := range m.items {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
		}
		line := prefix + "[" + item.key + "] " + item.label
		// Pad to box width
		pad := boxW - 4 - len(line)
		if pad > 0 {
			line += strings.Repeat(" ", pad)
		}
		if i == m.cursor {
			sb.WriteString(styleCursorRow.Render(line))
		} else {
			sb.WriteString(line)
		}
		sb.WriteString("\n")
	}

	if m.tip != "" {
		sb.WriteString(styleFormHelp.Render(m.tip))
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(styleFormHint.Render(FormatHints(Hint{"Enter", "Select"}, Hint{"Esc/q", "Cancel"})))

	content := sb.String()

	border := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2)
	if !noColor {
		border = border.BorderForeground(colorAccent)
	}

	box := border.Render(content)
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// --- Menu builders ---

func buildFunctionsMenu() []menuItem {
	return []menuItem{
		{key: "1", label: "Cert Lister", kind: formNone},
		{key: "2", label: "Remote Fetch", kind: formRemote},
		{key: "3", label: "Packet Analyzer", kind: formPcapAnalyze},
		{key: "4", label: "Trust Stores", kind: formTrustStore},
	}
}

func buildNewMenu() []menuItem {
	return []menuItem{
		{key: "k", label: "Create Key", kind: formCreateKey},
		{key: "c", label: "Create Certificate", kind: formCreateCert},
		{key: "r", label: "Create CSR", kind: formCreateCSR},
	}
}

func buildActionMenu(node TreeNode) []menuItem {
	if node.Locked {
		return nil
	}

	// Trust stores are read-only: every action below mutates a file.
	if node.isReadOnlySource() {
		return nil
	}

	ct := node.ContentType

	// Bundle (multi-item container)
	if node.IsBundle {
		items := []menuItem{
			{key: "e", label: "Extract", kind: formExtract},
			{key: "c", label: "Convert", kind: formConvert},
			{key: "p", label: "Change Password", kind: formReencrypt},
		}
		if node.Container != nil && len(node.Container.Password) > 0 {
			items = append(items, menuItem{key: "x", label: "Remove Passphrase", kind: formRemovePassphrase})
		}
		return items
	}

	// Individual item types
	if node.Item == nil {
		return nil
	}

	switch {
	case strings.Contains(ct, "/cert"):
		items := []menuItem{
			{key: "r", label: "Renew", kind: formRenew},
			{key: "t", label: "New Cert (like this)", kind: formCreateCert},
			{key: "n", label: "New CSR (like this)", kind: formCreateCSR},
			{key: "c", label: "Convert", kind: formConvert},
		}
		if node.IsChild {
			items = append(items, menuItem{key: "e", label: "Extract", kind: formExtract})
		}
		return items
	case strings.Contains(ct, "/csr"):
		return []menuItem{
			{key: "s", label: "Sign", kind: formSignCSR},
			{key: "t", label: "New Cert (like this)", kind: formCreateCert},
			{key: "n", label: "New CSR (like this)", kind: formCreateCSR},
			{key: "c", label: "Convert", kind: formConvert},
		}
	case strings.Contains(ct, "/key"):
		items := []menuItem{
			{key: "c", label: "Convert", kind: formConvert},
			{key: "t", label: "Create Certificate", kind: formCreateCert},
			{key: "r", label: "Create CSR", kind: formCreateCSR},
		}
		// For JKS sub-items, show "Change Entry Password" instead of "Change Password"
		if node.IsChild && node.Container != nil && node.Item.Alias != "" &&
			node.Container.Format == certlib.FormatJKS {
			items = append(items, menuItem{key: "p", label: "Change Entry Password", kind: formReencrypt})
		} else {
			items = append(items, menuItem{key: "p", label: "Change Password", kind: formReencrypt})
		}
		if node.Item != nil && node.Item.Encrypted {
			items = append(items, menuItem{key: "x", label: "Remove Passphrase", kind: formRemovePassphrase})
		}
		return items
	}

	return nil
}
