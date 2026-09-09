package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

// --- Diff view ---

func (m *RootModel) openDiffFromMultiSelect() tea.Cmd {
	selected := m.multiSelect.collectSelected(m.allNodes)

	// Filter to certificates only
	var certs []TreeNode
	for _, n := range selected {
		if n.Item != nil && n.Item.Type == certlib.ContentCertificate && n.Item.Certificate != nil {
			certs = append(certs, n)
		}
	}

	if len(certs) != 2 {
		return m.notify(notifyInfo, fmt.Sprintf("diff requires exactly 2 certificates, got %d", len(certs)))
	}

	m.diffLeftCert = certs[0].Item.Certificate
	m.diffRightCert = certs[1].Item.Certificate
	m.diffLeftSrc = certlib.DiffSource{
		FilePath:  certs[0].Container.FilePath,
		ItemIndex: certs[0].ItemIdx,
		Alias:     certs[0].Item.Alias,
		Format:    string(certs[0].Container.Format),
	}
	m.diffRightSrc = certlib.DiffSource{
		FilePath:  certs[1].Container.FilePath,
		ItemIndex: certs[1].ItemIdx,
		Alias:     certs[1].Item.Alias,
		Format:    string(certs[1].Container.Format),
	}

	m.recomputeDiff()
	m.diffScroll = 0
	m.state = stateDiff
	return nil
}

func (m *RootModel) recomputeDiff() {
	result := certlib.CompareCertificates(m.diffLeftCert, m.diffRightCert, m.diffDetailed)
	result.Left = m.diffLeftSrc
	result.Right = m.diffRightSrc
	m.diffResult = &result
}

func (m RootModel) handleDiffKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		m.diffResult = nil
		m.state = stateMultiSelect
		return m, nil

	case msg.String() == "d":
		m.diffDetailed = !m.diffDetailed
		m.recomputeDiff()
		return m, nil

	case msg.String() == "c":
		m.diffOnlyDiff = !m.diffOnlyDiff
		return m, nil

	case msg.String() == "s":
		m.diffLeftCert, m.diffRightCert = m.diffRightCert, m.diffLeftCert
		m.diffLeftSrc, m.diffRightSrc = m.diffRightSrc, m.diffLeftSrc
		m.recomputeDiff()
		m.diffScroll = 0
		return m, nil

	case isKeyUp(msg):
		if m.diffScroll > 0 {
			m.diffScroll--
		}
		return m, nil

	case isKeyDown(msg):
		m.diffScroll++
		return m, nil

	case isKeyPgUp(msg):
		m.diffScroll -= m.height / 2
		if m.diffScroll < 0 {
			m.diffScroll = 0
		}
		return m, nil

	case isKeyPgDown(msg):
		m.diffScroll += m.height / 2
		return m, nil

	case isKeyHome(msg):
		m.diffScroll = 0
		return m, nil

	case isKeyEnd(msg):
		m.diffScroll = 99999
		return m, nil
	}

	return m, nil
}

func (m RootModel) viewDiff() string {
	if m.diffResult == nil {
		return ""
	}

	result := m.diffResult

	var sb strings.Builder

	// Header
	leftLabel := filepath.Base(result.Left.FilePath)
	rightLabel := filepath.Base(result.Right.FilePath)
	if result.Left.Alias != "" {
		leftLabel = fmt.Sprintf("%s [%q]", leftLabel, result.Left.Alias)
	}
	if result.Right.Alias != "" {
		rightLabel = fmt.Sprintf("%s [%q]", rightLabel, result.Right.Alias)
	}

	titleStyle := lipgloss.NewStyle()
	if !noColor {
		titleStyle = titleStyle.Foreground(colorAccent).Bold(true)
	}
	sb.WriteString(titleStyle.Render(fmt.Sprintf("Diff: %s vs %s", leftLabel, rightLabel)))
	sb.WriteString("\n\n")

	if result.Identical() {
		sameStyle := lipgloss.NewStyle()
		if !noColor {
			sameStyle = sameStyle.Foreground(colorGreen)
		}
		sb.WriteString(sameStyle.Render("All fields are identical."))
		sb.WriteString("\n")
	} else {
		// Compute max name length for alignment
		maxNameLen := 0
		for _, f := range result.Fields {
			if m.diffOnlyDiff && f.Status == certlib.DiffSame {
				continue
			}
			if len(f.Name) > maxNameLen {
				maxNameLen = len(f.Name)
			}
		}

		for _, f := range result.Fields {
			if m.diffOnlyDiff && f.Status == certlib.DiffSame {
				continue
			}
			sb.WriteString(m.renderDiffField(f, maxNameLen))
		}

		sb.WriteString("\n")
		sb.WriteString(m.renderDiffSummary(result.Summary))
	}

	// Toggles status
	var toggles []string
	if m.diffDetailed {
		toggles = append(toggles, "details: on")
	}
	if m.diffOnlyDiff {
		toggles = append(toggles, "only changes: on")
	}
	if len(toggles) > 0 {
		sb.WriteString("\n")
		dimStyle := lipgloss.NewStyle()
		if !noColor {
			dimStyle = dimStyle.Foreground(colorDimGrey)
		}
		sb.WriteString(dimStyle.Render(strings.Join(toggles, "  ")))
		sb.WriteString("\n")
	}

	// Split content into lines and apply scroll
	content := sb.String()
	lines := strings.Split(content, "\n")

	// Info bar
	footer, footerLines := RenderHintBar(m.width, m.diffHints())

	viewH := m.height - footerLines
	if viewH < 1 {
		viewH = 1
	}

	// Clamp scroll
	maxScroll := len(lines) - viewH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.diffScroll > maxScroll {
		m.diffScroll = maxScroll
	}

	// Render visible lines
	var out strings.Builder
	start := m.diffScroll
	end := start + viewH
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		out.WriteString(lines[i])
		out.WriteString("\n")
	}

	// Pad remaining space
	rendered := end - start
	for i := rendered; i < viewH; i++ {
		out.WriteString("\n")
	}

	out.WriteString(footer)
	return out.String()
}

func (m RootModel) renderDiffField(f certlib.DiffField, nameWidth int) string {
	var sb strings.Builder
	padding := strings.Repeat(" ", nameWidth-len(f.Name))
	prefix := fmt.Sprintf("  %s:%s  ", f.Name, padding)

	changedStyle := lipgloss.NewStyle()
	addedStyle := lipgloss.NewStyle()
	removedStyle := lipgloss.NewStyle()
	sameStyle := lipgloss.NewStyle()
	if !noColor {
		changedStyle = changedStyle.Foreground(colorYellow)
		addedStyle = addedStyle.Foreground(colorGreen)
		removedStyle = removedStyle.Foreground(colorRed)
		sameStyle = sameStyle.Foreground(colorDimGrey)
	}

	if len(f.Children) > 0 && f.Status == certlib.DiffChanged {
		sb.WriteString(fmt.Sprintf("  %s:\n", f.Name))
		for _, child := range f.Children {
			switch child.Status {
			case certlib.DiffSame:
				sb.WriteString(fmt.Sprintf("      %s  %s\n", child.Name, sameStyle.Render("(same)")))
			case certlib.DiffAdded:
				line := fmt.Sprintf("    + %s", child.Name)
				sb.WriteString(fmt.Sprintf("%s  %s\n", addedStyle.Render(line), addedStyle.Render("(added)")))
			case certlib.DiffRemoved:
				line := fmt.Sprintf("    - %s", child.Name)
				sb.WriteString(fmt.Sprintf("%s  %s\n", removedStyle.Render(line), removedStyle.Render("(removed)")))
			}
		}
		return sb.String()
	}

	switch f.Status {
	case certlib.DiffSame:
		sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, f.Left, sameStyle.Render("(same)")))
	case certlib.DiffChanged:
		sb.WriteString(fmt.Sprintf("%s%s  %s  %s\n", prefix, f.Left,
			changedStyle.Render("->"), changedStyle.Render(f.Right)))
	case certlib.DiffAdded:
		sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, addedStyle.Render(f.Right), addedStyle.Render("(added)")))
	case certlib.DiffRemoved:
		sb.WriteString(fmt.Sprintf("%s%s  %s\n", prefix, removedStyle.Render(f.Left), removedStyle.Render("(removed)")))
	}

	return sb.String()
}

func (m RootModel) renderDiffSummary(s certlib.DiffSummary) string {
	var parts []string

	changedStyle := lipgloss.NewStyle()
	addedStyle := lipgloss.NewStyle()
	removedStyle := lipgloss.NewStyle()
	if !noColor {
		changedStyle = changedStyle.Foreground(colorYellow)
		addedStyle = addedStyle.Foreground(colorGreen)
		removedStyle = removedStyle.Foreground(colorRed)
	}

	if s.Changed > 0 {
		parts = append(parts, changedStyle.Render(fmt.Sprintf("%d changed", s.Changed)))
	}
	if s.Added > 0 {
		parts = append(parts, addedStyle.Render(fmt.Sprintf("%d added", s.Added)))
	}
	if s.Removed > 0 {
		parts = append(parts, removedStyle.Render(fmt.Sprintf("%d removed", s.Removed)))
	}
	if s.Same > 0 {
		parts = append(parts, fmt.Sprintf("%d same", s.Same))
	}
	return fmt.Sprintf("Summary: %s", strings.Join(parts, ", "))
}

func (m RootModel) diffHints() []Hint {
	return []Hint{{"d", "Details"}, {"c", "Only changes"}, {"s", "Swap"}, {"Up/Down", "Scroll"}, {"?", "Help"}, {"Esc/q", "Back"}}
}
