package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type checkSortMode int

const (
	checkSortSeverity checkSortMode = iota
	checkSortFilename
	checkSortCategory
)

type checkViewModel struct {
	issues       []certlib.CheckIssue
	allIssues    []certlib.CheckIssue
	cursor       int
	offset       int
	width        int
	height       int
	minSeverity  int // 0=all, 1=warning+, 2=critical
	sortMode     checkSortMode
	filterText   string
	filterActive bool
	filesScanned int
	summary      certlib.CheckSummary
	remoteOrigin bool
	status       string
}

const statusRemoteCheckNoNav = "Details not available for remote checks"

func newCheckViewModel(result *certlib.CheckResult) checkViewModel {
	m := checkViewModel{
		allIssues:    result.Issues,
		filesScanned: result.FilesScanned,
		summary:      result.Summary,
	}
	m.applyFilters()
	return m
}

func (m *checkViewModel) applyFilters() {
	var filtered []certlib.CheckIssue
	for _, issue := range m.allIssues {
		if issue.Severity.Rank() < m.minSeverity {
			continue
		}
		if m.filterText != "" {
			search := strings.ToLower(issue.Filename + " " + issue.Message + " " + issue.Category)
			if !strings.Contains(search, strings.ToLower(m.filterText)) {
				continue
			}
		}
		filtered = append(filtered, issue)
	}

	switch m.sortMode {
	case checkSortFilename:
		sort.SliceStable(filtered, func(i, j int) bool {
			return filtered[i].Filename < filtered[j].Filename
		})
	case checkSortCategory:
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].Category != filtered[j].Category {
				return filtered[i].Category < filtered[j].Category
			}
			return filtered[i].Severity.Rank() > filtered[j].Severity.Rank()
		})
	default:
		sort.SliceStable(filtered, func(i, j int) bool {
			return filtered[i].Severity.Rank() > filtered[j].Severity.Rank()
		})
	}

	m.issues = filtered
	if m.cursor >= len(m.issues) {
		m.cursor = len(m.issues) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.clampOffset()
}

func (m *checkViewModel) clampOffset() {
	viewH := m.viewportHeight()
	if viewH <= 0 {
		return
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+viewH {
		m.offset = m.cursor - viewH + 1
	}
	maxOffset := len(m.issues) - viewH
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.offset > maxOffset {
		m.offset = maxOffset
	}
}

func (m *checkViewModel) viewportHeight() int {
	_, footerH := m.footerHintBar()
	// height minus title(1) + separator(1) + header(1) + footer(footerH)
	h := m.height - 3 - footerH
	if h < 1 {
		h = 1
	}
	return h
}

func (m *checkViewModel) footerHintBar() (string, int) {
	hints, status := m.hints()
	return RenderHintBar(m.width, hints, status...)
}

func (m *checkViewModel) hints() ([]Hint, []StatusHint) {
	severityLabel := "all"
	switch m.minSeverity {
	case 1:
		severityLabel = "warning+"
	case 2:
		severityLabel = "critical"
	}
	sortLabel := "severity"
	switch m.sortMode {
	case checkSortFilename:
		sortLabel = "filename"
	case checkSortCategory:
		sortLabel = "category"
	}
	var hints []Hint
	if m.filterActive {
		hints = []Hint{{"", "Filter: " + m.filterText}, {"Esc", "Clear"}}
	} else {
		hints = []Hint{
			{"Enter", "Details"}, {"/", "Filter"}, {"s", "Sort:" + sortLabel},
			{"1-3", "Sev:" + severityLabel}, {"c", "Catalog"}, {"?", "Help"}, {"Esc/q", "Back"},
		}
	}
	var status []StatusHint
	if m.status != "" {
		status = append(status, StatusHint{m.status})
	}
	return hints, status
}

func (m *checkViewModel) resize(width, height int) {
	m.width = width
	m.height = height
	m.clampOffset()
}

func (m checkViewModel) view() string {
	var sb strings.Builder

	totalIssues := len(m.allIssues)
	title := fmt.Sprintf(" Certificate Checks%s%d files, %d issues",
		strings.Repeat(" ", max(1, m.width-50)),
		m.filesScanned, totalIssues)
	if runeWidth(title) > m.width {
		title = truncate(title, m.width)
	}
	sb.WriteString(styleModalTitle.Render(title))
	sb.WriteString("\n")

	sep := strings.Repeat("=", m.width)
	sb.WriteString(lipgloss.NewStyle().Foreground(colorDimGrey).Render(sep))
	sb.WriteString("\n")

	// Header
	header := fmt.Sprintf(" %-10s %-24s %s", "SEV", "FILE", "MESSAGE")
	if runeWidth(header) > m.width {
		header = truncate(header, m.width)
	}
	sb.WriteString(styleHeader.Render(header))
	sb.WriteString("\n")

	viewH := m.viewportHeight()
	end := m.offset + viewH
	if end > len(m.issues) {
		end = len(m.issues)
	}

	for i := m.offset; i < end; i++ {
		issue := m.issues[i]
		sev := strings.ToUpper(string(issue.Severity))
		line := fmt.Sprintf(" %-10s %-24s %s", sev, issue.Filename, issue.Message)
		if runeWidth(line) > m.width {
			line = truncate(line, m.width)
		}

		var style lipgloss.Style
		if i == m.cursor {
			style = styleCursorRow
		} else {
			switch issue.Severity {
			case certlib.SeverityCritical:
				style = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
			case certlib.SeverityWarning:
				style = lipgloss.NewStyle().Foreground(colorYellow)
			default:
				style = styleDimRow
			}
		}
		sb.WriteString(style.Render(padRight(line, m.width)))
		sb.WriteString("\n")
	}

	// Pad remaining lines
	rendered := end - m.offset
	for i := rendered; i < viewH; i++ {
		sb.WriteString("\n")
	}

	// Footer
	footer, _ := m.footerHintBar()
	sb.WriteString(footer)

	return sb.String()
}

type catalogModel struct {
	disabledChecks []string
	lines          []string
	offset         int
	width          int
	height         int
	total          int
	disabled       int
}

func newCatalogModel(disabledChecks []string, width, height int) catalogModel {
	total, _, disabledCount := certlib.EnabledCheckCount(disabledChecks)

	c := catalogModel{
		disabledChecks: disabledChecks,
		width:          width,
		height:         height,
		total:          total,
		disabled:       disabledCount,
	}
	c.buildLines()
	return c
}

func (c *catalogModel) buildLines() {
	disabled := make(map[string]bool, len(c.disabledChecks))
	for _, id := range c.disabledChecks {
		disabled[id] = true
	}

	checks := certlib.AllChecks()

	var lines []string
	lastCategory := ""
	for _, def := range checks {
		if def.Category != lastCategory {
			if lastCategory != "" {
				lines = append(lines, "")
			}
			lines = append(lines, lipgloss.NewStyle().Bold(true).Render(" "+strings.ToUpper(def.Category)))
			lastCategory = def.Category
		}

		marker := lipgloss.NewStyle().Foreground(colorGreen).Render("*")
		if disabled[def.ID] {
			marker = lipgloss.NewStyle().Foreground(colorDisabled).Render("-")
		}
		sev := strings.ToUpper(string(def.Severity))
		line := fmt.Sprintf("   %s %-25s %-10s %s", marker, def.ID, sev, def.Description)
		if runeWidth(line) > c.width {
			line = truncate(line, c.width)
		}
		lines = append(lines, line)
	}

	c.lines = lines
}

func (c *catalogModel) resize(width, height int) {
	c.width = width
	c.height = height
	c.buildLines()
}

func (c *catalogModel) catalogViewportHeight() int {
	_, footerH := c.footerHintBar()
	// title(1) + separator(1) + footer(footerH)
	h := c.height - 2 - footerH
	if h < 1 {
		h = 1
	}
	return h
}

func (c *catalogModel) footerHintBar() (string, int) {
	hints, status := c.hints()
	return RenderHintBar(c.width, hints, status...)
}

func (c *catalogModel) hints() ([]Hint, []StatusHint) {
	hints := []Hint{{"Up/Down", "Scroll"}, {"?", "Help"}, {"Esc/q", "Close"}}
	var status []StatusHint
	viewH := c.height - 3 // rough estimate to avoid recursion
	if viewH < 1 {
		viewH = 1
	}
	if len(c.lines) > viewH {
		status = append(status, StatusHint{fmt.Sprintf("(%d/%d)", c.offset+1, len(c.lines))})
	}
	return hints, status
}

func (c *catalogModel) scrollDown() {
	viewH := c.catalogViewportHeight()
	maxOffset := len(c.lines) - viewH
	if maxOffset < 0 {
		maxOffset = 0
	}
	if c.offset < maxOffset {
		c.offset++
	}
}

func (c *catalogModel) scrollUp() {
	if c.offset > 0 {
		c.offset--
	}
}

func (c *catalogModel) pageDown() {
	viewH := c.catalogViewportHeight()
	c.offset += viewH
	maxOffset := len(c.lines) - viewH
	if maxOffset < 0 {
		maxOffset = 0
	}
	if c.offset > maxOffset {
		c.offset = maxOffset
	}
}

func (c *catalogModel) pageUp() {
	viewH := c.catalogViewportHeight()
	c.offset -= viewH
	if c.offset < 0 {
		c.offset = 0
	}
}

func (c catalogModel) view() string {
	var sb strings.Builder

	title := fmt.Sprintf(" Available Checks%s%d checks, %d disabled",
		strings.Repeat(" ", max(1, c.width-50)),
		c.total, c.disabled)
	sb.WriteString(styleModalTitle.Render(truncate(title, c.width)))
	sb.WriteString("\n")

	sep := strings.Repeat("=", c.width)
	sb.WriteString(lipgloss.NewStyle().Foreground(colorDimGrey).Render(sep))
	sb.WriteString("\n")

	viewH := c.catalogViewportHeight()
	end := c.offset + viewH
	if end > len(c.lines) {
		end = len(c.lines)
	}

	for i := c.offset; i < end; i++ {
		sb.WriteString(c.lines[i])
		sb.WriteString("\n")
	}

	// Pad remaining lines
	rendered := end - c.offset
	for i := rendered; i < viewH; i++ {
		sb.WriteString("\n")
	}

	footer, _ := c.footerHintBar()
	sb.WriteString(footer)

	return sb.String()
}
