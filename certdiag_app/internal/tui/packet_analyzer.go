package tui

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/zarmin/certdiag/certdiag_app/internal/pcapint"
	pktoutput "github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/proxy"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/tcp"
)

// --- Messages ---

type PcapAnalyzeMsg struct {
	Result *pcapint.AnalyzeResult
	Err    error
}

type ProxySessionMsg struct {
	Session *session.Session
}

type ProxyStartMsg struct {
	Proxy *proxy.Proxy
	Err   error
}

type proxyTickMsg struct{}

func startPcapAnalyze(path string, aggressive bool) tea.Cmd {
	return func() tea.Msg {
		result, err := pcapint.Analyze(pcapint.AnalyzeOptions{
			Path:       path,
			Aggressive: aggressive,
		})
		return PcapAnalyzeMsg{Result: result, Err: err}
	}
}

// --- States ---

type packetState int

const (
	packetIdle packetState = iota
	packetLoading
	packetSessions
	packetDetail
	packetCertDetail
	packetProxyRunning
	packetFilterEdit
	packetDumpConfirm
)

// --- Detail line (for navigable detail view) ---

type sessionDetailLine struct {
	text      string
	style     *lipgloss.Style
	certIndex int // >= 0 if this line represents a certificate
	cert      *x509.Certificate
}

// --- Model ---

type packetAnalyzerModel struct {
	state       packetState
	sessions    []*session.Session // filtered/displayed
	allSessions []*session.Session // unfiltered (for refiltering)
	cursor      int
	offset      int
	width       int
	height      int

	// source info
	pcapFile    string
	totalSess   int
	pcapBytes   int64
	pcapPackets int

	// proxy
	proxy        *proxy.Proxy
	proxyTracker *session.Tracker
	proxyListen  string
	proxyTarget  string
	sessionChan  chan *session.Session
	stopCh       chan struct{}
	mu           sync.Mutex

	// settings
	aggressive bool
	filterExpr string

	// detail view - navigable
	detailIdx          int
	detailScroll       int
	sessionDetailLines []sessionDetailLine
	detailCursor       int // cursor within cert lines

	// cert detail (drill-down from session detail)
	certDetailNode *TreeNode

	// filter editing
	filterInput textinput.Model

	// dump all confirmation
	dumpDir   string
	dumpCount int
}

func newPacketAnalyzerModel() *packetAnalyzerModel {
	ti := textinput.New()
	ti.Placeholder = ""
	ti.CharLimit = 256
	return &packetAnalyzerModel{
		state:       packetIdle,
		sessionChan: make(chan *session.Session, 64),
		stopCh:      make(chan struct{}),
		filterInput: ti,
	}
}

// --- Status line ---

func (m *packetAnalyzerModel) statusLine() string {
	m.mu.Lock()
	sessCount := len(m.sessions)
	totalCount := len(m.allSessions)
	m.mu.Unlock()

	sessStr := fmt.Sprintf("TLS sessions: %d", sessCount)
	if m.filterExpr != "" && totalCount != sessCount {
		sessStr = fmt.Sprintf("TLS sessions: %d/%d (filtered)", sessCount, totalCount)
	}

	switch {
	case m.state == packetProxyRunning && m.proxy != nil:
		return fmt.Sprintf("[PROXY] %s -> %s | RUNNING | %s | ingress: %s | egress: %s",
			m.proxyListen, m.proxyTarget, sessStr,
			formatBytes(m.proxy.IngressBytes()), formatBytes(m.proxy.EgressBytes()))
	case m.proxyListen != "" && m.state == packetSessions:
		return fmt.Sprintf("[PROXY] %s -> %s | STOPPED | %s",
			m.proxyListen, m.proxyTarget, sessStr)
	case m.pcapFile != "":
		line := fmt.Sprintf("[PCAP] %s | %s", m.pcapFile, sessStr)
		if m.pcapBytes > 0 || m.pcapPackets > 0 {
			line += fmt.Sprintf(" | total traffic: %s / %d pkts", formatBytes(m.pcapBytes), m.pcapPackets)
		}
		return line
	default:
		return "[IDLE] No sessions loaded"
	}
}

// --- Session list view ---

func (m *packetAnalyzerModel) viewSessionList() string {
	var b strings.Builder

	statusStyle := lipgloss.NewStyle().Bold(true)
	b.WriteString(statusStyle.Render("  " + m.statusLine()))
	b.WriteString("\n")

	b.WriteString("\n")

	m.mu.Lock()
	sessions := m.sessions
	m.mu.Unlock()

	if len(sessions) == 0 {
		if m.state == packetProxyRunning {
			b.WriteString("  Waiting for connections...\n")
		} else if m.state == packetIdle {
			b.WriteString("\n  Packet Analyzer\n\n")
			b.WriteString("  Analyze PCAP captures or start a TCP proxy to inspect TLS\n")
			b.WriteString("  handshakes from live or recorded network traffic.\n")
		} else {
			b.WriteString("  No TLS sessions found.\n")
		}
		return b.String()
	}

	headerStyle := lipgloss.NewStyle().Bold(true)
	selectedStyle := lipgloss.NewStyle().Reverse(true)

	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-4s %-20s %-22s %-22s %-9s %-30s %s", "#", "Timestamp", "Source", "Dest", "Version", "Cipher Suite", "SNI")))
	b.WriteString("\n")

	visibleLines := m.height - 7
	if visibleLines < 1 {
		visibleLines = 10
	}

	// Defensive clamp: a stale negative cursor (e.g. after PgDn on a
	// previously-empty list) must never index sessions[-1].
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+visibleLines {
		m.offset = m.cursor - visibleLines + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}

	end := m.offset + visibleLines
	if end > len(sessions) {
		end = len(sessions)
	}

	for i := m.offset; i < end; i++ {
		s := sessions[i]
		ts := "--"
		if !s.StartTime.IsZero() {
			ts = s.StartTime.Format("2006-01-02 15:04:05")
		}
		sni := s.SNI()
		if sni == "" {
			sni = "--"
		}
		status := ""
		if s.Status == session.StatusFailed {
			status = "  FAILED"
		} else if s.Status == session.StatusAborted {
			status = "  ABORTED"
		}
		line := fmt.Sprintf("  %-4d %-20s %-22s %-22s %-9s %-30s %s%s",
			i+1, ts, truncStr(s.ClientAddr, 22), truncStr(s.ServerAddr, 22),
			s.VersionString(), truncStr(s.CipherSuite(), 30), sni, status)

		if i == m.cursor {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// --- Navigable detail view ---

func (m *packetAnalyzerModel) buildDetailLines() {
	m.mu.Lock()
	if m.detailIdx < 0 || m.detailIdx >= len(m.sessions) {
		m.mu.Unlock()
		m.sessionDetailLines = nil
		return
	}
	s := m.sessions[m.detailIdx]
	m.mu.Unlock()

	var lines []sessionDetailLine

	// Use PrintDetail to get the text, then parse it to identify cert lines
	var buf bytes.Buffer
	pktoutput.PrintDetail(&buf, s, m.detailIdx+1)

	rawLines := strings.Split(buf.String(), "\n")

	// Identify certificate lines by pattern matching
	certs := sessionParsedCerts(s)
	for _, raw := range rawLines {
		dl := sessionDetailLine{text: raw, certIndex: -1}

		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "[") {
			for ci, cert := range certs {
				prefix := fmt.Sprintf("[%d] Subject:", ci)
				if strings.HasPrefix(trimmed, prefix) {
					dl.certIndex = ci
					dl.cert = cert
					if !noColor {
						st := lipgloss.NewStyle().Foreground(colorAccent)
						dl.style = &st
					}
					break
				}
			}
		}
		lines = append(lines, dl)
	}
	m.sessionDetailLines = lines
}

func (m *packetAnalyzerModel) viewDetail() string {
	if len(m.sessionDetailLines) == 0 {
		return "  No session selected."
	}

	visibleLines := m.height - 3
	if visibleLines < 1 {
		visibleLines = 10
	}
	if m.detailScroll > len(m.sessionDetailLines)-visibleLines {
		m.detailScroll = len(m.sessionDetailLines) - visibleLines
	}
	if m.detailScroll < 0 {
		m.detailScroll = 0
	}

	end := m.detailScroll + visibleLines
	if end > len(m.sessionDetailLines) {
		end = len(m.sessionDetailLines)
	}

	var b strings.Builder
	for i := m.detailScroll; i < end; i++ {
		dl := m.sessionDetailLines[i]
		if i == m.detailCursor {
			b.WriteString(styleCursorRow.Render(padRight(dl.text, m.width)))
		} else if dl.certIndex >= 0 && dl.style != nil {
			b.WriteString(dl.style.Render(dl.text))
		} else {
			b.WriteString(dl.text)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// --- Dump confirm view ---

func (m *packetAnalyzerModel) viewDumpConfirm() string {
	return fmt.Sprintf("\n  Dump %d certificate chains to %s?\n\n  [Enter] Confirm   [Esc] Cancel\n", m.dumpCount, m.dumpDir)
}

// --- Hint bar ---

func (m *packetAnalyzerModel) hintBar(width int) string {
	hints, status := m.hints()
	bar, _ := RenderHintBar(width, hints, status...)
	return bar
}

func (m *packetAnalyzerModel) hints() ([]Hint, []StatusHint) {
	var hints []Hint
	var status []StatusHint

	switch m.state {
	case packetIdle:
		hints = []Hint{{"o", "Open pcap"}, {"p", "Proxy start"}, {"F", "Functions"}, {"?", "Help"}, {"q", "Quit"}}
	case packetSessions:
		hints = []Hint{{"Enter", "Details"}, {"o", "Open pcap"}, {"p", "Proxy start"}, {"/", "Filter"}, {"D", "Dump all"}, {"C", "Clear"}, {"c", "Copy"}, {"F", "Functions"}, {"?", "Help"}, {"q", "Quit"}}
	case packetProxyRunning:
		hints = []Hint{{"Enter", "Details"}, {"s", "Stop"}, {"C", "Clear"}, {"/", "Filter"}, {"D", "Dump all"}, {"c", "Copy"}, {"?", "Help"}, {"q", "Quit"}}
	case packetDetail:
		hints = []Hint{{"Enter", "Cert detail"}, {"s", "Save cert"}, {"Up/Down", "Navigate"}, {"c", "Copy"}, {"?", "Help"}, {"Esc/q", "Back"}}
	case packetCertDetail:
		hints = []Hint{{"s", "Save"}, {"c", "Copy"}, {"Up/Down", "Scroll"}, {"?", "Help"}, {"Esc/q", "Back"}}
	case packetFilterEdit:
		hints = []Hint{{"Enter", "Apply"}, {"Esc", "Cancel"}}
	}

	if m.filterExpr != "" && m.state != packetFilterEdit {
		m.mu.Lock()
		shown := len(m.sessions)
		total := len(m.allSessions)
		m.mu.Unlock()
		status = append(status, StatusHint{Text: fmt.Sprintf("Filter: %s  %d/%d", m.filterExpr, shown, total)})
	}

	return hints, status
}

// --- Filter modal ---

func (m *packetAnalyzerModel) viewFilterModal() string {
	boxW := 50
	if boxW > m.width-4 {
		boxW = m.width - 4
	}
	if boxW < 30 {
		boxW = 30
	}

	var sb strings.Builder
	sb.WriteString(styleModalTitle.Render("Session Filter"))
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("  Filter: %s\n\n", m.filterInput.View()))
	sb.WriteString(styleFormHelp.Render("  Type to search across IPs, SNI, cipher suite, version"))
	sb.WriteString("\n")
	sb.WriteString("\n")
	sb.WriteString(styleFormHint.Render(FormatHints(Hint{"Enter", "Apply"}, Hint{"Esc", "Cancel"})))

	var border lipgloss.Border
	if noColor {
		border = lipgloss.NormalBorder()
	} else {
		border = lipgloss.RoundedBorder()
	}

	boxStyle := lipgloss.NewStyle().
		Border(border).
		BorderForeground(colorAccent).
		Padding(1, 2).
		Width(boxW - 2)

	box := boxStyle.Render(sb.String())
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

// --- Combined view ---

func (m *packetAnalyzerModel) view() string {
	switch m.state {
	case packetIdle, packetSessions, packetProxyRunning:
		content := m.viewSessionList()
		hintBar := m.hintBar(m.width)
		available := m.height - 1
		contentLines := strings.Count(content, "\n")
		if contentLines < available {
			content += strings.Repeat("\n", available-contentLines)
		}
		return content + "\n" + hintBar
	case packetFilterEdit:
		return m.viewFilterModal()
	case packetDetail:
		content := m.viewDetail()
		hintBar := m.hintBar(m.width)
		return content + "\n" + hintBar
	case packetCertDetail:
		// Rendered by model.go using the existing detail panel
		return ""
	case packetDumpConfirm:
		return m.viewDumpConfirm()
	case packetLoading:
		return "  Analyzing pcap..."
	}
	return ""
}

// --- Proxy lifecycle (channel-based) ---

func (m *packetAnalyzerModel) startProxy() tea.Cmd {
	m.pcapFile = ""
	m.sessions = nil
	m.allSessions = nil
	m.totalSess = 0
	m.cursor = 0
	m.offset = 0
	// Drain any leftover messages from previous proxy
	for len(m.sessionChan) > 0 {
		<-m.sessionChan
	}
	m.stopCh = make(chan struct{})

	return func() tea.Msg {
		px := proxy.New(m.proxyListen, m.proxyTarget)
		px.OnConnection = func(c *tcp.Connection) {
			sessions := m.proxyTracker.ProcessConnections([]*tcp.Connection{c})
			for _, s := range sessions {
				m.mu.Lock()
				m.totalSess++
				m.allSessions = append(m.allSessions, s)
				if !s.MatchesSearch(m.filterExpr) {
					m.mu.Unlock()
					continue
				}
				m.sessions = append(m.sessions, s)
				m.mu.Unlock()
				m.sessionChan <- s
			}
		}
		if err := px.Start(); err != nil {
			return ProxyStartMsg{Err: err}
		}
		return ProxyStartMsg{Proxy: px}
	}
}

func (m *packetAnalyzerModel) waitForSession() tea.Cmd {
	stopCh := m.stopCh
	return func() tea.Msg {
		select {
		case s, ok := <-m.sessionChan:
			if !ok {
				return nil
			}
			return ProxySessionMsg{Session: s}
		case <-stopCh:
			return nil
		}
	}
}

func proxyTick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return proxyTickMsg{}
	})
}

func (m *packetAnalyzerModel) stopProxy() {
	if m.proxy != nil {
		m.proxy.Stop()
		m.proxy = nil
		close(m.stopCh)
	}
	m.state = packetSessions
}

func (m *packetAnalyzerModel) clearSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = nil
	m.allSessions = nil
	m.totalSess = 0
	m.cursor = 0
	m.offset = 0
	m.pcapFile = ""
	m.proxyListen = ""
	m.proxyTarget = ""
	m.state = packetIdle
}

func (m *packetAnalyzerModel) isProxyRunning() bool {
	return m.state == packetProxyRunning
}

func (m *packetAnalyzerModel) restoreListState() packetState {
	if m.proxy != nil {
		return packetProxyRunning
	}
	if len(m.sessions) == 0 && m.pcapFile == "" && m.proxyListen == "" {
		return packetIdle
	}
	return packetSessions
}

func (m *packetAnalyzerModel) refilterSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filterExpr == "" {
		m.sessions = m.allSessions
	} else {
		var filtered []*session.Session
		for _, s := range m.allSessions {
			if s.MatchesSearch(m.filterExpr) {
				filtered = append(filtered, s)
			}
		}
		m.sessions = filtered
	}
	m.cursor = 0
	m.offset = 0
}

// --- Export helpers ---

func (m *packetAnalyzerModel) sessionsWithCerts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, s := range m.sessions {
		if sessionHasCerts(s) {
			count++
		}
	}
	return count
}

func (m *packetAnalyzerModel) dumpAllCerts(dir string) (int, error) {
	m.mu.Lock()
	sessions := m.sessions
	m.mu.Unlock()

	dumped := 0
	names := make(map[string]int)

	for i, s := range sessions {
		certs := sessionParsedCerts(s)
		if len(certs) == 0 {
			continue
		}

		baseName := sessionCertFilename(s, i+1)
		if prev, exists := names[baseName]; exists {
			names[baseName] = prev + 1
			baseName = fmt.Sprintf("%s_%d", baseName, names[baseName])
		} else {
			names[baseName] = 1
		}

		path := filepath.Join(dir, baseName+".pem")
		if err := writeCertsPEM(path, certs); err != nil {
			return dumped, err
		}
		dumped++
	}
	return dumped, nil
}

func sessionCertFilename(s *session.Session, idx int) string {
	name := s.SNI()
	if name == "" {
		name = s.ServerAddr
	}
	certs := sessionParsedCerts(s)
	if len(certs) > 0 && certs[0].Subject.CommonName != "" {
		name = certs[0].Subject.CommonName
	}
	return stringutil.SanitizeFilename(fmt.Sprintf("%d_%s", idx, name))
}

func writeCertsPEM(path string, certs []*x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cert := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

// --- Copy helper ---

func (m *packetAnalyzerModel) copySelectedLine() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.state {
	case packetSessions, packetProxyRunning:
		if m.cursor >= 0 && m.cursor < len(m.sessions) {
			s := m.sessions[m.cursor]
			sni := s.SNI()
			if sni == "" {
				sni = "--"
			}
			return fmt.Sprintf("%s %s %s %s %s %s",
				s.ClientAddr, s.ServerAddr, s.VersionString(), s.CipherSuite(), sni, s.Status.String())
		}
	case packetDetail:
		if m.detailCursor >= 0 && m.detailCursor < len(m.sessionDetailLines) {
			return m.sessionDetailLines[m.detailCursor].text
		}
	}
	return ""
}

// --- Detail navigation helpers ---

func (m *packetAnalyzerModel) detailMoveCursorDown() {
	for i := m.detailCursor + 1; i < len(m.sessionDetailLines); i++ {
		m.detailCursor = i
		break
	}
	// Ensure visible
	visibleLines := m.height - 3
	if visibleLines < 1 {
		visibleLines = 10
	}
	if m.detailCursor >= m.detailScroll+visibleLines {
		m.detailScroll = m.detailCursor - visibleLines + 1
	}
}

func (m *packetAnalyzerModel) detailMoveCursorUp() {
	if m.detailCursor > 0 {
		m.detailCursor--
	}
	if m.detailCursor < m.detailScroll {
		m.detailScroll = m.detailCursor
	}
}

func (m *packetAnalyzerModel) selectedCert() *x509.Certificate {
	if m.detailCursor >= 0 && m.detailCursor < len(m.sessionDetailLines) {
		return m.sessionDetailLines[m.detailCursor].cert
	}
	return nil
}

func (m *packetAnalyzerModel) selectedCertIndex() int {
	if m.detailCursor >= 0 && m.detailCursor < len(m.sessionDetailLines) {
		return m.sessionDetailLines[m.detailCursor].certIndex
	}
	return -1
}

// --- Session cert helpers ---

func sessionParsedCerts(s *session.Session) []*x509.Certificate {
	if s.Certificates == nil {
		return nil
	}
	var certs []*x509.Certificate
	for _, der := range s.Certificates.Certificates {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return certs
}

func sessionHasCerts(s *session.Session) bool {
	return s.Certificates != nil && len(s.Certificates.Certificates) > 0
}

// --- Utility ---

func truncStr(s string, max int) string {
	if ansi.StringWidth(s) <= max {
		return s
	}
	return ansi.Truncate(s, max, "~")
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
