package tui

import (
	"crypto/x509"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

// --- Packet Analyzer handlers ---

func (m RootModel) handlePcapAnalyzeResult(msg PcapAnalyzeMsg) (tea.Model, tea.Cmd) {
	if m.packetAnalyzer == nil {
		return m, nil
	}
	if msg.Err != nil {
		m.packetAnalyzer.state = packetIdle
		m.notify(notifyError, msg.Err.Error())
		return m, nil
	}
	pa := m.packetAnalyzer
	pa.allSessions = msg.Result.AllSessions
	pa.totalSess = msg.Result.Total
	pa.pcapFile = msg.Result.PcapFile
	pa.pcapBytes = msg.Result.TotalBytes
	pa.pcapPackets = msg.Result.Packets
	pa.refilterSessions()
	pa.state = packetSessions
	return m, nil
}

func (m RootModel) handleProxyStart(msg ProxyStartMsg) (tea.Model, tea.Cmd) {
	if m.packetAnalyzer == nil {
		return m, nil
	}
	if msg.Err != nil {
		if m.activeForm != nil && m.activeFormKind == formProxySetup {
			m.state = statePacketForm
		} else {
			m.packetAnalyzer.state = packetIdle
		}
		return m, m.notify(notifyError, msg.Err.Error())
	}
	m.activeForm = nil
	m.activeFormKind = formNone
	m.packetAnalyzer.proxy = msg.Proxy
	m.packetAnalyzer.state = packetProxyRunning
	m.state = statePacketAnalyzer
	return m, tea.Batch(m.packetAnalyzer.waitForSession(), proxyTick())
}

func (m RootModel) handlePacketAnalyzerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer
	if pa == nil {
		return m, nil
	}

	switch pa.state {
	case packetDetail:
		return m.handleSessionDetailKey(msg)
	case packetCertDetail:
		return m.handleSessionCertDetailKey(msg)
	case packetFilterEdit:
		return m.handleFilterEditKey(msg)
	case packetDumpConfirm:
		return m.handleDumpConfirmKey(msg)
	case packetLoading:
		if isKeyQuit(msg) {
			return m, tea.Quit
		}
		return m, nil
	}

	// Session list / idle / proxy running states
	switch {
	case isKeyQuit(msg):
		if pa.isProxyRunning() {
			pa.stopProxy()
		}
		return m, tea.Quit

	case isKeyEsc(msg):
		// C5: Show transient hint
		return m, m.notify(notifyInfo, "Use F to switch views")

	case msg.String() == "F":
		if pa.isProxyRunning() {
			return m, m.notify(notifyInfo, "Stop the proxy first (press s)")
		}
		m.openFunctionsMenu()
		return m, nil

	case msg.String() == "o":
		if pa.isProxyRunning() {
			return m, nil
		}
		m.activeForm = buildPcapForm(m.scanPath, pa.aggressive)
		m.activeFormKind = formPcapAnalyze
		m.state = statePacketForm
		return m, nil

	case msg.String() == "p":
		if pa.isProxyRunning() {
			return m, nil
		}
		m.activeForm = buildProxyForm(pa.proxyListen, pa.proxyTarget, pa.aggressive)
		m.activeFormKind = formProxySetup
		m.state = statePacketForm
		return m, nil

	case msg.String() == "s" && pa.isProxyRunning():
		pa.stopProxy()
		return m, nil

	case msg.String() == "C": // C11: uppercase C for Clear
		if pa.isProxyRunning() {
			pa.mu.Lock()
			pa.sessions = nil
			pa.allSessions = nil
			pa.totalSess = 0
			pa.cursor = 0
			pa.offset = 0
			pa.mu.Unlock()
		} else {
			pa.clearSessions()
		}
		return m, nil

	case msg.String() == "c": // C11: lowercase c for Copy
		text := pa.copySelectedLine()
		if text != "" {
			return m, m.copyToClipboard(text)
		}
		return m, nil

	case msg.String() == "/": // C6: Filter editing
		pa.filterInput.SetValue(pa.filterExpr)
		pa.filterInput.Focus()
		pa.state = packetFilterEdit
		return m, nil

	case msg.String() == "D": // C9: Dump all with confirmation
		count := pa.sessionsWithCerts()
		if count == 0 {
			return m, m.notify(notifyError, "No certificates to dump")
		}
		return m, m.openDumpDirPicker()

	case isKeyEnter(msg):
		pa.mu.Lock()
		sessCount := len(pa.sessions)
		pa.mu.Unlock()
		if sessCount > 0 && pa.cursor < sessCount {
			pa.detailIdx = pa.cursor
			pa.detailScroll = 0
			pa.detailCursor = 0
			pa.buildDetailLines()
			pa.state = packetDetail
		}
		return m, nil

	case isKeyUp(msg):
		if pa.cursor > 0 {
			pa.cursor--
		}
	case isKeyDown(msg):
		pa.mu.Lock()
		max := len(pa.sessions) - 1
		pa.mu.Unlock()
		if pa.cursor < max {
			pa.cursor++
		}
	case isKeyPgUp(msg):
		pa.cursor -= 10
		if pa.cursor < 0 {
			pa.cursor = 0
		}
	case isKeyPgDown(msg):
		pa.mu.Lock()
		max := len(pa.sessions) - 1
		pa.mu.Unlock()
		pa.cursor += 10
		if max < 0 {
			pa.cursor = 0
		} else if pa.cursor > max {
			pa.cursor = max
		}
	}
	return m, nil
}

// C7: Navigable session detail
func (m RootModel) handleSessionDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit
	case isKeyClose(msg):
		if pa.proxy != nil {
			pa.state = packetProxyRunning
		} else {
			pa.state = packetSessions
		}
		return m, nil
	case isKeyEnter(msg):
		// Enter on cert line opens cert detail
		cert := pa.selectedCert()
		if cert != nil {
			node := certToTreeNode(cert, "")
			pa.certDetailNode = &node
			m.detail = newDetailModel(node, nil, nil, m.detailOutputOptions(), m.width, m.height)
			pa.state = packetCertDetail
		}
		return m, nil
	case msg.String() == "s":
		// C8: Save individual cert
		cert := pa.selectedCert()
		if cert != nil {
			return m, m.openSessionCertSavePicker(pa.detailIdx, pa.selectedCertIndex(), cert)
		}
		return m, nil
	case msg.String() == "c":
		text := pa.copySelectedLine()
		if text != "" {
			return m, m.copyToClipboard(text)
		}
		return m, nil
	case isKeyUp(msg):
		pa.detailMoveCursorUp()
	case isKeyDown(msg):
		pa.detailMoveCursorDown()
	case isKeyPgUp(msg):
		for i := 0; i < 10; i++ {
			pa.detailMoveCursorUp()
		}
	case isKeyPgDown(msg):
		for i := 0; i < 10; i++ {
			pa.detailMoveCursorDown()
		}
	}
	return m, nil
}

// Cert detail from session drill-down
func (m RootModel) handleSessionCertDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit
	case isKeyClose(msg):
		pa.certDetailNode = nil
		m.detail = nil
		pa.state = packetDetail
		return m, nil
	case msg.String() == "s":
		if pa.certDetailNode != nil && pa.certDetailNode.Item != nil && pa.certDetailNode.Item.Certificate != nil {
			cert := pa.certDetailNode.Item.Certificate
			return m, m.openSessionCertSavePicker(pa.detailIdx, -1, cert)
		}
		return m, nil
	case msg.String() == "c":
		if m.detail != nil {
			line := m.detail.selectedLine()
			if line != nil {
				text := line.value
				if text == "" {
					text = line.text
				}
				return m, m.copyToClipboard(text)
			}
		}
		return m, nil
	case isKeyUp(msg):
		if m.detail != nil {
			detailH := m.height - 2
			if m.detail.hasSelectableLines() {
				m.detail.moveCursorUp()
				if m.detail.cursorLine >= 0 {
					m.detail.ensureLineVisible(m.detail.cursorLine, m.detail.visibleLines(detailH))
				}
			} else {
				m.detail.scrollUp()
			}
		}
	case isKeyDown(msg):
		if m.detail != nil {
			detailH := m.height - 2
			if m.detail.hasSelectableLines() {
				m.detail.moveCursorDown()
				if m.detail.cursorLine >= 0 {
					m.detail.ensureLineVisible(m.detail.cursorLine, m.detail.visibleLines(detailH))
				}
			} else {
				m.detail.scrollDown(m.detail.visibleLines(detailH))
			}
		}
	case isKeyPgUp(msg):
		if m.detail != nil {
			detailH := m.height - 2
			visLines := m.detail.visibleLines(detailH)
			if m.detail.hasSelectableLines() {
				for i := 0; i < visLines; i++ {
					m.detail.moveCursorUp()
				}
				if m.detail.cursorLine >= 0 {
					m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
				}
			} else {
				for i := 0; i < 10; i++ {
					m.detail.scrollUp()
				}
			}
		}
	case isKeyPgDown(msg):
		if m.detail != nil {
			detailH := m.height - 2
			visLines := m.detail.visibleLines(detailH)
			if m.detail.hasSelectableLines() {
				for i := 0; i < visLines; i++ {
					m.detail.moveCursorDown()
				}
				if m.detail.cursorLine >= 0 {
					m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
				}
			} else {
				for i := 0; i < 10; i++ {
					m.detail.scrollDown(visLines)
				}
			}
		}
	}
	return m, nil
}

// C6: Filter editing
func (m RootModel) handleFilterEditKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer
	switch {
	case isKeyEsc(msg):
		pa.filterInput.Blur()
		pa.state = pa.restoreListState()
		return m, nil
	case isKeyEnter(msg):
		pa.filterExpr = pa.filterInput.Value()
		pa.filterInput.Blur()
		pa.refilterSessions()
		pa.state = pa.restoreListState()
		return m, nil
	}
	var cmd tea.Cmd
	pa.filterInput, cmd = pa.filterInput.Update(msg)
	return m, cmd
}

// Packet form key handler (proxy setup / pcap open)
func (m RootModel) handlePacketFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if isKeyCtrlC(msg) {
		return m, tea.Quit
	}

	if m.confirmDiscard {
		switch msg.String() {
		case "y", "Y":
			m.confirmDiscard = false
			m.activeForm = nil
			m.activeFormKind = formNone
			m.state = statePacketAnalyzer
		case "n", "N", "esc":
			m.confirmDiscard = false
		}
		return m, nil
	}

	if isKeyEsc(msg) {
		if m.activeForm != nil && m.activeForm.isDirty() {
			m.confirmDiscard = true
			return m, nil
		}
		m.activeForm = nil
		m.activeFormKind = formNone
		m.state = statePacketAnalyzer
		return m, nil
	}

	submitted, cmd := m.activeForm.update(msg)
	if submitted {
		return m.submitPacketForm()
	}
	return m, cmd
}

func (m RootModel) submitPacketForm() (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer

	switch m.activeFormKind {
	case formProxySetup:
		listen := strings.TrimSpace(m.activeForm.fieldValue(fieldKeyProxyListen))
		target := strings.TrimSpace(m.activeForm.fieldValue(fieldKeyProxyTarget))
		aggressive := m.activeForm.fieldValue(fieldKeyProxyAggressive) == "true"

		pa.proxyListen = listen
		pa.proxyTarget = target
		pa.aggressive = aggressive
		pa.proxyTracker = &session.Tracker{Aggressive: aggressive}
		pa.sessions = nil
		pa.allSessions = nil
		pa.totalSess = 0
		pa.cursor = 0
		pa.offset = 0
		// Keep form alive for error recovery -- handleProxyStart clears it on success
		m.state = statePacketAnalyzer
		return m, pa.startProxy()

	case formPcapAnalyze:
		file := strings.TrimSpace(m.activeForm.fieldValue(fieldKeyPcapFile))
		aggressive := m.activeForm.fieldValue(fieldKeyPcapAggressive) == "true"

		if file == "" {
			return m, m.notify(notifyInfo, "Select a pcap file first")
		}
		pa.aggressive = aggressive
		pa.pcapFile = file
		pa.state = packetLoading
		pa.sessions = nil
		pa.allSessions = nil
		m.activeForm = nil
		m.activeFormKind = formNone
		m.state = statePacketAnalyzer
		return m, startPcapAnalyze(file, aggressive)
	}

	return m, nil
}

func (m RootModel) viewPacketForm() string {
	if m.activeForm == nil {
		return ""
	}
	m.activeForm.width = m.width
	m.activeForm.height = m.height

	var extra string
	if m.confirmDiscard {
		extra = styleFormError.Render("  Discard changes? [y/n]")
	} else if m.statusMessage != "" {
		extra = styleInfoBar.Render("  " + m.statusMessage)
	}

	if extra != "" {
		m.activeForm.height = m.height - 1
		return m.activeForm.view() + extra
	}
	return m.activeForm.view()
}

// C9: Dump all confirmation
func (m RootModel) handleDumpConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	pa := m.packetAnalyzer
	switch {
	case isKeyEsc(msg):
		pa.dumpDir = ""
		pa.dumpCount = 0
		pa.state = pa.restoreListState()
		return m, nil
	case isKeyEnter(msg):
		dir := pa.dumpDir
		pa.state = pa.restoreListState()
		dumped, err := pa.dumpAllCerts(dir)
		pa.dumpDir = ""
		pa.dumpCount = 0
		if err != nil {
			return m, m.notify(notifyError, fmt.Sprintf("Dump failed: %v", err))
		}
		return m, m.notify(notifyInfo, fmt.Sprintf("Dumped %d certificate chains to %s", dumped, dir))
	}
	return m, nil
}

// C8: Save individual cert from session detail
func (m RootModel) openSessionCertSavePicker(sessIdx, certIdx int, cert *x509.Certificate) tea.Cmd {
	name := stringutil.SanitizeFilename(fmt.Sprintf("%d_%s", sessIdx+1, cert.Subject.CommonName))
	if name == fmt.Sprintf("%d_", sessIdx+1) {
		name = fmt.Sprintf("%d_cert", sessIdx+1)
	}
	name += ".pem"

	picker := filepicker.New(filepicker.TypeSaveFile).
		WithTitle("Save certificate").
		WithStartDir(scanDir(m.scanPath)).
		WithBookmarks(scanPathBookmark(m.scanPath)).
		WithSaveName(name)

	rawCert := cert
	return tea.Exec(picker, func(err error) tea.Msg {
		if err != nil {
			return nil
		}
		path, perr := picker.Result()
		if perr != nil || path == "" {
			return nil
		}
		// Write the cert directly
		if werr := writeCertsPEM(path, []*x509.Certificate{rawCert}); werr != nil {
			return pcapCertSavedMsg{path: path, err: werr}
		}
		return pcapCertSavedMsg{path: path}
	})
}

type pcapCertSavedMsg struct {
	path string
	err  error
}

// C9: Open directory picker for dump all
func (m RootModel) openDumpDirPicker() tea.Cmd {
	picker := filepicker.New(filepicker.TypeOpenDir).
		WithTitle("Select dump directory").
		WithStartDir(scanDir(m.scanPath)).
		WithBookmarks(scanPathBookmark(m.scanPath)).
		WithAllowNewDir(true)

	return tea.Exec(picker, func(err error) tea.Msg {
		if err != nil {
			return nil
		}
		path, perr := picker.Result()
		if perr != nil || path == "" {
			return nil
		}
		return pcapDumpDirPickedMsg{dir: path}
	})
}

type pcapDumpDirPickedMsg struct{ dir string }
