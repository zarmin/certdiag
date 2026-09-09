package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// --- Menu + Form ---

func (m *RootModel) openFunctionsMenu() {
	items := buildFunctionsMenu()
	cursor := 0
	switch m.currentRoot {
	case rootRemoteFetch:
		cursor = 1
	case rootPacketAnalyzer:
		cursor = 2
	case rootTrustStore:
		cursor = 3
	}
	m.prevState = m.state
	m.menu.activate("Functions", items, "", cursor)
	m.state = stateMenu
}

func (m *RootModel) openNewMenu() {
	items := buildNewMenu()
	m.prevState = m.state
	m.menu.activate("New", items, "Tip: For bundling, use multiselect mode [m] first")
	m.state = stateMenu
}

func (m *RootModel) openActionMenu() tea.Cmd {
	if len(m.visible) == 0 || m.tree.cursor >= len(m.visible) {
		return nil
	}
	node := m.visible[m.tree.cursor]
	if needsPassword(node) {
		return m.notify(notifyInfo, "Unlock file first (Enter to enter password)")
	}
	items := buildActionMenu(node)
	if len(items) == 0 {
		return m.notify(notifyInfo, "No actions available")
	}
	m.actionNode = &node
	m.prevState = m.state
	m.menu.activate("Actions", items, "Tip: For bundling, use multiselect mode [m] first")
	m.state = stateMenu
	return nil
}

func (m RootModel) handleMenuKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if isKeyCtrlC(msg) {
		return m, tea.Quit
	}
	selected, done := m.menu.update(msg)
	if !done {
		return m, nil
	}

	m.menu.close()

	if selected == nil {
		m.actionNode = nil
		m.state = m.prevState
		return m, nil
	}

	// Functions menu: switch root views
	switch selected.kind {
	case formNone:
		// Switch to Cert Lister -- always rescan (C12)
		m.currentRoot = rootCertLister
		m.tree.firstColHeader = headerFilename
		m.tree.activeCols = m.tuiOpts.ActiveCols
		m.resetScanContext()
		m.detail = nil
		m.state = stateLoading
		return m, m.startScan()
	case formRemote:
		// Switch to Remote Fetch root view (B1). A result already in hand is
		// shown again rather than thrown away; R asks for a new target.
		if m.remoteHasResult && m.remoteResult != nil {
			m.currentRoot = rootRemoteFetch
			m.detail = nil
			m.rebuildRemoteTree()
			m.state = stateTree
			m.focus = focusTree
			return m, nil
		}
		// openRemoteForm records the root it is opened over, so Esc can return
		// there; switching root comes after.
		m.openRemoteForm()
		m.currentRoot = rootRemoteFetch
		return m, nil
	case formTrustStore:
		cmd := m.openTrustStores()
		return m, cmd
	case formPcapAnalyze:
		// Switch to Packet Analyzer root view
		m.currentRoot = rootPacketAnalyzer
		if m.packetAnalyzer == nil {
			m.packetAnalyzer = newPacketAnalyzerModel()
		}
		m.state = statePacketAnalyzer
		return m, nil
	case formProxySetup:
		m.currentRoot = rootPacketAnalyzer
		if m.packetAnalyzer == nil {
			m.packetAnalyzer = newPacketAnalyzerModel()
		}
		pa := m.packetAnalyzer
		m.activeForm = buildProxyForm(pa.proxyListen, pa.proxyTarget, pa.aggressive)
		m.activeFormKind = formProxySetup
		m.state = statePacketForm
		return m, nil
	}

	form := buildForm(selected.kind, m.scanPath, m.actionNode, m.subjectOrg, m.subjectCountry, m.keyDefaults, m.defaultDays, m.defaultCADays)
	m.actionNode = nil
	if form == nil {
		m.state = m.prevState
		cmd := m.notify(notifyInfo, "Not yet implemented")
		return m, cmd
	}

	if !m.scanOpts.UseSignatureScan {
		form.setExtensionWarning(warnNoSignatureScan)
	}
	form.width = m.width
	form.height = m.height
	m.activeForm = form
	m.activeFormKind = selected.kind
	m.confirmOverwrite = false
	m.confirmDiscard = false
	m.state = stateForm
	return m, nil
}

func (m RootModel) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.confirmOverwrite {
		switch msg.String() {
		case "y", "Y":
			m.confirmOverwrite = false
			m.state = stateLoading
			return m, tea.Batch(m.spinner.Tick, m.submitForm(m.activeFormKind, m.activeForm, true))
		case "n", "N", "esc":
			m.confirmOverwrite = false
			return m, nil
		}
		return m, nil
	}

	if m.confirmDiscard {
		switch msg.String() {
		case "y", "Y":
			m.confirmDiscard = false
			m.activeForm = nil
			m.activeFormKind = formNone
			m.state = m.prevState
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
		m.state = m.prevState
		return m, nil
	}

	if msg.String() == "o" && !m.activeForm.focusedFieldIsTextInput() {
		cmds, err := m.openSSLForForm()
		if err != nil {
			return m, m.notify(notifyError, "openssl equivalent: "+err.Error())
		}
		if len(cmds) == 0 {
			return m, m.notify(notifyNotice, "no openssl equivalent for this form")
		}
		m.popup = openSSLPopup(cmds)
		return m, nil
	}

	submitted, cmd := m.activeForm.update(msg)
	if submitted {
		m.state = stateLoading
		return m, tea.Batch(m.spinner.Tick, m.submitForm(m.activeFormKind, m.activeForm, false))
	}
	return m, cmd
}

func (m *RootModel) submitForm(kind formKind, form *formModel, overwrite bool) tea.Cmd {
	switch kind {
	case formCreateKey:
		return submitCreateKey(form, overwrite)
	case formCreateCert:
		return submitCreateCert(form, m.scanPath, overwrite, m.passwordCache.tagged())
	case formCreateCSR:
		return submitCreateCSR(form, overwrite, m.passwordCache.tagged())
	case formSignCSR:
		return submitSignCSR(form, m.scanPath, overwrite, m.passwordCache.tagged())
	case formConvert:
		return submitConvert(form, overwrite, m.passwordCache.tagged())
	case formRenew:
		return submitRenew(form, m.scanPath, overwrite, m.passwordCache.tagged())
	case formExtract:
		return submitExtract(form, overwrite)
	case formReencrypt:
		return submitReencrypt(form, overwrite, m.passwordCache.tagged())
	case formRemovePassphrase:
		return submitRemovePassphrase(form, overwrite, m.passwordCache.tagged())
	case formBundle:
		return submitBundle(form, overwrite, m.passwordCache.tagged())
	default:
		return func() tea.Msg {
			return FormResultMsg{Err: fmt.Errorf("not implemented")}
		}
	}
}

func (m RootModel) handleFormResult(msg FormResultMsg) (tea.Model, tea.Cmd) {
	if msg.FileExists {
		m.confirmOverwrite = true
		m.state = stateForm
		return m, nil
	}

	if msg.Err != nil {
		m.state = stateForm
		m.notify(notifyError, msg.Err.Error())
		return m, nil
	}

	// Success -- save passwords to cache
	for _, pw := range msg.Passwords {
		m.passwordCache.add(pw)
	}
	if m.activeForm != nil {
		if pw := m.activeForm.getMeta("input_password"); pw != "" {
			m.passwordCache.add([]byte(pw))
		}
	}

	m.activeForm = nil
	m.activeFormKind = formNone
	m.multiSelectActive = false
	m.multiSelect.clear()
	m.resetScanContext()
	m.detail = nil
	m.state = stateLoading
	cmd := m.notify(notifyInfo, msg.Message)
	return m, tea.Batch(m.startScan(), cmd)
}

func (m RootModel) viewMenu() string {
	return m.menu.view(m.width, m.height)
}

func (m RootModel) viewForm() string {
	if m.activeForm == nil {
		return ""
	}
	m.activeForm.width = m.width
	m.activeForm.height = m.height

	var extra string
	if m.confirmOverwrite {
		extra = styleFormError.Render("  File already exists. Overwrite? [y/n]")
	} else if m.confirmDiscard {
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
