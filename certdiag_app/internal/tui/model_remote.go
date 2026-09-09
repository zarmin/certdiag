package tui

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

// --- Remote fetch TUI integration ---

func (m *RootModel) openRemoteForm() {
	form := buildRemoteForm()
	form.width = m.width
	form.height = m.height
	m.activeForm = form
	m.activeFormKind = formRemote
	m.prevState = m.state
	m.prevRoot = m.currentRoot
	m.state = stateRemoteForm
}

func (m RootModel) handleRemoteFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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

	if isKeyCtrlC(msg) {
		return m, tea.Quit
	}

	// Esc always leaves the form. It used to point at F instead, which is not
	// bound here at all, so a form opened with no result behind it - the trust
	// store's verify action, for one - had no way out.
	if isKeyEsc(msg) {
		m.activeForm = nil
		m.activeFormKind = formNone
		return m.leaveRemoteForm()
	}

	submitted, cmd := m.activeForm.update(msg)
	if submitted {
		target := strings.TrimSpace(m.activeForm.fieldValue(fieldKeyTarget))
		m.resetScanContext()
		m.loadingMessage = fmt.Sprintf("Connecting to %s...", target)
		m.state = stateLoading
		return m, tea.Batch(m.spinner.Tick, submitRemoteFetch(m.scanCtx, m.activeForm, m.passwordCache.tagged()))
	}
	return m, cmd
}

func (m RootModel) handleRemoteFetchResult(msg RemoteFetchResultMsg) (tea.Model, tea.Cmd) {
	for _, pw := range msg.Passwords {
		m.passwordCache.add(pw)
	}
	if errors.Is(msg.Err, errFetchCancelled) {
		// Esc during the connect: back to the form, no error dialog.
		m.state = stateRemoteForm
		return m, m.notify(notifyInfo, "connection cancelled")
	}
	if msg.Err != nil {
		m.state = stateRemoteForm
		return m, m.notify(notifyError, msg.Err.Error())
	}
	// A result whose every target failed is a failed connection, not a
	// "Connected" view with an empty bundle (M31 E1): the form stays and the
	// first reason is shown.
	if msg.Result != nil && !anyTargetSucceeded(msg.Result) {
		m.state = stateRemoteForm
		reason := "no certificates received"
		for _, tr := range msg.Result.TargetResults {
			if tr.Error != "" {
				reason = tr.Error
				break
			}
		}
		return m, m.notify(notifyError, reason)
	}

	m.remoteResult = msg.Result
	m.remoteHasResult = true
	m.remoteLastOpts = msg.Opts
	m.activeForm = nil
	m.activeFormKind = formNone
	m.currentRoot = rootRemoteFetch
	m.rebuildRemoteTree()
	m.state = stateTree
	m.focus = focusTree

	// When the fetch was started from the trust store view's verify action, the
	// answer to show is the verdict, not the chain.
	if m.verifyFetchedAgainstPending(msg.Result, msg.Opts.Hostname) {
		return m, nil
	}

	target := ""
	if len(msg.Result.TargetResults) > 0 {
		target = msg.Result.TargetResults[0].Target
	}
	cmd := m.notify(notifyInfo, fmt.Sprintf("Connected to %s", target))
	return m, cmd
}

func (m *RootModel) runRemoteChecks() {
	if m.remoteResult == nil || len(m.remoteResult.TargetResults) == 0 {
		return
	}
	tr := m.remoteResult.TargetResults[0]
	if tr.Error != "" || len(tr.Certs) == 0 {
		return
	}

	var certs []*x509.Certificate
	for _, ci := range tr.Certs {
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			certs = append(certs, ci.Cert.Certificate)
		}
	}

	target, err := certlib.ParseTarget(tr.Target)
	if err != nil {
		target = certlib.RemoteTarget{Host: tr.Target}
	}
	in := certops.CheckTargetInput{
		Target:       target,
		Certificates: certs,
	}
	if tr.TLSInfo != nil {
		in.TLSInfo = *tr.TLSInfo
	}
	// Trust anchors are used only when they are already loaded: pressing c must
	// not go and read the OS store behind the user's back.
	if len(m.trustStores) > 0 {
		in.Roots = certops.OSAnchorPool(m.trustStores)
		in.Stores = m.trustStores
	}

	checkOpts := certlib.CheckOptions{
		DisabledChecks: m.disabledChecks,
	}
	result := certops.CheckFetchedTarget(in, checkOpts)
	m.checkView = newCheckViewModel(result)
	m.checkView.remoteOrigin = true
	m.checkView.width = m.width
	m.checkView.height = m.height
	m.checkReturn = m.state
	m.state = stateCheckView
}

func (m *RootModel) openRemoteSaveForm() tea.Cmd {
	if m.remoteResult == nil || len(m.remoteResult.TargetResults) == 0 {
		return nil
	}
	tr := m.remoteResult.TargetResults[0]
	if tr.Error != "" || len(tr.Certs) == 0 {
		return nil
	}

	defaultName := stringutil.SanitizeFilename(tr.Target) + "_chain.pem"
	picker := filepicker.New(filepicker.TypeSaveFile).
		WithTitle("Save Chain").
		WithStartDir(".").
		WithSaveName(defaultName).
		WithSaveExtensions(extsCertOutput).
		WithFilterOverridable(true).
		WithAllowNewDir(true)

	return tea.Exec(picker, func(err error) tea.Msg {
		if err != nil {
			return nil
		}
		path, perr := picker.Result()
		if perr != nil || path == "" {
			return nil
		}
		return remoteSavePickedMsg{path: path}
	})
}

func (m RootModel) handleRemoteSavePicked(msg remoteSavePickedMsg) (tea.Model, tea.Cmd) {
	if m.remoteResult == nil || len(m.remoteResult.TargetResults) == 0 {
		return m, nil
	}
	tr := m.remoteResult.TargetResults[0]

	var certs []*x509.Certificate
	for _, ci := range tr.Certs {
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			certs = append(certs, ci.Cert.Certificate)
		}
	}

	_, err := certops.SaveRemoteCerts(tr.Target, certs, certops.SaveRemoteOptions{
		SaveTo:    msg.path,
		Overwrite: true,
	})
	if err != nil {
		cmd := m.notify(notifyError, err.Error())
		return m, cmd
	}
	cmd := m.notify(notifyInfo, fmt.Sprintf("Saved chain to %s", filepath.Base(msg.path)))
	return m, cmd
}

func (m *RootModel) openRemoteSaveAll() {
	if m.remoteResult == nil || len(m.remoteResult.TargetResults) == 0 {
		return
	}
	tr := m.remoteResult.TargetResults[0]
	if tr.Error != "" || len(tr.Certs) == 0 {
		return
	}

	sanitized := stringutil.SanitizeFilename(tr.Target)
	var filenames []string
	for i, ci := range tr.Certs {
		cn := "unknown"
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			cn = stringutil.SanitizeFilename(ci.Cert.Certificate.Subject.CommonName)
			if cn == "" {
				cn = "unknown"
			}
		}
		filenames = append(filenames, fmt.Sprintf("%s_%d_%s.pem", sanitized, i+1, cn))
	}

	m.popup = popupState{
		kind:    popupConfirm,
		title:   "Save All Certificates",
		message: fmt.Sprintf("Save %d certificate(s) to current directory?", len(tr.Certs)),
		lines:   filenames,
	}

	target := tr.Target
	var certs []*x509.Certificate
	for _, ci := range tr.Certs {
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			certs = append(certs, ci.Cert.Certificate)
		}
	}
	m.confirmAction = func(cm *RootModel) (tea.Model, tea.Cmd) {
		return *cm, saveRemoteAllCmd(target, certs)
	}
}

type remoteSaveAllMsg struct {
	count int
	err   error
}

func saveRemoteAllCmd(target string, certs []*x509.Certificate) tea.Cmd {
	return func() tea.Msg {
		result, err := certops.SaveRemoteCerts(target, certs, certops.SaveRemoteOptions{
			SaveAll:   true,
			Overwrite: true,
		})
		if err != nil {
			return remoteSaveAllMsg{err: err}
		}
		return remoteSaveAllMsg{count: len(result.SavedFiles)}
	}
}

// rebuildRemoteStore turns the fetch result into a CertStore with relations and
// chains, which is what gives the remote rows and detail their fingerprints,
// relations and chain line.
func (m *RootModel) rebuildRemoteStore() {
	m.remoteStore = certops.RemoteCertStore(m.remoteResult)
	// Issuers fetched over AIA are rows of their own, so the completed chain is
	// visible rather than an invisible aid to the verdict.
	if m.remoteAIA != nil {
		if c := certops.AIAContainer(*m.remoteAIA); c != nil {
			m.remoteStore.AddContainer(*c)
		}
	}
	relations, chains, containing := certops.RemoteStoreChains(m.remoteStore)

	opts := m.detailOutputOptions()
	opts.RelationIndex = relations
	opts.Chains = chains
	opts.ChainsContaining = containing
	opts.Store = m.remoteStore
	m.remoteOpts = opts

	containers := make([]*certlib.CertContainer, 0, len(m.remoteStore.Containers))
	for i := range m.remoteStore.Containers {
		containers = append(containers, &m.remoteStore.Containers[i])
	}
	m.remoteStructured = output.BuildStructuredOutput(containers, opts)
}

// rebuildRemoteTree shows the fetched result on the shared tree, the way the
// trust store view shows a synthesized store. Everything the Cert Lister can do
// - search, columns, wrap, folding, the detail split - then applies to a served
// chain without a line of remote-specific code.
func (m *RootModel) rebuildRemoteTree() {
	m.rebuildRemoteStore()

	m.store = m.remoteStore
	m.opts = m.remoteOpts
	m.structured = m.remoteStructured

	m.tree.activeCols = m.tuiOpts.ActiveCols
	m.tree.firstColHeader = headerRemote
	m.allNodes = ConvertStore(m.remoteStore, m.remoteOpts, m.pathDisplay)
	m.markRemoteChainOutliers()
	m.recomputeVisible()
	m.tree.cursor = 0
	m.tree.offset = 0
	m.tree.clampCursor(len(m.visible))
	m.updateTreeViewportHeight()
}

// inRemoteView reports whether the remote result is the active root view.
func (m RootModel) inRemoteView() bool {
	return m.currentRoot == rootRemoteFetch && m.remoteHasResult
}

// remoteTargetFor maps a container index back to the target it was fetched
// from. The connection metadata lives here, not in the store: certlib must stay
// ignorant of TLS sessions.
func (m RootModel) remoteTargetFor(containerIdx int) *certops.TargetFetchResult {
	if m.remoteResult == nil || containerIdx < 0 || containerIdx >= len(m.remoteResult.TargetResults) {
		return nil
	}
	return &m.remoteResult.TargetResults[containerIdx]
}

// cursorRemoteTarget returns the target the cursor is inside.
func (m RootModel) cursorRemoteTarget() *certops.TargetFetchResult {
	if len(m.visible) == 0 || m.tree.cursor >= len(m.visible) {
		return m.remoteTargetFor(0)
	}
	return m.remoteTargetFor(m.visible[m.tree.cursor].ContainerIdx)
}

func (m RootModel) viewRemoteForm() string {
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

// remoteKey handles the actions that exist only for a fetched remote result. It
// runs before the shared tree handlers, so the keys the remote view has always
// used keep their meaning even where the Cert Lister binds them differently:
// c is Check here, not Copy.
func (m RootModel) remoteKey(msg tea.KeyMsg, returnState viewState) (bool, tea.Model, tea.Cmd) {
	if !m.inRemoteView() {
		return false, m, nil
	}

	switch {
	case isKeySave(msg):
		return true, m, m.openRemoteSaveForm()

	case msg.String() == "S":
		m.openRemoteSaveAll()
		return true, m, nil

	case msg.String() == "c":
		m.runRemoteChecks()
		return true, m, nil

	case msg.String() == "R":
		m.openRemoteForm()
		return true, m, nil

	case isKeyRescan(msg):
		if len(m.remoteLastOpts.Targets) == 0 {
			return true, m, m.notify(notifyInfo, "Nothing to re-fetch; press R for a new target")
		}
		opts := m.remoteLastOpts
		m.detail = nil
		m.loadingMessage = "Fetching " + opts.Targets[0] + "..."
		m.state = stateLoading
		return true, m, tea.Batch(m.spinner.Tick, func() tea.Msg {
			result, err := certops.FetchRemoteCert(opts)
			return RemoteFetchResultMsg{Result: result, Err: err, Opts: opts}
		})

	case isKeyEsc(msg) && returnState == stateTree:
		return true, m, m.notify(notifyInfo, "Use F to switch views, R for new remote")
	}

	return false, m, nil
}

// remoteConnectionLines renders what the old top panel showed: the negotiated
// connection, the resolved addresses and any expiry warning. On the shared tree
// the rows are certificates, so this belongs to the target's own row.
func remoteConnectionLines(tr *certops.TargetFetchResult) []detailLine {
	if tr == nil {
		return nil
	}

	var lines []detailLine
	add := func(label, value string) {
		if value != "" {
			lines = append(lines, detailLine{text: fmt.Sprintf("  %-16s %s", label+":", value), value: value, selectable: true})
		}
	}

	lines = append(lines, detailLine{text: "Connection:"})
	add("Target", tr.Target)
	if tr.Error != "" {
		add("Error", tr.Error)
		return append(lines, detailLine{text: ""})
	}

	if c := tr.Connection; c != nil {
		add("TLS Version", c.TLSVersion)
		add("Cipher Suite", c.CipherSuite)
		add("ALPN", c.ALPN)
		add("SNI", c.SNI)
		add("Remote Address", c.RemoteAddress)
		add("Latency", fmt.Sprintf("%dms", c.LatencyMs))
		staple := "no"
		if c.OCSPStapled {
			staple = "yes"
		}
		add("OCSP Stapled", staple)
	}

	if tr.MultiIP != nil && len(tr.MultiIP.ResolvedIPs) > 0 {
		add("Resolved IPs", strings.Join(tr.MultiIP.ResolvedIPs, ", "))
		if !tr.MultiIP.AllIdentical {
			add("Chains", "DIFFERENT chains across IPs")
		}
	}

	if tr.ExpiryWarn != nil && len(tr.ExpiryWarn.ExpiringCerts) > 0 {
		lines = append(lines, detailLine{text: ""}, detailLine{text: "Expiry warnings:"})
		for _, ec := range tr.ExpiryWarn.ExpiringCerts {
			status := "expiring"
			if ec.Expired {
				status = "EXPIRED"
			}
			add(status, fmt.Sprintf("%s (%s)", ec.Subject, ec.NotAfter.Format("2006-01-02")))
		}
	}

	return append(lines, detailLine{text: ""})
}

// certToTreeNode wraps a bare certificate as a tree row. The packet analyzer
// uses it for certificates recovered from a capture, which have no container.
func certToTreeNode(cert *x509.Certificate, role string) TreeNode {
	subject := cert.Subject.CommonName
	if subject == "" {
		subject = cert.Subject.String()
	}
	filename := subject
	if role != "" {
		filename = fmt.Sprintf("[%s] %s", role, subject)
	}

	return TreeNode{
		Filename:    filename,
		Subject:     subject,
		Issuer:      cert.Issuer.CommonName,
		ContentType: string(certlib.ContentCertificate),
		Expiry:      cert.NotAfter.Format("2006-01-02"),
		ExpiryTime:  cert.NotAfter,
		Container:   &certlib.CertContainer{FilePath: "(remote)"},
		Item: &certlib.CertItem{
			Type:        certlib.ContentCertificate,
			Certificate: cert,
			RawBytes:    cert.Raw,
		},
	}
}

// markRemoteChainOutliers flags served certificates that lie on no path from
// the leaf. A server can send a stale intermediate or an unrelated certificate
// and still look correct in a listing; saying so on the row is the whole point
// of showing a served chain as a tree.
func (m *RootModel) markRemoteChainOutliers() {
	if m.remoteStore == nil {
		return
	}

	for ci := range m.remoteStore.Containers {
		c := &m.remoteStore.Containers[ci]
		if len(c.Items) < 2 {
			continue
		}
		certs := make([]*x509.Certificate, 0, len(c.Items))
		for i := range c.Items {
			certs = append(certs, c.Items[i].Certificate)
		}
		onPath := make(map[int]bool)
		for _, idx := range certlib.ServedChainPath(certs) {
			onPath[idx] = true
		}

		for i := range m.allNodes {
			n := &m.allNodes[i]
			if n.ContainerIdx != ci || n.ItemIdx < 0 || onPath[n.ItemIdx] {
				continue
			}
			n.Warnings = append(n.Warnings, "not in chain: served but on no path from the leaf")
			n.Searchable = buildSearchable(*n)
		}
	}
}

// leaveRemoteForm returns to whatever the form was opened over: the fetched
// result if there is one, otherwise the root view the user came from.
func (m RootModel) leaveRemoteForm() (tea.Model, tea.Cmd) {
	if m.pendingVerify {
		// A cancelled store verification goes back to the store it started
		// from, not to a remote view the user never asked for.
		m.pendingVerify = false
		m.pendingVerifyPool = nil
		m.currentRoot = m.prevRoot
		m.state = stateTree
		m.focus = focusTree
		return m, m.notify(notifyInfo, "Verification cancelled")
	}

	if m.remoteHasResult && m.remoteResult != nil {
		m.currentRoot = rootRemoteFetch
		m.rebuildRemoteTree()
		m.state = stateTree
		m.focus = focusTree
		return m, nil
	}

	m.currentRoot = m.prevRoot
	m.focus = focusTree
	switch m.prevState {
	case stateRemoteForm, stateLoading, stateMenu:
		// Nothing to return to; the tree is always somewhere to stand.
		m.state = stateTree
	default:
		m.state = m.prevState
	}
	return m, nil
}

// anyTargetSucceeded reports whether at least one target served a chain.
func anyTargetSucceeded(result *certops.FetchRemoteCertResult) bool {
	for _, tr := range result.TargetResults {
		if tr.Error == "" && len(tr.Certs) > 0 {
			return true
		}
	}
	return false
}
