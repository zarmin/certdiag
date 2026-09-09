package tui

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

// trustStoreNoisyChecks fires on every CN-only certificate, which is every root
// CA -- hundreds of info issues on a normal machine. Suppressed by default in
// store mode; still toggleable in the check catalog.
var trustStoreNoisyChecks = []string{"missing_sans"}

type TrustStoreLoadedMsg struct {
	Stores   []truststore.StoreContents
	Warnings []string
	Err      error
}

type trustVerifyPickedMsg struct{ path string }
type storeExportPickedMsg struct{ path string }

func (m *RootModel) openTrustStores() tea.Cmd {
	m.currentRoot = rootTrustStore
	m.detail = nil
	m.err = nil
	m.search.filterText = ""

	if len(m.trustStores) > 0 {
		m.rebuildTrustStoreTree()
		m.state = stateTree
		return nil
	}

	m.resetScanContext()
	m.loadingMessage = "Loading trust stores..."
	m.state = stateLoading
	return tea.Batch(m.spinner.Tick, m.trustStoreLoadCmd())
}

func (m RootModel) trustStoreLoadCmd() tea.Cmd {
	loader := m.tuiOpts.TrustStoreLoader
	if loader == nil {
		loader = certops.StoreLoadAll
	}
	opts := certops.StoreLoadAllOptions{
		Passwords:    m.passwordCache.tagged(),
		IncludeFiles: m.tuiOpts.InitialStoreFiles,
		Ctx:          m.scanCtx,
	}

	return func() tea.Msg {
		result, err := loader(opts)
		if err != nil {
			return TrustStoreLoadedMsg{Err: err}
		}
		return TrustStoreLoadedMsg{Stores: result.Stores, Warnings: result.Warnings}
	}
}

func (m RootModel) handleTrustStoreLoaded(msg TrustStoreLoadedMsg) (tea.Model, tea.Cmd) {
	if errors.Is(msg.Err, context.Canceled) {
		// The user pressed Esc: back to the cert lister, no error line.
		m.currentRoot = rootCertLister
		m.tree.firstColHeader = headerFilename
		m.tree.activeCols = m.tuiOpts.ActiveCols
		m.recomputeVisible()
		m.state = stateTree
		return m, m.notify(notifyInfo, "trust store load cancelled")
	}
	if msg.Err != nil {
		m.err = msg.Err
		m.state = stateTree
		return m, nil
	}
	m.err = nil

	m.trustStores = msg.Stores
	m.storeWarnings = msg.Warnings
	m.rebuildTrustStoreTree()
	m.state = stateTree

	if len(msg.Warnings) > 0 {
		return m, m.notify(notifyInfo, fmt.Sprintf("%d store warning(s) -- see group details", len(msg.Warnings)))
	}
	return m, nil
}

// rebuildTrustStoreTree re-synthesizes the tree from the cached store contents.
// It never re-reads a store, so the grouping toggle is instant.
func (m *RootModel) rebuildTrustStoreTree() {
	store := certops.SynthesizeCertStore(m.trustStores, certops.SynthOptions{Grouping: m.storeGrouping})
	m.storePresence = certops.ComputeStorePresence(m.trustStores)

	opts := output.OutputOptions{}
	if store.TotalItems() >= 2 {
		relations := certlib.DetectRelations(store)
		// Mirror a scanned store, where ScanPathWithOptions populates this.
		store.Relations = relations
		opts.RelationIndex = certlib.BuildRelationIndex(relations, store)
		alts := certlib.AssembleChainAlternatives(opts.RelationIndex, store)
		opts.Chains = certlib.FirstChains(alts)
		opts.ChainsContaining = certlib.ChainsContaining(alts)
		opts.Store = store
	}

	m.store = store
	m.opts = m.stampDisplayOpts(opts)
	m.structured = nil
	m.autoRunChecks()

	m.tree.activeCols = m.storeCols
	m.tree.firstColHeader = headerStore
	m.allNodes = ConvertStore(store, opts, m.pathDisplay)
	m.decorateStoreNodes()
	m.recomputeVisible()
	m.tree.cursor = 0
	m.tree.offset = 0
	m.tree.clampCursor(len(m.visible))
}

// decorateStoreNodes fills the store-only columns, which have no equivalent in
// a file scan and so are not produced by ConvertStore.
func (m *RootModel) decorateStoreNodes() {
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.Item == nil || n.Item.Certificate == nil {
			continue
		}
		cert := n.Item.Certificate
		n.Stores = m.storePresence.TagsFor(cert)
		n.StoresInAll = m.storePresence.InAllStores(cert)
		// Everything shown here is in a store, so the baseline verdict is
		// ANCHOR. An explicit trust setting can strengthen that to DENIED. The
		// per-purpose detail stays in the detail pane.
		n.Trust = truststore.VerdictAnchor.Display()
		if t, ok := m.trustLookup(cert); ok {
			n.Trust = truststore.VerdictFromTrustStatus(t.Overall).Display()
			n.TrustPolicies = formatTrustPolicies(t.Policies)
		}
		n.StoreKind = m.storeKindFor(n.ContainerIdx)
		n.Searchable = buildSearchable(*n)
	}
}

func (m *RootModel) trustLookup(cert *x509.Certificate) (truststore.CertTrust, bool) {
	if cert == nil {
		return truststore.CertTrust{}, false
	}
	fp := truststore.CertFingerprint(cert)
	for i := range m.trustStores {
		sc := &m.trustStores[i]
		if sc.TrustMap == nil {
			continue
		}
		if t, ok := sc.TrustMap[fp]; ok {
			return t, true
		}
	}
	return truststore.CertTrust{}, false
}

func (m *RootModel) trustStatusFor(cert *x509.Certificate) truststore.TrustStatus {
	if t, ok := m.trustLookup(cert); ok {
		return t.Overall
	}
	return truststore.TrustUnset
}

func formatTrustPolicies(policies []truststore.TrustPolicy) []string {
	var out []string
	for _, p := range policies {
		out = append(out, fmt.Sprintf("%s: %s", p.Purpose, p.Status))
	}
	return out
}

// storeKindFor reports the store type backing a synthesized container, for the
// detail pane.
func (m *RootModel) storeKindFor(containerIdx int) string {
	if m.store == nil || containerIdx < 0 || containerIdx >= len(m.store.Containers) {
		return ""
	}
	path := m.store.Containers[containerIdx].FilePath
	for i := range m.trustStores {
		if m.trustStores[i].Info.Path == path {
			return string(m.trustStores[i].Info.Type)
		}
	}
	// Kind grouping stores the store type itself as the synthetic path.
	return path
}

func (m *RootModel) toggleStoreGrouping() tea.Cmd {
	m.storeGrouping = m.storeGrouping.Next()
	m.detail = nil
	m.rebuildTrustStoreTree()
	if m.saveStoreOpts != nil {
		_ = m.saveStoreOpts(m.storeCols, string(m.storeGrouping))
	}
	return m.notify(notifyInfo, "Grouped by "+m.storeGrouping.Label())
}

func (m RootModel) inTrustStoreView() bool {
	return m.currentRoot == rootTrustStore
}

// --- Export ---

func (m *RootModel) openStoreExport() tea.Cmd {
	if len(m.visible) == 0 || m.tree.cursor >= len(m.visible) {
		return nil
	}
	node := m.visible[m.tree.cursor]
	if node.Item == nil || node.Item.Certificate == nil {
		return m.notify(notifyInfo, "Select a certificate to export")
	}

	cert := node.Item.Certificate
	m.storeExportCert = cert

	picker := filepicker.New(filepicker.TypeSaveFile).
		WithTitle("Export Certificate").
		WithStartDir(".").
		WithSaveName(certops.CertExportName(cert) + ".pem").
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
		return storeExportPickedMsg{path: path}
	})
}

func (m RootModel) handleStoreExportPicked(msg storeExportPickedMsg) (tea.Model, tea.Cmd) {
	if msg.path == "" || m.storeExportCert == nil {
		return m, nil
	}
	cert := m.storeExportCert
	m.storeExportCert = nil

	if err := certops.ExportCertificate(cert, msg.path, true); err != nil {
		return m, m.notify(notifyError, err.Error())
	}
	return m, m.notify(notifyInfo, "Exported to "+filepath.Base(msg.path))
}

// --- Verify ---

func (m *RootModel) openStoreVerify() tea.Cmd {
	if len(m.visible) == 0 || m.tree.cursor >= len(m.visible) {
		return nil
	}

	picker := filepicker.New(filepicker.TypeOpenFile).
		WithTitle("Verify Certificate Against Store").
		WithStartDir(".")

	return tea.Exec(picker, func(err error) tea.Msg {
		if err != nil {
			return nil
		}
		path, perr := picker.Result()
		if perr != nil || path == "" {
			return nil
		}
		return trustVerifyPickedMsg{path: path}
	})
}

func (m RootModel) handleTrustVerifyPicked(msg trustVerifyPickedMsg) (tea.Model, tea.Cmd) {
	if msg.path == "" {
		return m, nil
	}

	certs, err := certops.ReadCertificatesFromFile(msg.path, m.passwordCache.tagged())
	if err != nil {
		return m, m.notify(notifyError, err.Error())
	}

	info, pool := m.poolForCursorGroup()
	result := truststore.VerifyChain(certs, info, pool, "")

	m.trustVerify = &result
	m.trustVerifyPath = msg.path
	m.state = stateTrustVerify
	return m, nil
}

// poolForCursorGroup builds the verification pool from the store group the
// cursor is in. In kind mode that is the merged, deduplicated set for the kind.
func (m RootModel) poolForCursorGroup() (truststore.StoreInfo, *x509.CertPool) {
	info := truststore.StoreInfo{Type: truststore.StoreTypeOS, Name: "OS Trust Store"}

	if len(m.visible) == 0 || m.tree.cursor >= len(m.visible) {
		return info, nil
	}

	node := m.visible[m.tree.cursor]
	if node.Container == nil {
		return info, nil
	}

	var certs []*x509.Certificate
	for i := range node.Container.Items {
		if c := node.Container.Items[i].Certificate; c != nil {
			certs = append(certs, c)
		}
	}

	info = truststore.StoreInfo{
		Type:      truststore.StoreTypeCustom,
		Name:      node.Container.Label,
		Path:      node.Container.FilePath,
		CertCount: len(certs),
	}
	// Carry the source store's type and warnings across. An NSS profile holds
	// only what was added to it, so an untrusted verdict there is not a fact
	// about the browser; without the warning the result reads as if it were.
	for i := range m.trustStores {
		src := m.trustStores[i].Info
		if src.Name == node.Container.Label || src.Path == node.Container.FilePath {
			info.Type = src.Type
			info.Warnings = src.Warnings
			info.ID = src.ID
			break
		}
	}
	return info, truststore.BuildCertPool(certs)
}

func (m RootModel) handleTrustVerifyKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyEnter(msg):
		// A verified remote endpoint is still a fetched result; Enter goes to
		// it rather than making the user fetch again.
		if m.trustVerifyRemote && m.remoteHasResult {
			m.trustVerify = nil
			m.trustVerifyRemote = false
			m.currentRoot = rootRemoteFetch
			m.rebuildRemoteTree()
			m.state = stateTree
			m.focus = focusTree
			return m, nil
		}
		return m, nil

	case isKeyClose(msg):
		m.trustVerify = nil
		if m.trustVerifyRemote {
			// Verification was started from the trust store view, so that is
			// where Esc belongs, not the Cert Lister.
			m.trustVerifyRemote = false
			m.currentRoot = rootTrustStore
			m.rebuildTrustStoreTree()
		}
		m.state = stateTree
		return m, nil
	}
	return m, nil
}

// --- Verify against a store: file or remote endpoint ---

// openStoreVerifyMenu asks what to verify. Both answers end in the same place:
// a chain checked against the store group under the cursor.
func (m *RootModel) openStoreVerifyMenu() {
	m.menu.activate("Verify Against Store", []menuItem{
		{key: "f", label: "File..."},
		{key: "r", label: "Remote endpoint..."},
	}, "")
	m.prevState = m.state
	m.state = stateVerifyPick
}

func (m RootModel) handleVerifyPickKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if isKeyCtrlC(msg) {
		return m, tea.Quit
	}
	switch msg.String() {
	case "f", "F":
		m.menu.close()
		m.state = m.prevState
		return m, m.openStoreVerify()
	case "r", "R":
		m.menu.close()
		return m.startRemoteVerify()
	}

	selected, done := m.menu.update(msg)
	if !done {
		return m, nil
	}
	m.menu.close()
	if selected == nil {
		m.state = m.prevState
		return m, nil
	}
	if selected.key == "r" {
		return m.startRemoteVerify()
	}
	m.state = m.prevState
	return m, m.openStoreVerify()
}

// startRemoteVerify opens the ordinary remote form, remembering which store the
// answer should be measured against. The form is shared, so proxy, STARTTLS,
// SNI, IP family and timeout all carry over, as does the target history.
func (m RootModel) startRemoteVerify() (tea.Model, tea.Cmd) {
	info, pool := m.poolForCursorGroup()
	if pool == nil {
		m.state = m.prevState
		return m, m.notify(notifyInfo, "This store has no certificates to verify against")
	}
	m.pendingVerifyInfo = info
	m.pendingVerifyPool = pool
	m.pendingVerify = true
	m.openRemoteForm()
	return m, nil
}

// verifyFetchedAgainstPending checks a freshly fetched chain against the store
// the user picked. The hostname is part of the question: a chain valid for
// another name is not a pass.
func (m *RootModel) verifyFetchedAgainstPending(result *certops.FetchRemoteCertResult, hostname string) bool {
	if !m.pendingVerify || result == nil || len(result.TargetResults) == 0 {
		return false
	}
	m.pendingVerify = false

	tr := result.TargetResults[0]
	var certs []*x509.Certificate
	for _, ci := range tr.Certs {
		if ci.Cert != nil && ci.Cert.Certificate != nil {
			certs = append(certs, ci.Cert.Certificate)
		}
	}
	if len(certs) == 0 {
		return false
	}

	if hostname == "" {
		hostname = tr.Target
		if h, _, err := net.SplitHostPort(tr.Target); err == nil {
			hostname = h
		}
	}

	verified := truststore.VerifyChain(certs, m.pendingVerifyInfo, m.pendingVerifyPool, hostname)
	m.trustVerify = &verified
	m.trustVerifyPath = tr.Target
	m.trustVerifyRemote = true
	m.state = stateTrustVerify
	return true
}

// --- Store-mode check options ---

// checkDisabledList merges the user's disabled checks with the store-mode
// suppressions. The user's list is added to, never replaced.
func (m RootModel) checkDisabledList() []string {
	disabled := append([]string{}, m.disabledChecks...)
	if !m.inTrustStoreView() {
		return disabled
	}
	for _, id := range trustStoreNoisyChecks {
		if !hasCheckID(disabled, id) {
			disabled = append(disabled, id)
		}
	}
	return disabled
}

func hasCheckID(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sanitizeStoreCols(cols []string) []string {
	if len(cols) == 0 {
		return defaultStoreCols()
	}
	var out []string
	for _, c := range cols {
		if colSpecByID(c) != nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return defaultStoreCols()
	}
	return out
}

func defaultStoreCols() []string {
	return []string{"subject", "expiry", "algo", "stores"}
}

// --- Key interception ---

// trustStoreKey handles the keys whose meaning differs in the read-only trust
// store view. It reports handled=false for everything else, so the normal tree
// handlers keep working unchanged.
func (m RootModel) trustStoreKey(msg tea.KeyMsg, returnState viewState) (bool, tea.Model, tea.Cmd) {
	readOnlyNode := false
	if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
		readOnlyNode = m.visible[m.tree.cursor].isReadOnlySource()
	}

	// Write actions are suppressed on trust store nodes regardless of the
	// active root view: the guard is on the data, not the screen.
	if readOnlyNode {
		switch {
		case isKeyDelete(msg), isKeyAction(msg), isKeyNew(msg), isKeyMultiSelect(msg), isKeySave(msg):
			return true, m, m.notify(notifyInfo, "Trust stores are read-only")
		}
	}

	if !m.inTrustStoreView() {
		return false, m, nil
	}

	switch {
	case isKeyGrouping(msg):
		cmd := m.toggleStoreGrouping()
		return true, m, cmd

	case isKeyExport(msg):
		cmd := m.openStoreExport()
		return true, m, cmd

	case isKeyVerify(msg):
		m.openStoreVerifyMenu()
		return true, m, nil

	case isKeyRescan(msg):
		m.trustStores = nil
		m.detail = nil
		m.resetScanContext()
		m.loadingMessage = "Loading trust stores..."
		m.state = stateLoading
		return true, m, tea.Batch(m.spinner.Tick, m.trustStoreLoadCmd())
	}

	return false, m, nil
}

// decorateListerNodes fills TRUST and STORES for the Cert Lister, which gets
// its verdicts from the trust index rather than from store membership alone.
func (m *RootModel) decorateListerNodes() {
	if m.trustIndex == nil {
		return
	}
	for i := range m.allNodes {
		n := &m.allNodes[i]
		if n.Item == nil || n.Item.Certificate == nil {
			continue
		}
		cert := n.Item.Certificate
		n.Trust = m.trustIndex.Verdict(cert).Display()
		n.Stores = m.storePresence.TagsFor(cert)
		n.StoresInAll = m.storePresence.InAllStores(cert)
		if anchor := m.trustIndex.AnchorFor(cert); anchor != nil {
			n.TrustPolicies = []string{"Anchor: " + output.FormatSubject(anchor)}
		}
		n.Searchable = buildSearchable(*n)
	}
}

// trustColumnsActive reports whether a column needing trust data is switched on.
func trustColumnsActive(cols []string) bool {
	for _, c := range cols {
		if c == colIDTrust || c == colIDStores {
			return true
		}
	}
	return false
}

// ensureListerTrust loads the trust stores and evaluates the scanned store when
// a trust column is switched on in the Cert Lister. Nothing is loaded until
// then, so a plain browse never pays for reading the OS trust store.
func (m *RootModel) ensureListerTrust() tea.Cmd {
	if m.inTrustStoreView() || m.store == nil {
		return nil
	}
	if !trustColumnsActive(m.tree.activeCols) || m.trustIndex != nil {
		return nil
	}
	if len(m.trustStores) > 0 {
		m.applyListerTrust()
		return nil
	}
	return tea.Batch(m.spinner.Tick, m.listerTrustLoadCmd())
}

func (m RootModel) listerTrustLoadCmd() tea.Cmd {
	loader := m.tuiOpts.TrustStoreLoader
	if loader == nil {
		loader = certops.StoreLoadAll
	}
	opts := certops.StoreLoadAllOptions{
		Passwords:    m.passwordCache.tagged(),
		IncludeFiles: m.tuiOpts.InitialStoreFiles,
		BundleDir:    m.tuiOpts.BundleDir,
	}
	return func() tea.Msg {
		result, err := loader(opts)
		if err != nil {
			return ListerTrustLoadedMsg{Err: err}
		}
		return ListerTrustLoadedMsg{Stores: result.Stores}
	}
}

// ListerTrustLoadedMsg carries the trust stores back to the Cert Lister.
type ListerTrustLoadedMsg struct {
	Stores []truststore.StoreContents
	Err    error
}

func (m RootModel) handleListerTrustLoaded(msg ListerTrustLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.Err != nil {
		return m, m.notify(notifyError, fmt.Sprintf("trust: %v", msg.Err))
	}
	m.trustStores = msg.Stores
	m.applyListerTrust()
	return m, nil
}

// applyListerTrust injects the relevant anchors into the relation graph,
// resolves the verdicts and rebuilds the tree so chains complete up to a root
// the machine trusts.
func (m *RootModel) applyListerTrust() {
	m.storePresence = certops.ComputeStorePresence(m.trustStores)

	if anchors := certops.AnchorContainer(m.store, m.trustStores); anchors != nil {
		m.store.AddContainer(*anchors)
	}

	index, err := certops.EvaluateTrust(certops.TrustEvalOptions{Store: m.store, Stores: m.trustStores})
	if err != nil {
		return
	}
	m.trustIndex = index

	if m.store.TotalItems() >= 2 {
		relations := certlib.DetectRelations(m.store)
		m.opts.RelationIndex = certlib.BuildRelationIndex(relations, m.store)
		alts := certlib.AssembleChainAlternatives(m.opts.RelationIndex, m.store)
		m.opts.Chains = certlib.FirstChains(alts)
		m.opts.ChainsContaining = certlib.ChainsContaining(alts)
		m.opts.Store = m.store
	}

	m.allNodes = ConvertStore(m.store, m.opts, m.pathDisplay)
	m.decorateListerNodes()
	m.recomputeVisible()
	m.tree.clampCursor(len(m.visible))
}
