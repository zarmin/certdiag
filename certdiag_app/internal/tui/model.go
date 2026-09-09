package tui

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/pkg/packet_anal/session"
)

type rootView int

const (
	rootCertLister rootView = iota
	rootRemoteFetch
	rootPacketAnalyzer
	rootTrustStore
)

type viewState int

const (
	stateLoading viewState = iota
	stateTree
	stateSplit
	stateSearch
	statePassword
	stateMenu
	stateForm
	stateMultiSelect
	stateColumnEditor
	stateOptions
	stateCheckView
	stateCheckCatalog
	stateDiff
	stateRemoteForm
	statePacketAnalyzer
	statePacketForm
	stateTrustVerify
	stateVerifyPick
)

const splitScreenMinHeight = 32

type focusPanel int

const (
	focusTree focusPanel = iota
	focusDetail
)

type ScanCompleteMsg struct {
	Store      *certlib.CertStore
	Opts       output.OutputOptions
	Structured *output.StructuredOutput
	Err        error
	Incomplete bool
}

type copyFeedbackClearMsg struct{}
type statusClearMsg struct{ gen int }
type remoteSavePickedMsg struct{ path string }

type UnlockResultMsg struct {
	Unlocked map[int]*certlib.CertContainer
	Password []byte
	Err      error
}

type RootModel struct {
	state  viewState
	width  int
	height int

	tuiOpts TUIOptions

	tree     treeModel
	detail   *detailModel
	search   searchModel
	password passwordModel
	menu     menuModel
	focus    focusPanel
	history  navHistory

	prevState viewState
	// prevRoot is the root view a form was opened over, so leaving the form
	// returns to where the user actually was.
	prevRoot rootView

	activeForm       *formModel
	activeFormKind   formKind
	confirmOverwrite bool
	confirmDiscard   bool
	confirmDelete    bool
	deleteFilePath   string
	deleteFilePaths  []string
	actionNode       *TreeNode

	shellDir  string
	shellFile string
	shellName string

	multiSelect       multiSelectModel
	multiSelectActive bool
	multiSelectReturn viewState

	columnEditor    columnEditorModel
	colEditorReturn viewState
	saveColumns     func(cols []string) error

	optionsEditor optionsModel
	optionsReturn viewState
	saveOptions   func(opts SavedOptions) error
	lockedFlags   map[string]bool

	checkView      checkViewModel
	checkCatalog   *catalogModel
	checkReturn    viewState
	disabledChecks []string

	trustStores   []truststore.StoreContents
	storeGrouping certops.StoreGrouping
	storePresence certops.StorePresence
	trustIndex    *truststore.TrustIndex
	// aiaCache is set only when the user enabled caching; nil means fetched
	// certificates are used for this run and forgotten.
	aiaCache          certlib.AIACache
	storeWarnings     []string
	storeCols         []string
	fingerprintFormat certlib.FingerprintFormat

	trustVerify     *truststore.VerifyResult
	trustVerifyPath string
	// trustVerifyRemote records that the verification came from an endpoint
	// rather than a file, so Esc returns to the trust store view and Enter can
	// open the fetched result.
	trustVerifyRemote bool
	// pendingVerify* carry the store group chosen before the remote form was
	// opened, so the answer is measured against what the user picked.
	pendingVerify     bool
	pendingVerifyInfo truststore.StoreInfo
	pendingVerifyPool *x509.CertPool
	storeExportCert   *x509.Certificate
	saveStoreOpts     func(cols []string, grouping string) error

	remoteResult *certops.FetchRemoteCertResult
	// remoteStore is the served chain as a CertStore, so remote certificates get
	// the same relations, chains and detail rendering a scanned file gets.
	remoteStore    *certlib.CertStore
	remoteLastOpts certops.FetchRemoteCertOptions
	// remoteAIA holds the issuers fetched alongside a remote result, so they
	// are rows of their own rather than an invisible aid to the verdict.
	remoteAIA        *certlib.AIAResult
	remoteOpts       output.OutputOptions
	remoteStructured *output.StructuredOutput
	currentRoot      rootView
	packetAnalyzer   *packetAnalyzerModel
	remoteHasResult  bool

	diffResult    *certlib.DiffResult
	diffDetailed  bool
	diffOnlyDiff  bool
	diffScroll    int
	diffLeftCert  *x509.Certificate
	diffRightCert *x509.Certificate
	diffLeftSrc   certlib.DiffSource
	diffRightSrc  certlib.DiffSource

	store      *certlib.CertStore
	opts       output.OutputOptions
	structured *output.StructuredOutput
	allNodes   []TreeNode
	visible    []TreeNode

	pathDisplay string

	scanPath       string
	scanOpts       certlib.ScanOptions
	discover       bool
	scanCtx        context.Context
	scanCancel     context.CancelFunc
	scanIncomplete bool
	scanProgress   *certlib.ScanProgress
	passwordCache  *passwordCache

	copyFeedback     string
	copyFeedbackTime time.Time

	statusMessage   string
	statusTransient bool
	statusGen       int

	popup         popupState
	confirmAction func(*RootModel) (tea.Model, tea.Cmd)

	spinner        spinner.Model
	loadingMessage string
	err            error
	subjectOrg     string
	subjectCountry string
	keyDefaults    certlib.KeyGenOptions
	defaultDays    int
	defaultCADays  int
	configPath     string
}

func NewRootModel(path string, scanOpts certlib.ScanOptions, discover bool, opts output.OutputOptions, tuiOpts TUIOptions) RootModel {
	initStyles()
	initFormStyles()

	s := spinner.New(spinner.WithSpinner(spinner.Dot))
	if !noColor {
		s.Style = lipgloss.NewStyle().Foreground(colorAccent)
	}

	tree := newTreeModel()
	tree.activeCols = tuiOpts.ActiveCols

	pathDisplay := tuiOpts.PathDisplay
	if pathDisplay == "" {
		pathDisplay = "filename"
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := RootModel{
		state:             stateLoading,
		tree:              tree,
		search:            newSearchModel(),
		password:          newPasswordModel(),
		multiSelect:       newMultiSelectModel(),
		pathDisplay:       pathDisplay,
		scanPath:          path,
		scanOpts:          scanOpts,
		discover:          discover,
		scanCtx:           ctx,
		scanCancel:        cancel,
		scanProgress:      &certlib.ScanProgress{},
		passwordCache:     newPasswordCache(),
		opts:              opts,
		spinner:           s,
		statusMessage:     tuiOpts.StatusMessage,
		subjectOrg:        tuiOpts.SubjectOrg,
		subjectCountry:    tuiOpts.SubjectCountry,
		keyDefaults:       tuiOpts.KeyDefaults,
		defaultDays:       tuiOpts.DefaultDays,
		defaultCADays:     tuiOpts.DefaultCADays,
		configPath:        tuiOpts.ConfigPath,
		saveColumns:       tuiOpts.SaveColumns,
		saveOptions:       tuiOpts.SaveOptions,
		lockedFlags:       tuiOpts.LockedFlags,
		disabledChecks:    tuiOpts.DisabledChecks,
		storeGrouping:     certops.ParseStoreGrouping(tuiOpts.StoreGrouping),
		fingerprintFormat: certlib.ParseFingerprintFormat(tuiOpts.FingerprintFormat),
		storeCols:         sanitizeStoreCols(tuiOpts.StoreCols),
		saveStoreOpts:     tuiOpts.SaveStoreOptions,
	}
	m.tuiOpts = tuiOpts
	m.aiaCache = tuiOpts.AIACache

	if scanOpts.PasswordProvider != nil {
		for _, tp := range scanOpts.PasswordProvider.PasswordsForFile("") {
			m.passwordCache.add(tp.Password)
		}
	}

	if tuiOpts.InitialTrustStore {
		m.currentRoot = rootTrustStore
		m.state = stateLoading
		m.loadingMessage = "Loading trust stores..."
	} else if tuiOpts.InitialPcapFile != "" {
		m.currentRoot = rootPacketAnalyzer
		m.packetAnalyzer = newPacketAnalyzerModel()
		m.packetAnalyzer.aggressive = tuiOpts.InitialPcapAggr
		m.packetAnalyzer.filterExpr = tuiOpts.InitialPcapFilter
		m.packetAnalyzer.state = packetLoading
		m.state = statePacketAnalyzer
	} else if tuiOpts.InitialProxyListen != "" && tuiOpts.InitialProxyTarget != "" {
		m.currentRoot = rootPacketAnalyzer
		m.packetAnalyzer = newPacketAnalyzerModel()
		m.packetAnalyzer.aggressive = tuiOpts.InitialProxyAggr
		m.packetAnalyzer.filterExpr = tuiOpts.InitialProxyFilter
		m.packetAnalyzer.proxyListen = tuiOpts.InitialProxyListen
		m.packetAnalyzer.proxyTarget = tuiOpts.InitialProxyTarget
		m.packetAnalyzer.proxyTracker = &session.Tracker{Aggressive: tuiOpts.InitialProxyAggr}
		m.state = statePacketAnalyzer
	}

	return m
}

func (m RootModel) Init() tea.Cmd {
	if m.tuiOpts.InitialTrustStore {
		return tea.Batch(m.spinner.Tick, m.trustStoreLoadCmd())
	}
	if m.tuiOpts.InitialPcapFile != "" {
		return tea.Batch(m.spinner.Tick, startPcapAnalyze(m.tuiOpts.InitialPcapFile, m.tuiOpts.InitialPcapAggr))
	}
	if m.tuiOpts.InitialProxyListen != "" && m.tuiOpts.InitialProxyTarget != "" {
		return tea.Batch(m.spinner.Tick, m.packetAnalyzer.startProxy())
	}
	return tea.Batch(m.spinner.Tick, m.scanCmd())
}

func (m *RootModel) resetScanContext() {
	ctx, cancel := context.WithCancel(context.Background())
	m.scanCtx = ctx
	m.scanCancel = cancel
	m.scanIncomplete = false
	m.loadingMessage = ""
}

func (m *RootModel) startScan() tea.Cmd {
	m.scanProgress = &certlib.ScanProgress{}
	return tea.Batch(m.spinner.Tick, m.scanCmd())
}

// stampDisplayOpts re-applies the display settings the model owns onto an
// OutputOptions built elsewhere. Scanning and trust store loading both replace
// m.opts wholesale with a value produced in a goroutine that has no access to
// the model, so anything display-related must be stamped back on receipt.
func (m RootModel) stampDisplayOpts(o output.OutputOptions) output.OutputOptions {
	o.FingerprintFormat = m.fingerprintFormat
	return o
}

// detailOutputOptions supplies the display settings the detail pane needs when
// there is no scan-derived OutputOptions to hand (remote and packet views).
func (m RootModel) detailOutputOptions() output.OutputOptions {
	return m.stampDisplayOpts(output.OutputOptions{})
}

func (m *RootModel) recomputeVisible() {
	m.visible = computeVisible(m.allNodes, m.search.filterText)
	m.tree.cachedVisible = m.visible
}

func (m RootModel) scanCmd() tea.Cmd {
	path := m.scanPath
	scanOpts := m.scanOpts
	discover := m.discover
	ctx := m.scanCtx

	scanOpts.Context = ctx
	scanOpts.Progress = m.scanProgress

	if m.passwordCache.len() > 0 {
		scanOpts.PasswordProvider = &savedPasswordProvider{
			base:  scanOpts.PasswordProvider,
			cache: m.passwordCache,
		}
	}

	return func() tea.Msg {
		s, err := certlib.ScanPathWithOptions(path, scanOpts)
		if err != nil && ctx.Err() == nil {
			return ScanCompleteMsg{Err: err}
		}
		store := s
		incomplete := ctx.Err() != nil

		if !incomplete && discover {
			var filePaths []string
			for _, c := range store.Containers {
				filePaths = append(filePaths, c.FilePath)
			}
			siblings, err := certlib.ScanSiblings(filePaths, scanOpts)
			if err == nil {
				for _, c := range siblings.Containers {
					store.AddContainer(c)
				}
			}
		}

		// Re-check after walk/siblings -- cancellation may have arrived during scan
		incomplete = incomplete || ctx.Err() != nil

		opts := output.OutputOptions{Skipped: store.Skipped}
		if !incomplete {
			// The same relation and chain assembly the CLI scan uses.
			analysis := certops.Analyze(store, certops.ScanOptions{AssembleChains: true})
			if analysis.RelIndex != nil {
				opts.RelationIndex = analysis.RelIndex
				opts.Chains = analysis.Chains
				opts.ChainsContaining = analysis.ChainsContaining
				opts.Store = store
			}
		}

		var allContainers []*certlib.CertContainer
		for i := range store.Containers {
			c := &store.Containers[i]
			if !c.RelationsOnly {
				allContainers = append(allContainers, c)
			}
		}

		var structured *output.StructuredOutput
		if !incomplete {
			structured = output.BuildStructuredOutput(allContainers, opts)
		}

		return ScanCompleteMsg{
			Store:      store,
			Opts:       opts,
			Structured: structured,
			Incomplete: incomplete,
		}
	}
}

func (m *RootModel) notify(level notifyLevel, message string) tea.Cmd {
	switch level {
	case notifyNotice:
		m.popup = popupState{kind: popupNotice, message: message}
		return nil
	case notifyError:
		m.popup = popupState{kind: popupError, message: message}
		return nil
	default:
		m.statusMessage = message
		m.statusTransient = true
		m.statusGen++
		gen := m.statusGen
		return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
			return statusClearMsg{gen: gen}
		})
	}
}

func (m RootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.tree.width = msg.Width
		m.updateTreeViewportHeight()
		m.tree.clampCursor(len(m.visible))
		m.checkView.resize(msg.Width, msg.Height)
		if m.checkCatalog != nil {
			m.checkCatalog.resize(msg.Width, msg.Height)
		}
		if m.detail != nil {
			src := m.detail.source
			scroll := m.detail.scrollOffset
			m.detail = newDetailModel(m.detail.node, m.structured, m.store, m.opts, m.width, m.height)
			m.detail.source = src
			m.detail.scrollOffset = scroll
		}
		return m, nil

	case ScanCompleteMsg:
		m.scanProgress = nil
		if msg.Err != nil {
			m.err = msg.Err
			m.state = stateTree
			return m, nil
		}
		m.err = nil // a finished scan supersedes any earlier error line
		m.scanIncomplete = msg.Incomplete
		m.store = msg.Store
		m.opts = m.stampDisplayOpts(msg.Opts)
		m.structured = msg.Structured
		m.autoRunChecks()
		m.allNodes = ConvertStore(msg.Store, m.opts, m.pathDisplay)
		m.recomputeVisible()
		m.tree.clampCursor(len(m.visible))
		m.state = stateTree
		// A trust column carried over from config needs its data loaded before
		// it can render anything.
		return m, m.ensureListerTrust()

	case AIAFetchedMsg:
		return m.handleAIAFetched(msg)

	case TrustStoreLoadedMsg:
		return m.handleTrustStoreLoaded(msg)

	case ListerTrustLoadedMsg:
		return m.handleListerTrustLoaded(msg)

	case storeExportPickedMsg:
		return m.handleStoreExportPicked(msg)

	case trustVerifyPickedMsg:
		return m.handleTrustVerifyPicked(msg)

	case spinner.TickMsg:
		if m.state == stateLoading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case copyFeedbackClearMsg:
		m.copyFeedback = ""
		return m, nil

	case statusClearMsg:
		if m.statusTransient && msg.gen == m.statusGen {
			m.statusMessage = ""
			m.statusTransient = false
		}
		return m, nil

	case UnlockResultMsg:
		return m.handleUnlockResult(msg)

	case FormResultMsg:
		return m.handleFormResult(msg)

	case RemoteFetchResultMsg:
		return m.handleRemoteFetchResult(msg)

	case PcapAnalyzeMsg:
		return m.handlePcapAnalyzeResult(msg)

	case ProxyStartMsg:
		return m.handleProxyStart(msg)

	case ProxySessionMsg:
		// Proxy session arrived -- re-subscribe for the next one
		// Check proxy != nil instead of state, so we keep listening even during menu/search transitions
		if m.packetAnalyzer != nil && m.packetAnalyzer.proxy != nil {
			return m, m.packetAnalyzer.waitForSession()
		}
		return m, nil

	case proxyTickMsg:
		if m.packetAnalyzer != nil && m.packetAnalyzer.proxy != nil {
			return m, proxyTick()
		}
		return m, nil

	case pcapCertSavedMsg:
		if msg.err != nil {
			return m, m.notify(notifyError, fmt.Sprintf("Save failed: %v", msg.err))
		}
		return m, m.notify(notifyInfo, fmt.Sprintf("Saved to %s", msg.path))

	case pcapDumpDirPickedMsg:
		if m.packetAnalyzer != nil {
			pa := m.packetAnalyzer
			pa.dumpDir = msg.dir
			pa.dumpCount = pa.sessionsWithCerts()
			pa.state = packetDumpConfirm
		}
		return m, nil

	case filePickedMsg:
		if m.activeForm != nil {
			m.activeForm.handleFilePicked(msg)
		}
		return m, nil

	case remoteSavePickedMsg:
		return m.handleRemoteSavePicked(msg)

	case remoteSaveAllMsg:
		if msg.err != nil {
			return m, m.notify(notifyError, msg.err.Error())
		}
		return m, m.notify(notifyInfo, fmt.Sprintf("Saved %d file(s)", msg.count))

	case shellExitMsg:
		var exitErr *exec.ExitError
		if msg.err != nil && !errors.As(msg.err, &exitErr) {
			m.notify(notifyError, fmt.Sprintf("shell: %v", msg.err))
			return m, nil
		}
		m.resetScanContext()
		m.state = stateLoading
		return m, m.startScan()

	case tea.KeyMsg:
		if m.popup.kind == popupShell {
			switch msg.String() {
			case "enter":
				m.popup = popupState{}
				dir, file := m.shellDir, m.shellFile
				m.shellDir, m.shellFile, m.shellName = "", "", ""
				return m, m.spawnShell(dir, file)
			default:
				m.popup = popupState{}
				m.shellDir, m.shellFile, m.shellName = "", "", ""
			}
			return m, nil
		}
		if m.popup.kind == popupConfirm {
			switch {
			case msg.String() == "left" || msg.String() == "h" || msg.String() == "shift+tab":
				m.popup.selected = 0
				return m, nil
			case msg.String() == "right" || msg.String() == "l" || msg.String() == "tab":
				m.popup.selected = 1
				return m, nil
			case msg.String() == "y" || msg.String() == "Y":
				m.popup.selected = 0
				fallthrough
			case msg.String() == "enter":
				if m.popup.selected == 0 {
					m.popup = popupState{}
					if m.confirmAction != nil {
						action := m.confirmAction
						m.confirmAction = nil
						return action(&m)
					}
					return m.doDeleteFiles()
				}
				m.popup = popupState{}
				m.confirmAction = nil
				m.deleteFilePaths = nil
				return m, nil
			case msg.String() == "n" || msg.String() == "N" || msg.String() == "esc":
				m.popup = popupState{}
				m.confirmAction = nil
				m.deleteFilePaths = nil
				return m, nil
			}
			return m, nil
		}
		if m.popup.kind == popupCommand {
			switch msg.String() {
			case "c", "y":
				text := m.popup.message
				m.popup = popupState{}
				return m, m.copyToClipboard(text)
			default:
				m.popup = popupState{}
			}
			return m, nil
		}
		if m.popup.kind != popupNone {
			m.popup.kind = updatePopup(msg, m.popup.kind)
			return m, nil
		}
		return m.handleKey(msg)
	}

	if m.state == stateSearch && m.search.active {
		cmd := m.search.update(msg)
		m.recomputeVisible()
		m.tree.clampCursor(len(m.visible))
		return m, cmd
	}

	if m.state == statePassword && m.password.active {
		cmd := m.password.update(msg)
		return m, cmd
	}

	return m, nil
}

func (m RootModel) treeFooterHints() ([]Hint, []StatusHint) {
	var wrapLabel string
	switch m.tree.displayMode {
	case displayTruncate:
		wrapLabel = "Wrap"
	case displayWrap:
		wrapLabel = "HScroll"
	case displayHScroll:
		wrapLabel = "Truncate"
	}
	var hints []Hint
	if m.inTrustStoreView() {
		hints = []Hint{
			{"Enter", "Details"}, {"/", "Search"}, {"W", "Checks"}, {"V", "Verify"},
			{"g", "Grouping"}, {"E", "Export"}, {"F", "Functions"}, {"r", "Reload"},
			{"z", "Fold"}, {"w", wrapLabel}, {"C", "Columns"}, {"O", "Options"}, {"?", "Help"}, {"q", "Quit"},
		}
	} else if m.inRemoteView() {
		hints = []Hint{
			{"Enter", "Details"}, {"/", "Search"}, {"c", "Check"}, {"s", "Save chain"}, {"S", "Save all"},
			{"A", "Fetch AIA"}, {"R", "New remote"}, {"r", "Re-fetch"}, {"F", "Functions"},
			{"z", "Fold"}, {"w", wrapLabel}, {"C", "Columns"}, {"O", "Options"}, {"?", "Help"}, {"q", "Quit"},
		}
	} else {
		hints = []Hint{
			{"Enter", "Details"}, {"/", "Search"}, {"W", "Checks"}, {"n", "New"}, {"a", "Actions"},
			{"F", "Functions"}, {"r", "Rescan"}, {"m", "Multi-select"}, {"z", "Fold"}, {"w", wrapLabel},
			{"A", "Fetch AIA"}, {"C", "Columns"}, {"O", "Options"}, {"Ctrl+D", "Delete"}, {"!", "Shell"},
			{"?", "Help"}, {"q", "Quit"},
		}
	}
	var status []StatusHint
	if m.scanIncomplete {
		status = append(status, StatusHint{"(incomplete scan)"})
	}
	if m.inTrustStoreView() && len(m.storeWarnings) > 0 {
		status = append(status, StatusHint{fmt.Sprintf("%d warning(s)", len(m.storeWarnings))})
	}
	if m.search.filterText != "" {
		status = append(status, StatusHint{fmt.Sprintf("Filter: %s", m.search.filterText)})
	}
	if m.statusMessage != "" {
		status = append(status, StatusHint{m.statusMessage})
	}
	return hints, status
}

func (m *RootModel) updateTreeViewportHeight() {
	hints, status := m.treeFooterHints()
	_, footerH := RenderHintBar(m.width, hints, status...)
	if m.state == stateSplit && m.height >= splitScreenMinHeight {
		// Split mode: tree gets top half minus title/header/infobar
		treeH := m.height / 2
		m.tree.viewportHeight = treeH - 3
	} else {
		// Full tree mode: minus title/header and the actual footer height
		m.tree.viewportHeight = m.height - 2 - footerH
	}
	if m.tree.viewportHeight < 1 {
		m.tree.viewportHeight = 1
	}
}

func (m RootModel) treeTitleLine() string {
	if m.inTrustStoreView() {
		title := fmt.Sprintf("Trust stores - %d loaded, grouped by %s",
			len(m.trustStores), m.storeGrouping.Label())
		maxW := m.width - 2
		if maxW > 0 && runeWidth(title) > maxW {
			title = truncate(title, maxW)
		}
		return title
	}
	abs, _ := filepath.Abs(m.scanPath)
	title := "Certificate list - " + abs
	maxW := m.width - 2
	if maxW > 0 && runeWidth(title) > maxW {
		title = truncate(title, maxW)
	}
	return title
}

func (m RootModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if isKeyHelp(msg) && m.helpAvailable() {
		return m.openHelp()
	}
	switch m.state {
	case stateLoading:
		if isKeyQuit(msg) {
			return m, tea.Quit
		}
		if isKeyEsc(msg) {
			if m.scanCancel != nil {
				m.scanCancel()
			}
			return m, nil
		}
		return m, nil

	case stateTree:
		return m.handleTreeKey(msg)

	case stateSplit:
		return m.handleSplitKey(msg)

	case stateSearch:
		return m.handleSearchKey(msg)

	case statePassword:
		return m.handlePasswordKey(msg)

	case stateMenu:
		return m.handleMenuKey(msg)

	case stateForm:
		return m.handleFormKey(msg)

	case stateMultiSelect:
		return m.handleMultiSelectKey(msg)

	case stateColumnEditor:
		return m.handleColumnEditorKey(msg)

	case stateOptions:
		return m.handleOptionsKey(msg)

	case stateCheckView:
		return m.handleCheckViewKey(msg)

	case stateCheckCatalog:
		return m.handleCheckCatalogKey(msg)

	case stateDiff:
		return m.handleDiffKey(msg)

	case stateRemoteForm:
		return m.handleRemoteFormKey(msg)

	case statePacketAnalyzer:
		return m.handlePacketAnalyzerKey(msg)

	case statePacketForm:
		return m.handlePacketFormKey(msg)

	case stateVerifyPick:
		return m.handleVerifyPickKey(msg)

	case stateTrustVerify:
		return m.handleTrustVerifyKey(msg)
	}

	return m, nil
}

func (m RootModel) handleCheckViewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// When the filter is active, printable characters and backspace edit the
	// filter text and must take precedence over command keys (q/1/2/3/s/?/'/'),
	// otherwise terms like "rsa" or "sha1" can never be typed. Special keys
	// (esc, up/down, enter) fall through to the command switch below.
	if m.checkView.filterActive {
		switch msg.Type {
		case tea.KeyBackspace:
			if len(m.checkView.filterText) > 0 {
				m.checkView.filterText = m.checkView.filterText[:len(m.checkView.filterText)-1]
			}
			m.checkView.applyFilters()
			return m, nil
		case tea.KeySpace:
			// bubbletea delivers a lone space as KeySpace, not KeyRunes; without
			// this case the space key would fall through and be dropped.
			m.checkView.filterText += " "
			m.checkView.applyFilters()
			return m, nil
		case tea.KeyRunes:
			m.checkView.filterText += string(msg.Runes)
			m.checkView.applyFilters()
			return m, nil
		}
	}

	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		if m.checkView.filterActive {
			m.checkView.filterActive = false
			m.checkView.filterText = ""
			m.checkView.applyFilters()
			return m, nil
		}
		m.state = m.checkReturn
		return m, nil

	case isKeyUp(msg):
		if m.checkView.cursor > 0 {
			m.checkView.cursor--
			m.checkView.clampOffset()
		}
		return m, nil

	case isKeyDown(msg):
		if m.checkView.cursor < len(m.checkView.issues)-1 {
			m.checkView.cursor++
			m.checkView.clampOffset()
		}
		return m, nil

	case isKeyEnter(msg):
		if m.checkView.remoteOrigin {
			m.checkView.status = statusRemoteCheckNoNav
			return m, nil
		}
		if len(m.checkView.issues) > 0 && m.checkView.cursor < len(m.checkView.issues) {
			issue := m.checkView.issues[m.checkView.cursor]
			m.navigateToRef(issue.ItemRef)
			m.state = m.checkReturn
		}
		return m, nil

	case msg.String() == "1":
		m.checkView.minSeverity = 0
		m.checkView.applyFilters()
		return m, nil

	case msg.String() == "2":
		m.checkView.minSeverity = 1
		m.checkView.applyFilters()
		return m, nil

	case msg.String() == "3":
		m.checkView.minSeverity = 2
		m.checkView.applyFilters()
		return m, nil

	case msg.String() == "s":
		m.checkView.sortMode = (m.checkView.sortMode + 1) % 3
		m.checkView.applyFilters()
		return m, nil

	case msg.String() == "c":
		cat := newCatalogModel(m.disabledChecks, m.width, m.height)
		m.checkCatalog = &cat
		m.state = stateCheckCatalog
		return m, nil

	case isKeySearch(msg):
		m.checkView.filterActive = true
		m.checkView.filterText = ""
		return m, nil
	}

	return m, nil
}

func (m RootModel) handleCheckCatalogKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit
	case isKeyClose(msg):
		m.checkCatalog = nil
		m.state = stateCheckView
		return m, nil
	case isKeyUp(msg):
		if m.checkCatalog != nil {
			m.checkCatalog.scrollUp()
		}
		return m, nil
	case isKeyDown(msg):
		if m.checkCatalog != nil {
			m.checkCatalog.scrollDown()
		}
		return m, nil
	case isKeyPgUp(msg):
		if m.checkCatalog != nil {
			m.checkCatalog.pageUp()
		}
		return m, nil
	case isKeyPgDown(msg):
		if m.checkCatalog != nil {
			m.checkCatalog.pageDown()
		}
		return m, nil
	}
	return m, nil
}

func (m RootModel) handleTreeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if handled, model, cmd := m.trustStoreKey(msg, stateTree); handled {
		return model, cmd
	}
	if handled, model, cmd := m.remoteKey(msg, stateTree); handled {
		return model, cmd
	}

	if m.confirmDelete {
		switch msg.String() {
		case "y", "Y":
			m.confirmDelete = false
			return m.doDeleteFile()
		default:
			m.confirmDelete = false
			m.deleteFilePath = ""
		}
		return m, nil
	}

	switch {
	case isKeyQuit(msg):
		return m, tea.Quit

	case isKeyUp(msg):
		if m.tree.cursor > 0 {
			m.tree.cursor--
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyDown(msg):
		if m.tree.cursor < len(m.visible)-1 {
			m.tree.cursor++
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgUp(msg):
		m.tree.cursor -= m.tree.viewportHeight
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgDown(msg):
		m.tree.cursor += m.tree.viewportHeight
		if m.tree.cursor >= len(m.visible) {
			m.tree.cursor = len(m.visible) - 1
		}
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyHome(msg):
		m.tree.cursor = 0
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyEnd(msg):
		m.tree.cursor = len(m.visible) - 1
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyExpandAll(msg):
		m.toggleExpandAll()
		return m, nil

	case isKeyFetchAIA(msg):
		return m, m.startAIAFetch()

	case isKeyRight(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset += 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, true)
			}
		}
		return m, nil

	case isKeyLeft(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset -= 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, false)
			} else if node.IsChild {
				for i := m.tree.cursor - 1; i >= 0; i-- {
					if m.visible[i].IsBundle && m.visible[i].ContainerIdx == node.ContainerIdx {
						m.tree.cursor = i
						break
					}
				}
			}
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyEnter(msg):
		if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := m.visible[m.tree.cursor]
			if node.Skipped {
				// A skipped file has no detail; the reason is the whole story.
				return m, m.notify(notifyInfo, node.SkipReason)
			}
			if needsPassword(node) {
				m.prevState = stateTree
				m.state = statePassword
				cmd := m.password.activate(node)
				return m, cmd
			}
			m.openDetail(node)
		}
		return m, nil

	case isKeyNew(msg):
		m.openNewMenu()
		return m, nil

	case isKeyAction(msg):
		cmd := m.openActionMenu()
		return m, cmd

	case isKeyMultiSelect(msg):
		m.multiSelect = newMultiSelectModel()
		m.multiSelectActive = true
		m.multiSelectReturn = stateTree
		m.state = stateMultiSelect
		return m, nil

	case isKeyColumnEditor(msg):
		m.columnEditor = newColumnEditorModel(m.tree.activeCols, m.inTrustStoreView())
		m.colEditorReturn = stateTree
		m.state = stateColumnEditor
		return m, nil

	case isKeyOptions(msg):
		m.optionsEditor = newOptionsModel(m.currentScanSnapshot(), m.lockedFlags)
		m.optionsReturn = stateTree
		m.state = stateOptions
		return m, nil

	case isKeySearch(msg):
		m.state = stateSearch
		cmd := m.search.activate()
		return m, cmd

	case isKeyDelete(msg):
		if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := m.visible[m.tree.cursor]
			if node.Container != nil {
				m.confirmDelete = true
				m.deleteFilePath = node.Container.FilePath
			}
		}
		return m, nil

	case isKeyRescan(msg):
		m.resetScanContext()
		m.detail = nil
		m.state = stateLoading
		return m, m.startScan()

	case msg.String() == "F":
		m.openFunctionsMenu()
		return m, nil

	case isKeyShell(msg):
		m.showShellPopup(m.shellContextFromTree())
		return m, nil

	case isKeyWordWrap(msg):
		switch m.tree.displayMode {
		case displayTruncate:
			m.tree.displayMode = displayWrap
		case displayWrap:
			m.tree.displayMode = displayHScroll
		case displayHScroll:
			m.tree.displayMode = displayTruncate
		}
		m.tree.hScrollOffset = 0
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case msg.String() == "W":
		m.openCheckView()
		return m, nil
	}

	return m, nil
}

func (m *RootModel) autoRunChecks() {
	if m.store == nil {
		return
	}
	checkOpts := certlib.CheckOptions{
		DisabledChecks: m.checkDisabledList(),
	}
	result := certlib.RunChecks(m.store, m.opts.RelationIndex, checkOpts)
	m.opts.CheckResult = result
}

func (m *RootModel) openCheckView() {
	if m.store == nil {
		return
	}
	checkOpts := certlib.CheckOptions{
		DisabledChecks: m.checkDisabledList(),
	}
	result := certlib.RunChecks(m.store, m.opts.RelationIndex, checkOpts)
	m.checkView = newCheckViewModel(result)
	m.checkView.width = m.width
	m.checkView.height = m.height
	m.checkReturn = m.state
	m.state = stateCheckView
}

func (m *RootModel) openDetail(node TreeNode) {
	m.detail = newDetailModel(node, m.structured, m.store, m.opts, m.width, m.height)
	if m.inRemoteView() {
		if tr := m.remoteTargetFor(node.ContainerIdx); tr != nil {
			// The openssl popup renders an s_client command from this.
			m.detail.source = tr.Target
			if node.IsBundle {
				m.detail.contentLines = append(remoteConnectionLines(tr), m.detail.contentLines...)
			}
		}
	}
	m.state = stateSplit
	m.focus = focusDetail
	m.history.clear()
	m.updateTreeViewportHeight()
	m.tree.clampCursor(len(m.visible))
}

func (m *RootModel) toggleExpand(node *TreeNode, expand bool) {
	for i := range m.allNodes {
		if m.allNodes[i].IsBundle && m.allNodes[i].ContainerIdx == node.ContainerIdx {
			m.allNodes[i].Expanded = expand
			break
		}
	}
	m.recomputeVisible()
	m.tree.clampCursor(len(m.visible))
}

// visibleBundleContainers returns the container indices of the bundle rows the
// user can currently see. A search filter narrows it, so folding acts on what is
// on screen and leaves filtered-out containers as they were.
func (m RootModel) visibleBundleContainers() map[int]bool {
	out := make(map[int]bool)
	for _, n := range m.visible {
		if n.IsBundle {
			out[n.ContainerIdx] = true
		}
	}
	return out
}

// expandAll folds or unfolds every visible bundle at once.
func (m *RootModel) expandAll(expand bool) {
	targets := m.visibleBundleContainers()
	if len(targets) == 0 {
		return
	}

	var cursorNode TreeNode
	haveCursor := m.tree.cursor >= 0 && m.tree.cursor < len(m.visible)
	if haveCursor {
		cursorNode = m.visible[m.tree.cursor]
	}

	for i := range m.allNodes {
		if m.allNodes[i].IsBundle && targets[m.allNodes[i].ContainerIdx] {
			m.allNodes[i].Expanded = expand
		}
	}
	m.recomputeVisible()

	if haveCursor {
		m.cursorToNode(cursorNode)
	}
	m.tree.clampCursor(len(m.visible))
	m.tree.clampOffset(len(m.visible))
}

// toggleExpandAll folds everything when anything is unfolded, and unfolds
// everything otherwise.
func (m *RootModel) toggleExpandAll() {
	expand := true
	for _, n := range m.visible {
		if n.IsBundle && n.Expanded {
			expand = false
			break
		}
	}
	m.expandAll(expand)
}

// cursorToNode puts the cursor back on a node after the visible set changed. A
// child row that folded away hands the cursor to its bundle.
func (m *RootModel) cursorToNode(want TreeNode) {
	for i := range m.visible {
		if m.visible[i].ContainerIdx == want.ContainerIdx && m.visible[i].ItemIdx == want.ItemIdx {
			m.tree.cursor = i
			return
		}
	}
	for i := range m.visible {
		if m.visible[i].IsBundle && m.visible[i].ContainerIdx == want.ContainerIdx {
			m.tree.cursor = i
			return
		}
	}
}

func (m RootModel) handleSplitKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if handled, model, cmd := m.trustStoreKey(msg, stateSplit); handled {
		return model, cmd
	}
	if handled, model, cmd := m.remoteKey(msg, stateSplit); handled {
		return model, cmd
	}

	if m.confirmDelete {
		switch msg.String() {
		case "y", "Y":
			m.confirmDelete = false
			return m.doDeleteFile()
		default:
			m.confirmDelete = false
			m.deleteFilePath = ""
		}
		return m, nil
	}

	switch {
	case isKeyCtrlC(msg):
		return m, tea.Quit

	case isKeyClose(msg):
		m.detail = nil
		m.state = stateTree
		m.history.clear()
		m.updateTreeViewportHeight()
		m.tree.clampCursor(len(m.visible))
		return m, nil

	case isKeyTab(msg):
		if m.focus == focusTree {
			m.focus = focusDetail
		} else {
			m.focus = focusTree
		}
		return m, nil

	case isKeyHistoryBack(msg):
		m.navigateBack()
		return m, nil

	case isKeyHistoryForward(msg):
		m.navigateForward()
		return m, nil

	case isKeyNew(msg):
		m.openNewMenu()
		return m, nil

	case isKeyAction(msg):
		cmd := m.openActionMenu()
		return m, cmd

	case isKeyMultiSelect(msg):
		m.multiSelect = newMultiSelectModel()
		m.multiSelectActive = true
		m.multiSelectReturn = stateSplit
		m.state = stateMultiSelect
		return m, nil

	case isKeyColumnEditor(msg):
		m.columnEditor = newColumnEditorModel(m.tree.activeCols, m.inTrustStoreView())
		m.colEditorReturn = stateSplit
		m.state = stateColumnEditor
		return m, nil

	case isKeyOptions(msg):
		m.optionsEditor = newOptionsModel(m.currentScanSnapshot(), m.lockedFlags)
		m.optionsReturn = stateSplit
		m.state = stateOptions
		return m, nil

	case isKeyRescan(msg):
		m.resetScanContext()
		m.detail = nil
		m.state = stateLoading
		return m, m.startScan()

	case isKeySearch(msg):
		m.state = stateSearch
		cmd := m.search.activate()
		return m, cmd

	case msg.String() == "F":
		m.openFunctionsMenu()
		return m, nil

	case isKeyShell(msg):
		m.showShellPopup(m.shellContextFromSplit())
		return m, nil

	case msg.String() == "o":
		return m.showDetailOpenSSL()
	}

	if m.focus == focusTree {
		return m.handleSplitTreeKey(msg)
	}
	return m.handleSplitDetailKey(msg)
}

func (m RootModel) handleSplitTreeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyUp(msg):
		if m.tree.cursor > 0 {
			m.tree.cursor--
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyDown(msg):
		if m.tree.cursor < len(m.visible)-1 {
			m.tree.cursor++
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgUp(msg):
		m.tree.cursor -= m.tree.viewportHeight
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyPgDown(msg):
		m.tree.cursor += m.tree.viewportHeight
		if m.tree.cursor >= len(m.visible) {
			m.tree.cursor = len(m.visible) - 1
		}
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyHome(msg):
		m.tree.cursor = 0
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyEnd(msg):
		m.tree.cursor = len(m.visible) - 1
		if m.tree.cursor < 0 {
			m.tree.cursor = 0
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyExpandAll(msg):
		m.toggleExpandAll()
		return m, nil

	case isKeyFetchAIA(msg):
		return m, m.startAIAFetch()

	case isKeyRight(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset += 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, true)
			}
		}
		return m, nil

	case isKeyLeft(msg):
		if m.tree.displayMode == displayHScroll {
			m.tree.hScrollOffset -= 4
			m.tree.clampHScroll()
		} else if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := &m.visible[m.tree.cursor]
			if node.IsBundle {
				m.toggleExpand(node, false)
			} else if node.IsChild {
				for i := m.tree.cursor - 1; i >= 0; i-- {
					if m.visible[i].IsBundle && m.visible[i].ContainerIdx == node.ContainerIdx {
						m.tree.cursor = i
						break
					}
				}
			}
		}
		m.tree.clampOffset(len(m.visible))
		return m, nil

	case isKeyEnter(msg):
		if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := m.visible[m.tree.cursor]
			if needsPassword(node) {
				m.prevState = stateSplit
				m.state = statePassword
				cmd := m.password.activate(node)
				return m, cmd
			}
			if m.detail != nil {
				m.pushCurrentToHistory()
			}
			m.detail = newDetailModel(node, m.structured, m.store, m.opts, m.width, m.height)
		}
		return m, nil

	case isKeyDelete(msg):
		if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
			node := m.visible[m.tree.cursor]
			if node.Container != nil {
				m.confirmDelete = true
				m.deleteFilePath = node.Container.FilePath
			}
		}
		return m, nil
	}

	return m, nil
}

func (m RootModel) handleSplitDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.detail == nil {
		return m, nil
	}

	detailH := m.detailPanelHeight()

	switch {
	case isKeyDown(msg):
		if m.detail.hasSelectableLines() {
			m.detail.moveCursorDown()
			visLines := m.detail.visibleLines(detailH)
			if m.detail.cursorLine >= 0 {
				m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
			}
		} else {
			m.detail.scrollDown(m.detail.visibleLines(detailH))
		}
		return m, nil

	case isKeyUp(msg):
		if m.detail.hasSelectableLines() {
			m.detail.moveCursorUp()
			visLines := m.detail.visibleLines(detailH)
			if m.detail.cursorLine >= 0 {
				m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
			}
		} else {
			m.detail.scrollUp()
		}
		return m, nil

	case isKeyPgDown(msg):
		if m.detail.hasSelectableLines() {
			visLines := m.detail.visibleLines(detailH)
			for i := 0; i < visLines; i++ {
				m.detail.moveCursorDown()
			}
			if m.detail.cursorLine >= 0 {
				m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
			}
		} else {
			visLines := m.detail.visibleLines(detailH)
			for i := 0; i < visLines; i++ {
				m.detail.scrollDown(visLines)
			}
		}
		return m, nil

	case isKeyPgUp(msg):
		if m.detail.hasSelectableLines() {
			visLines := m.detail.visibleLines(detailH)
			for i := 0; i < visLines; i++ {
				m.detail.moveCursorUp()
			}
			if m.detail.cursorLine >= 0 {
				m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
			}
		} else {
			visLines := m.detail.visibleLines(detailH)
			for i := 0; i < visLines; i++ {
				m.detail.scrollUp()
			}
		}
		return m, nil

	case isKeyHome(msg), msg.String() == "g":
		visLines := m.detail.visibleLines(detailH)
		m.detail.moveCursorFirst()
		m.detail.scrollOffset = 0
		if m.detail.cursorLine >= 0 {
			m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
		}
		return m, nil

	case isKeyEnd(msg), msg.String() == "G":
		visLines := m.detail.visibleLines(detailH)
		m.detail.moveCursorLast()
		if m.detail.cursorLine >= 0 {
			m.detail.ensureLineVisible(m.detail.cursorLine, visLines)
		} else {
			m.detail.scrollToEnd(visLines)
		}
		return m, nil

	case isKeyEnter(msg):
		m.navigateToSelectedRelation()
		return m, nil

	case isKeyCopy(msg):
		return m.copySelectedValue()
	}

	return m, nil
}

func (m *RootModel) copySelectedValue() (tea.Model, tea.Cmd) {
	if clipboard.Unsupported {
		return m, nil
	}
	if m.detail == nil {
		return m, nil
	}
	sel := m.detail.selectedLine()
	if sel == nil {
		return m, nil
	}
	val := sel.value
	if val == "" {
		val = strings.TrimSpace(sel.text)
	}
	if val == "" {
		return m, nil
	}
	err := clipboard.WriteAll(val)
	if err != nil {
		m.copyFeedback = "Copy failed"
	} else {
		m.copyFeedback = "Copied!"
	}
	m.copyFeedbackTime = time.Now()
	return m, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return copyFeedbackClearMsg{}
	})
}

func (m *RootModel) copyToClipboard(text string) tea.Cmd {
	if clipboard.Unsupported {
		return m.notify(notifyError, "Clipboard not supported")
	}
	if err := clipboard.WriteAll(text); err != nil {
		return m.notify(notifyError, "Copy failed")
	}
	return m.notify(notifyInfo, "Copied to clipboard")
}

func (m RootModel) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyEnter(msg):
		m.search.commitAndClose()
		m.recomputeVisible()
		m.tree.clampCursor(len(m.visible))
		if m.detail != nil {
			m.state = stateSplit
		} else {
			m.state = stateTree
		}
		return m, nil

	case isKeyEsc(msg):
		m.search.clearAndClose()
		m.recomputeVisible()
		m.tree.clampCursor(len(m.visible))
		if m.detail != nil {
			m.state = stateSplit
		} else {
			m.state = stateTree
		}
		return m, nil
	}

	cmd := m.search.update(msg)
	m.recomputeVisible()
	m.tree.clampCursor(len(m.visible))
	return m, cmd
}

func (m RootModel) handlePasswordKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case isKeyEnter(msg):
		pw := m.password.value()
		m.password.close()
		m.loadingMessage = "Unlocking..."
		m.state = stateLoading
		return m, tea.Batch(m.spinner.Tick, m.unlockCmd(pw))

	case isKeyEsc(msg):
		m.password.close()
		m.state = m.prevState
		return m, nil
	}

	cmd := m.password.update(msg)
	return m, cmd
}

func (m *RootModel) unlockCmd(pw []byte) tea.Cmd {
	store := m.store
	scanOpts := m.scanOpts
	targetNode := m.password.targetNode
	cachedPasswords := m.passwordCache.tagged()

	return func() tea.Msg {
		unlocked := make(map[int]*certlib.CertContainer)

		// Build password list: new password + cached + provider
		tagged := []certlib.TaggedPassword{{Password: pw, Source: certlib.PasswordSourceInteractive}}
		allPasswords := append(tagged, cachedPasswords...)

		// Try target file first
		targetPasswords := allPasswords
		if scanOpts.PasswordProvider != nil {
			targetPasswords = append(targetPasswords, scanOpts.PasswordProvider.PasswordsForFile(store.Containers[targetNode.ContainerIdx].FilePath)...)
		}
		targetC, err := certlib.ReadFile(store.Containers[targetNode.ContainerIdx].FilePath, targetPasswords)
		if err != nil || certlib.HasPasswordErrors(targetC) {
			return UnlockResultMsg{}
		}
		targetC.RelationsOnly = store.Containers[targetNode.ContainerIdx].RelationsOnly
		unlocked[targetNode.ContainerIdx] = targetC

		// Try same password on all other locked containers
		for ci := range store.Containers {
			if ci == targetNode.ContainerIdx {
				continue
			}
			c := &store.Containers[ci]
			if !certlib.HasPasswordErrors(c) {
				continue
			}

			passwords := allPasswords
			if scanOpts.PasswordProvider != nil {
				passwords = append(passwords, scanOpts.PasswordProvider.PasswordsForFile(c.FilePath)...)
			}

			newC, err := certlib.ReadFile(c.FilePath, passwords)
			if err != nil || certlib.HasPasswordErrors(newC) {
				continue
			}
			newC.RelationsOnly = c.RelationsOnly
			unlocked[ci] = newC
		}

		return UnlockResultMsg{Unlocked: unlocked, Password: pw}
	}
}

func (m RootModel) handleUnlockResult(msg UnlockResultMsg) (tea.Model, tea.Cmd) {
	if len(msg.Unlocked) == 0 {
		if m.detail != nil {
			m.state = stateSplit
		} else {
			m.state = stateTree
		}
		m.notify(notifyError, "wrong password")
		return m, nil
	}

	// Replace containers in-place and save password to cache
	for idx, c := range msg.Unlocked {
		m.store.Containers[idx] = *c
	}
	m.passwordCache.add(msg.Password)

	// Rebuild relations
	totalItems := m.store.TotalItems()
	if totalItems >= 2 {
		relations := certlib.DetectRelations(m.store)
		m.opts.RelationIndex = certlib.BuildRelationIndex(relations, m.store)
		alts := certlib.AssembleChainAlternatives(m.opts.RelationIndex, m.store)
		m.opts.Chains = certlib.FirstChains(alts)
		m.opts.ChainsContaining = certlib.ChainsContaining(alts)
		m.opts.Store = m.store
	}

	// Rebuild structured output
	var allContainers []*certlib.CertContainer
	for i := range m.store.Containers {
		c := &m.store.Containers[i]
		if !c.RelationsOnly {
			allContainers = append(allContainers, c)
		}
	}
	m.structured = output.BuildStructuredOutput(allContainers, m.opts)

	// Rebuild tree nodes
	m.autoRunChecks()
	m.allNodes = ConvertStore(m.store, m.opts, m.pathDisplay)
	m.recomputeVisible()
	m.tree.clampCursor(len(m.visible))

	// Close detail if open (structure changed)
	m.detail = nil

	m.state = stateTree
	cmd := m.notify(notifyInfo, fmt.Sprintf("unlocked %d file(s)", len(msg.Unlocked)))
	return m, cmd
}

func (m *RootModel) doDeleteFile() (tea.Model, tea.Cmd) {
	path := m.deleteFilePath
	m.deleteFilePath = ""
	if err := os.Remove(path); err != nil {
		m.state = stateTree
		m.notify(notifyError, err.Error())
		return m, nil
	}
	m.resetScanContext()
	m.detail = nil
	m.state = stateLoading
	// The status line survives the rescan, so the user sees what happened.
	done := m.notify(notifyInfo, fmt.Sprintf("deleted %s", filepath.Base(path)))
	return m, tea.Batch(m.startScan(), done)
}

func (m *RootModel) doDeleteFiles() (tea.Model, tea.Cmd) {
	paths := m.deleteFilePaths
	m.deleteFilePaths = nil
	for _, p := range paths {
		if err := os.Remove(p); err != nil {
			m.multiSelectActive = false
			m.multiSelect.clear()
			m.state = m.multiSelectReturn
			m.notify(notifyError, err.Error())
			return m, nil
		}
	}
	m.multiSelectActive = false
	m.multiSelect.clear()
	m.resetScanContext()
	m.detail = nil
	m.state = stateLoading
	return m, m.startScan()
}
