package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// Fetching the issuers a scan is missing, on request.
//
// AIA reaches the network, so it never happens on its own: the user presses A.
// What comes back is added as ordinary rows, so the fetched cross-signed root
// can be inspected, related and saved next to the chain that needed it.

// AIAFetchedMsg carries the result of a chase back to the model.
type AIAFetchedMsg struct {
	Result certlib.AIAResult
	Err    error
}

// aiaFetchCmd chases AIA for every certificate in the current scan.
func (m RootModel) aiaFetchCmd() tea.Cmd {
	if m.store == nil {
		return nil
	}

	opts := certlib.AIAOptions{Ctx: m.scanCtx}
	if m.aiaCache != nil {
		opts.Cache = m.aiaCache
	}
	subjects := certops.StoreCertificates(m.store)

	return func() tea.Msg {
		return AIAFetchedMsg{Result: certlib.ChaseAIA(subjects, opts)}
	}
}

// startAIAFetch puts the model into the loading state while the fetch runs.
func (m *RootModel) startAIAFetch() tea.Cmd {
	if m.inTrustStoreView() {
		// A trust store is the answer, not a chain with something missing.
		// Chasing from its certificates would fetch on behalf of anchors.
		return m.notify(notifyInfo, "AIA applies to scanned and served chains, not to a trust store")
	}
	if m.store == nil || m.store.TotalItems() == 0 {
		return m.notify(notifyInfo, "Nothing to fetch issuers for")
	}
	msg := "Fetching AIA certificates..."
	if m.aiaCache == nil {
		// Worth saying once, at the moment the wait is visible.
		msg += " (enable defaults.aia.cache to keep them)"
	}
	m.loadingMessage = msg
	m.detail = nil
	m.state = stateLoading
	return tea.Batch(m.spinner.Tick, m.aiaFetchCmd())
}

// handleAIAFetched folds the fetched certificates into the scan and rebuilds.
func (m RootModel) handleAIAFetched(msg AIAFetchedMsg) (tea.Model, tea.Cmd) {
	m.state = stateTree
	if msg.Err != nil {
		return m, m.notify(notifyError, msg.Err.Error())
	}

	if c := certops.AIAContainer(msg.Result); c != nil {
		m.store.AddContainer(*c)
	}
	m.rebuildAfterAIA(msg.Result)

	switch {
	case len(msg.Result.Fetched) == 0 && len(msg.Result.Failures) == 0:
		return m, m.notify(notifyInfo, "No AIA URLs to follow")
	case len(msg.Result.Fetched) == 0:
		return m, m.notify(notifyError, fmt.Sprintf("AIA: %d URL(s) failed", len(msg.Result.Failures)))
	default:
		return m, m.notify(notifyInfo, fmt.Sprintf("Fetched %d certificate(s) over AIA", len(msg.Result.Fetched)))
	}
}

// rebuildAfterAIA recomputes relations, chains and trust with the fetched
// certificates in hand, keeping the cursor where it was.
func (m *RootModel) rebuildAfterAIA(res certlib.AIAResult) {
	cursorNode := TreeNode{ContainerIdx: -1}
	if m.tree.cursor < len(m.visible) {
		cursorNode = m.visible[m.tree.cursor]
	}

	relations := certlib.DetectRelations(m.store)
	m.store.Relations = relations
	m.opts.RelationIndex = certlib.BuildRelationIndex(relations, m.store)
	alts := certlib.AssembleChainAlternatives(m.opts.RelationIndex, m.store)
	m.opts.Chains = certlib.FirstChains(alts)
	m.opts.ChainsContaining = certlib.ChainsContaining(alts)
	m.opts.Store = m.store

	if m.inRemoteView() {
		m.remoteAIA = &res
	}

	if len(m.trustStores) > 0 {
		if index, err := certops.EvaluateTrust(certops.TrustEvalOptions{
			Store:  m.store,
			Stores: m.trustStores,
			AIA:    &res,
		}); err == nil {
			m.opts.TrustIndex = index
			m.trustIndex = index
		}
	}

	m.allNodes = ConvertStore(m.store, m.opts, m.pathDisplay)
	m.decorateListerNodes()
	if m.inRemoteView() {
		// The served chain may now complete; the not-in-chain marks have to be
		// recomputed or they would claim otherwise.
		m.markRemoteChainOutliers()
	}
	m.recomputeVisible()
	if cursorNode.ContainerIdx >= 0 {
		m.cursorToNode(cursorNode)
	}
	m.tree.clampCursor(len(m.visible))
}
