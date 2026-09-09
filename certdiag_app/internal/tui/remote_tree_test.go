package tui

import (
	"crypto/x509"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
)

// The acceptance list for M30a part V: everything the old remote view could do,
// asserted against the shared tree that replaced it. Anything missing here is a
// capability the refactor dropped.

func remoteTargetResult(target string, roles []string, certs []*x509.Certificate) certops.TargetFetchResult {
	tr := certops.TargetFetchResult{
		Target:     target,
		Connection: &certops.RemoteConnectionInfo{TLSVersion: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", RemoteAddress: "192.0.2.1:443"},
	}
	for i, c := range certs {
		tr.Certs = append(tr.Certs, certops.RemoteCertInfo{
			Index: i,
			Role:  roles[i],
			Cert:  &certlib.CertItem{Type: certlib.ContentCertificate, Certificate: c, RawBytes: c.Raw},
		})
	}
	return tr
}

// remoteTreeModel is a fetched result already shown on the shared tree, which is
// the state the user is in after a fetch completes.
func remoteTreeModel(t *testing.T, targets ...certops.TargetFetchResult) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	m := makeTestRootModel()
	m.width, m.height = 120, 40
	m.remoteResult = &certops.FetchRemoteCertResult{TargetResults: targets}
	m.remoteHasResult = true
	m.currentRoot = rootRemoteFetch
	m.rebuildRemoteTree()
	m.state = stateTree
	m.focus = focusTree
	return m
}

func defaultRemoteTree(t *testing.T) RootModel {
	t.Helper()
	ca, leaf := makeSignedPair(t)
	return remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate"}, []*x509.Certificate{leaf, ca}))
}

func press(t *testing.T, m RootModel, key tea.KeyMsg) RootModel {
	t.Helper()
	model, _ := m.handleKey(key)
	return model.(RootModel)
}

func runes(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

func TestRemoteTree_ShowsTargetAndCertificates(t *testing.T) {
	m := defaultRemoteTree(t)

	if len(m.visible) != 3 {
		t.Fatalf("expected the target row plus two certificates, got %d", len(m.visible))
	}
	if !m.visible[0].IsBundle {
		t.Error("the target must be the group row")
	}
	if !strings.Contains(m.visible[0].Filename, "example.com:443") {
		t.Errorf("the target row must name the endpoint, got %q", m.visible[0].Filename)
	}
	if !strings.Contains(m.visible[0].Filename, "TLS 1.3") {
		t.Errorf("the connection stays visible at a glance, got %q", m.visible[0].Filename)
	}
	if m.tree.firstColHeader != headerRemote {
		t.Errorf("expected the REMOTE header, got %q", m.tree.firstColHeader)
	}
}

func TestRemoteTree_EnterOpensDetail(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 1 // a certificate row

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	if m.state != stateSplit {
		t.Fatalf("Enter must open the detail split, got state %d", m.state)
	}
	if m.detail == nil {
		t.Fatal("no detail model")
	}
	if m.detail.source != "example.com:443" {
		t.Errorf("the detail must know its endpoint for the openssl popup, got %q", m.detail.source)
	}
}

// TestRemoteTree_EnterOnTargetShowsConnection: the connection block the old top
// panel showed now lives on the target's own row.
func TestRemoteTree_EnterOnTargetShowsConnection(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 0

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.detail == nil {
		t.Fatal("no detail model")
	}

	var text strings.Builder
	for _, l := range m.detail.contentLines {
		text.WriteString(l.text)
		text.WriteString("\n")
	}
	for _, want := range []string{"Connection:", "TLS 1.3", "TLS_AES_128_GCM_SHA256", "192.0.2.1:443"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("the target detail must carry %q:\n%s", want, text.String())
		}
	}
}

func TestRemoteTree_DownMovesBetweenCertificates(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 1

	m = press(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.tree.cursor != 2 {
		t.Errorf("expected the cursor on the next certificate, got %d", m.tree.cursor)
	}
	m = press(t, m, tea.KeyMsg{Type: tea.KeyUp})
	if m.tree.cursor != 1 {
		t.Errorf("expected the cursor back on the first certificate, got %d", m.tree.cursor)
	}
}

func TestRemoteTree_FoldCollapsesTarget(t *testing.T) {
	m := defaultRemoteTree(t)

	m = press(t, m, runes("z"))
	if len(m.visible) != 1 {
		t.Errorf("z must fold the target down to its own row, got %d rows", len(m.visible))
	}
}

func TestRemoteTree_SearchFilters(t *testing.T) {
	m := defaultRemoteTree(t)
	m.search.filterText = "leaf.example.com"
	m.recomputeVisible()

	for _, n := range m.visible {
		if n.Item != nil && !strings.Contains(strings.ToLower(n.Searchable), "leaf.example.com") {
			t.Errorf("row %q should have been filtered out", n.Subject)
		}
	}
	if len(m.visible) == 0 {
		t.Error("the matching certificate must survive the filter")
	}
}

// TestRemoteTree_CRunsRemoteChecks: the old view ran file-level checks only, so
// no remote_* finding could ever appear. This is the regression guard.
func TestRemoteTree_CRunsRemoteChecks(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	stranger, _ := makeSignedPair(t)
	m := remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate", "root"},
		[]*x509.Certificate{leaf, ca, stranger}))

	m = press(t, m, runes("c"))

	if m.state != stateCheckView {
		t.Fatalf("c must open the check view, got state %d", m.state)
	}
	var sawRemote bool
	for _, issue := range m.checkView.issues {
		if strings.HasPrefix(issue.CheckID, "remote_") {
			sawRemote = true
		}
	}
	if !sawRemote {
		t.Error("the remote checks must run on a fetched result, not just the file-level ones")
	}
}

func TestRemoteTree_EscShowsHint(t *testing.T) {
	m := defaultRemoteTree(t)

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEsc})

	if m.state != stateTree {
		t.Errorf("Esc must not navigate away from the result, got state %d", m.state)
	}
	if !strings.Contains(m.statusMessage, "F to switch views") {
		t.Errorf("Esc must explain how to leave, got %q", m.statusMessage)
	}
}

func TestRemoteTree_FOpensFunctionsMenu(t *testing.T) {
	m := defaultRemoteTree(t)

	m = press(t, m, runes("F"))
	if m.state != stateMenu {
		t.Errorf("F must open the functions menu, got state %d", m.state)
	}
}

func TestRemoteTree_ROpensForm(t *testing.T) {
	m := defaultRemoteTree(t)

	m = press(t, m, runes("R"))
	if m.state != stateRemoteForm {
		t.Errorf("R must open a new remote form, got state %d", m.state)
	}
}

func TestRemoteTree_SSavesAll(t *testing.T) {
	m := defaultRemoteTree(t)

	m = press(t, m, runes("S"))
	if m.popup.kind != popupConfirm {
		t.Error("S must ask before writing every certificate to disk")
	}
}

func TestRemoteTree_SaveChainReturnsCommand(t *testing.T) {
	m := defaultRemoteTree(t)

	handled, _, cmd := m.remoteKey(runes("s"), stateTree)
	if !handled {
		t.Fatal("s must be handled by the remote view, not by the read-only guard")
	}
	if cmd == nil {
		t.Error("s must open the save-chain picker")
	}
}

// TestRemoteTree_ReFetchUsesLastOptions: r re-runs the same fetch rather than
// walking the user back through the form.
func TestRemoteTree_ReFetchUsesLastOptions(t *testing.T) {
	m := defaultRemoteTree(t)
	m.remoteLastOpts = certops.FetchRemoteCertOptions{Targets: []string{"example.com:443"}}

	handled, model, cmd := m.remoteKey(runes("r"), stateTree)
	if !handled || cmd == nil {
		t.Fatal("r must re-run the last fetch")
	}
	if got := model.(RootModel); got.state != stateLoading {
		t.Errorf("expected the loading state while re-fetching, got %d", got.state)
	}
}

func TestRemoteTree_ReFetchWithoutOptionsExplains(t *testing.T) {
	m := defaultRemoteTree(t)
	m.remoteLastOpts = certops.FetchRemoteCertOptions{}

	handled, model, _ := m.remoteKey(runes("r"), stateTree)
	if !handled {
		t.Fatal("r must be handled")
	}
	if got := model.(RootModel); !strings.Contains(got.statusMessage, "R for a new target") {
		t.Errorf("expected an explanation, got %q", got.statusMessage)
	}
}

func TestRemoteSplit_TabSwitchesFocus(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 1
	m = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	before := m.focus
	m = press(t, m, tea.KeyMsg{Type: tea.KeyTab})
	if m.focus == before {
		t.Error("Tab must move focus between the tree and the detail")
	}
}

func TestRemoteSplit_EscReturnsToList(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 1
	m = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	m = press(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.state != stateTree {
		t.Errorf("Esc must close the detail and return to the list, got state %d", m.state)
	}
}

func TestRemoteTree_RowsAreReadOnly(t *testing.T) {
	m := defaultRemoteTree(t)
	m.tree.cursor = 1

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	got := model.(RootModel)
	if got.confirmDelete {
		t.Error("a served certificate must not be deletable")
	}
}

// TestRemoteTree_OneContainerPerTarget: two endpoints stay two groups, so one
// server's chain cannot appear to complete through another's certificates.
func TestRemoteTree_OneContainerPerTarget(t *testing.T) {
	caA, leafA := makeSignedPair(t)
	caB, leafB := makeSignedPair(t)
	m := remoteTreeModel(t,
		remoteTargetResult("a.example:443", []string{"leaf", "intermediate"}, []*x509.Certificate{leafA, caA}),
		remoteTargetResult("b.example:443", []string{"leaf", "intermediate"}, []*x509.Certificate{leafB, caB}),
	)

	bundles := 0
	for _, n := range m.visible {
		if n.IsBundle {
			bundles++
		}
	}
	if bundles != 2 {
		t.Errorf("expected one group per endpoint, got %d", bundles)
	}
}

func TestRemoteTree_HintBar(t *testing.T) {
	m := defaultRemoteTree(t)
	hints, _ := m.treeFooterHints()

	for _, key := range []string{"s", "S", "c", "R", "z"} {
		if !hintsContain(hints, key) {
			t.Errorf("the remote hint bar must advertise %q", key)
		}
	}
}

// TestRemoteTree_NotInChainMarker: a certificate the server sent that no path
// from the leaf reaches is called out on its own row. Without this the row
// looks exactly like a legitimate part of the chain.
func TestRemoteTree_NotInChainMarker(t *testing.T) {
	ca, leaf := makeSignedPair(t)
	strangerCA, _ := makeSignedPair(t)

	m := remoteTreeModel(t, remoteTargetResult("example.com:443",
		[]string{"leaf", "intermediate", "intermediate"},
		[]*x509.Certificate{leaf, ca, strangerCA}))

	var marked, unmarked int
	for _, n := range m.visible {
		if n.Item == nil {
			continue
		}
		flagged := false
		for _, w := range n.Warnings {
			if strings.Contains(w, "not in chain") {
				flagged = true
			}
		}
		if flagged {
			marked++
		} else {
			unmarked++
		}
	}
	if marked != 1 {
		t.Errorf("expected exactly the stranger to be marked, got %d marked", marked)
	}
	if unmarked != 2 {
		t.Errorf("expected the leaf and its issuer to stay unmarked, got %d", unmarked)
	}
}

// TestRemoteTree_FunctionsMenuReturnsToResult: switching away and back must not
// throw the result away or re-dial.
func TestRemoteTree_FunctionsMenuReturnsToResult(t *testing.T) {
	m := defaultRemoteTree(t)
	before := m.remoteResult

	m.currentRoot = rootCertLister
	m.openFunctionsMenu()
	// The Remote Fetch entry is the second one.
	m.menu.cursor = 1
	model, _ := m.handleMenuKey(tea.KeyMsg{Type: tea.KeyEnter})
	got := model.(RootModel)

	if got.state != stateTree {
		t.Errorf("an existing result must be shown again, got state %d", got.state)
	}
	if got.remoteResult != before {
		t.Error("the result must be reused, not re-fetched")
	}
}
