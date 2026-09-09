package tui

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

// T11 / H8: a finished scan clears an error line left by an earlier failure.
func TestScanComplete_ClearsStaleError(t *testing.T) {
	m := makeLoadedModel(t)
	m.err = errors.New("stale")
	result, _ := m.Update(scanTestCerts(t))
	if rm := result.(RootModel); rm.err != nil {
		t.Errorf("a successful scan must clear the error line, got %v", rm.err)
	}
}

// T22 / H8: Esc while the trust stores load returns to the cert lister without
// an error, and a later successful load clears an earlier failure.
func TestTrustStoreLoaded_CancelReturnsToLister(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.tuiOpts.ActiveCols = []string{"subject"}
	m.state = stateLoading

	model, cmd := m.handleTrustStoreLoaded(TrustStoreLoadedMsg{Err: context.Canceled})
	got := model.(RootModel)
	if got.state != stateTree || got.currentRoot != rootCertLister {
		t.Errorf("cancel: state=%v root=%v, want the cert lister tree", got.state, got.currentRoot)
	}
	if got.err != nil {
		t.Errorf("cancel is not an error, got %v", got.err)
	}
	if got.tree.firstColHeader != headerFilename {
		t.Errorf("header = %q, want FILENAME back", got.tree.firstColHeader)
	}
	if !strings.Contains(got.statusMessage, "cancelled") || cmd == nil {
		t.Errorf("expected a transient cancel notice, got %q", got.statusMessage)
	}
}

func TestTrustStoreLoaded_SuccessClearsError(t *testing.T) {
	m := makeTestRootModel()
	m.currentRoot = rootTrustStore
	m.storeGrouping = certops.GroupByInstance
	m.storeCols = defaultStoreCols()
	m.err = errors.New("earlier keychain failure")

	model, _ := m.handleTrustStoreLoaded(TrustStoreLoadedMsg{
		Stores: []truststore.StoreContents{tsStore("OS", truststore.StoreTypeOS, "/kc", tsCert(t, "R"))},
	})
	if got := model.(RootModel); got.err != nil {
		t.Errorf("a successful load must clear the error line, got %v", got.err)
	}
}

// T12 / M13: a bundle whose password was refused renders as locked.
func TestConvertStore_PasswordRefusedBundleIsLocked(t *testing.T) {
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath:    "/tmp/secret.p12",
		Format:      certlib.FormatPKCS12,
		ParseErrors: []string{"failed to decrypt: password required"},
	})
	m := newModelFromStore(t, store)
	if len(m.allNodes) == 0 || !m.allNodes[0].Locked {
		t.Fatalf("the header row must be locked, got %+v", m.allNodes)
	}
	m.tree.width = 120
	if v := m.View(); !strings.Contains(v, "[locked]") {
		t.Errorf("expected the [locked] marker in the tree:\n%s", v)
	}
}

// E2: what the scan skipped is listed, and Enter on it explains why.
func TestConvertStore_SkippedFilesAreListed(t *testing.T) {
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "/tmp/ok.pem", Format: certlib.FormatPEM,
		Items: []certlib.CertItem{{Type: certlib.ContentCertificate}},
	})
	store.Skipped = []certlib.SkippedFile{{Path: "/tmp/garbage.crt", Reason: "no PEM or DER content"}}
	m := newModelFromStore(t, store)

	last := m.allNodes[len(m.allNodes)-1]
	if !last.Skipped || last.Filename != "garbage.crt" || !last.IsChild {
		t.Fatalf("expected a skipped child row last, got %+v", last)
	}
	header := m.allNodes[len(m.allNodes)-2]
	if !header.IsBundle || header.Filename != "skipped (1)" || header.Expanded {
		t.Fatalf("expected a folded 'skipped (1)' header, got %+v", header)
	}

	// Fold, unfold and render the group, then open the row.
	m.tree.width = 120
	m.tree.cursor = len(m.visible) - 1
	m = sendSpecial(m, tea.KeyRight)
	if v := m.View(); !strings.Contains(v, "garbage.crt") || !strings.Contains(v, "skipped (1)") {
		t.Errorf("expected the skipped group and its row in the view:\n%s", v)
	}
	m.tree.cursor = len(m.visible) - 1
	m = sendSpecial(m, tea.KeyCtrlD)
	if m.deleteFilePath != "/tmp/garbage.crt" {
		t.Errorf("delete on a skipped row must target the file, got %q", m.deleteFilePath)
	}
	m.confirmDelete = false
	m.deleteFilePath = ""
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(RootModel)
	if rm.state != stateTree || rm.detail != nil {
		t.Errorf("Enter on a skipped row must not open a detail pane")
	}
	if !strings.Contains(rm.statusMessage, "no PEM or DER content") {
		t.Errorf("expected the reason in the status line, got %q", rm.statusMessage)
	}
}

// T13 / E1: a fetch where every target failed stays on the form with the
// reason; a cancelled fetch stays on the form without an error.
func TestRemoteFetchResult_AllTargetsFailedStaysOnForm(t *testing.T) {
	m := makeTestRootModel()
	m.state = stateLoading
	res := &certops.FetchRemoteCertResult{TargetResults: []certops.TargetFetchResult{
		{Target: "down.example:443", Error: "dial tcp: connection refused"},
	}}
	model, _ := m.handleRemoteFetchResult(RemoteFetchResultMsg{Result: res})
	got := model.(RootModel)
	if got.state != stateRemoteForm {
		t.Errorf("state = %v, want the remote form", got.state)
	}
	if got.remoteHasResult || got.currentRoot == rootRemoteFetch {
		t.Error("a failed fetch must not become the remote view")
	}
	if got.popup.kind != popupError || !strings.Contains(got.popup.message, "connection refused") {
		t.Errorf("expected the first target error as a popup, got %+v", got.popup)
	}
}

func TestRemoteFetchResult_CancelIsNotAnError(t *testing.T) {
	m := makeTestRootModel()
	m.state = stateLoading
	model, cmd := m.handleRemoteFetchResult(RemoteFetchResultMsg{Err: errFetchCancelled})
	got := model.(RootModel)
	if got.state != stateRemoteForm || got.popup.kind == popupError {
		t.Errorf("cancel: state=%v popup=%+v, want the form and no error", got.state, got.popup)
	}
	if !strings.Contains(got.statusMessage, "cancelled") || cmd == nil {
		t.Errorf("expected a transient cancel notice, got %q", got.statusMessage)
	}
}

// T15 / E3: the delete prompt leads with the file name.
func TestDeletePrompt_NamesTheFileFirst(t *testing.T) {
	got := deletePrompt(filepath.FromSlash("/a/very/long/directory/that/keeps/going/server.pem"))
	if !strings.HasPrefix(got, " Delete server.pem? [y/N]") {
		t.Errorf("prompt = %q", got)
	}
	if !strings.Contains(got, filepath.FromSlash("/a/very/long/directory/that/keeps/going")) {
		t.Errorf("prompt must still say where the file is: %q", got)
	}
}

// T16 / E4: column padding and truncation count display cells, not runes.
func TestPadOrTrunc_UsesDisplayWidth(t *testing.T) {
	cases := []struct {
		in    string
		width int
	}{
		{"日本語", 4}, {"日本語テキスト", 5}, {"abc", 5}, {"plain ascii here", 8}, {"é", 3},
	}
	for _, c := range cases {
		got := padOrTrunc(c.in, c.width)
		if w := lipgloss.Width(got); w != c.width {
			t.Errorf("padOrTrunc(%q, %d) has width %d: %q", c.in, c.width, w, got)
		}
	}
	if got := truncate("日本語テキスト", 5); !strings.HasSuffix(got, "...") {
		t.Errorf("wide text must be cut with an ellipsis, got %q", got)
	}
}

// T17 / E5: keys typed while a scan runs do not open anything.
func TestLoading_DropsActionKeys(t *testing.T) {
	m := makeLoadedModel(t)
	m.state = stateLoading
	for _, k := range []string{"n", "r", "/", "m", "s", "t"} {
		rm := sendKey(m, k)
		if rm.state != stateLoading || rm.activeForm != nil {
			t.Errorf("key %q during loading changed state to %v", k, rm.state)
		}
	}
}

// T18 / E6: Home and End move the detail cursor to the first and last line.
func TestDetail_HomeEnd(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if node.Item != nil && node.Item.Type == certlib.ContentCertificate && !node.Locked {
			m.tree.cursor = i
			break
		}
	}
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = result.(RootModel)
	if m.state != stateSplit || m.detail == nil {
		t.Skip("detail pane did not open")
	}
	first, last := -1, -1
	for i, l := range m.detail.contentLines {
		if l.selectable {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	m = sendSpecial(m, tea.KeyEnd)
	if m.detail.cursorLine != last {
		t.Errorf("End: cursor %d, want %d", m.detail.cursorLine, last)
	}
	m = sendSpecial(m, tea.KeyHome)
	if m.detail.cursorLine != first {
		t.Errorf("Home: cursor %d, want %d", m.detail.cursorLine, first)
	}
}

// T19 / E7: a filter shows matching children of a folded bundle.
func TestComputeVisible_FilterReachesIntoFoldedBundle(t *testing.T) {
	nodes := makeTestNodes()
	nodes[0].Expanded = false
	for i := range nodes {
		nodes[i].Searchable = strings.ToLower(nodes[i].Filename + " " + nodes[i].ContentType)
	}
	vis := computeVisible(nodes, "pkcs12/key")
	var names []string
	for _, n := range vis {
		names = append(names, n.Filename)
	}
	if len(vis) != 2 || vis[0].Filename != "bundle.p12" || vis[1].Filename != "key" {
		t.Errorf("expected the header and its matching child, got %v", names)
	}
	if vis := computeVisible(nodes, ""); len(vis) != 3 {
		t.Errorf("without a filter the folded bundle still hides its children, got %d rows", len(vis))
	}
}

// T20 / E8: multi-select edge cases.
func TestMultiSelect_ExitClearsStatus(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	if m.state != stateMultiSelect {
		t.Skip("multi-select did not open")
	}
	m.statusMessage = "2 selected"
	m = sendSpecial(m, tea.KeyEsc)
	if m.statusMessage != "" {
		t.Errorf("status %q survived leaving multi-select", m.statusMessage)
	}
}

func TestMultiSelect_ReadOnlyRowRefused(t *testing.T) {
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "store:os", Label: "OS", Source: certlib.SourceTrustStore, Format: certlib.FormatPEM,
		Items: []certlib.CertItem{{Type: certlib.ContentCertificate}},
	})
	m := newModelFromStore(t, store)
	m.state = stateMultiSelect
	m.multiSelectActive = true
	for i, n := range m.visible {
		if n.Item != nil {
			m.tree.cursor = i
		}
	}
	m = sendSpecial(m, tea.KeySpace)
	if m.multiSelect.count() != 0 {
		t.Error("a trust store row must not be selectable")
	}
	if !strings.Contains(m.statusMessage, "read-only") {
		t.Errorf("expected a read-only notice, got %q", m.statusMessage)
	}
}

func TestMultiSelect_AutoChainUsesSelection(t *testing.T) {
	m := makeLoadedModel(t)
	if m.opts.RelationIndex == nil {
		t.Skip("no relations in the fixture scan")
	}
	m = sendKey(m, "m")
	picked := 0
	for i, n := range m.visible {
		if n.Item != nil && n.Item.Type == certlib.ContentCertificate && !n.Locked && !n.IsChild {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			picked++
			if picked == 2 {
				break
			}
		}
	}
	if picked < 2 {
		t.Skip("fewer than two standalone certificates")
	}
	m = sendKey(m, "a")
	if !strings.Contains(m.statusMessage, "2 selected certificates") {
		t.Errorf("expected auto-chain over the selection, got %q", m.statusMessage)
	}
	if m.multiSelect.count() < 2 {
		t.Errorf("auto-chain dropped the selection: %d", m.multiSelect.count())
	}
}

// T21 / E9: picking a file clears a stale "required" error, and typing into a
// picker field says so.
func TestForm_FilePickedRevalidates(t *testing.T) {
	initFormStyles()
	f := newFormModel("t")
	field := newFilePickerField("input", "Input file", filepicker.TypeOpenFile, "", "", nil)
	idx := f.addField("input", field)
	f.validateField(idx)
	if f.errors[idx] == "" {
		t.Fatal("an empty required picker must fail validation")
	}
	f.handleFilePicked(filePickedMsg{fieldName: "input", path: "/tmp/x.pem"})
	if f.errors[idx] != "" {
		t.Errorf("error %q survived the picked file", f.errors[idx])
	}
}

func TestFilePickerField_TypingShowsHint(t *testing.T) {
	initFormStyles()
	field := newFilePickerField("input", "Input file", filepicker.TypeOpenFile, "", "", nil)
	field.Focus()
	updated, _ := field.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if v := updated.View(true, 80); !strings.Contains(v, "typing has no effect") {
		t.Errorf("expected the typing hint, got:\n%s", v)
	}
}

// T23 / E12: unlocking a container says what it is doing.
func TestPasswordSubmit_ShowsUnlockingLabel(t *testing.T) {
	m := makeLoadedModel(t)
	var target *TreeNode
	for i := range m.visible {
		if m.visible[i].Locked {
			target = &m.visible[i]
			break
		}
	}
	if target == nil {
		t.Skip("no locked container in the fixture scan")
	}
	m.state = statePassword
	m.password.activate(*target)
	m.password.textInput.SetValue("whatever")
	result, _ := m.handlePasswordKey(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(RootModel)
	if rm.state != stateLoading || rm.loadingMessage != "Unlocking..." {
		t.Errorf("state=%v message=%q", rm.state, rm.loadingMessage)
	}
}
