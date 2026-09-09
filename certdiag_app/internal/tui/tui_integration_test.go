package tui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
	"github.com/zarmin/certdiag/certdiag_app/internal/password"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// scanTestCerts scans the test certs directory and returns a ScanCompleteMsg.
func scanTestCerts(t *testing.T) ScanCompleteMsg {
	t.Helper()
	certsDir, err := filepath.Abs(filepath.Join("..", "..", "..", "tools", "testing", "certs"))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	pm, err := password.NewPasswordManager(password.PasswordManagerOpts{
		CLIPasswords: []string{"p12pass", "changeit", "keypass123", "ecdsapfx",
			"chainpass", "legacydes", "trustme", "multientry"},
	})
	if err != nil {
		t.Fatalf("password manager: %v", err)
	}
	scanOpts := certlib.ScanOptions{PasswordProvider: pm}
	s, err := certlib.ScanPathWithOptions(certsDir, scanOpts)
	if err != nil {
		t.Fatalf("scan certs: %v", err)
	}
	store := certlib.NewCertStore()
	for i := range s.Containers {
		store.AddContainer(s.Containers[i])
	}
	opts := output.OutputOptions{}
	if store.TotalItems() >= 2 {
		relations := certlib.DetectRelations(store)
		opts.RelationIndex = certlib.BuildRelationIndex(relations, store)
		opts.Chains = certlib.AssembleChains(opts.RelationIndex, store)
		opts.Store = store
	}
	var allContainers []*certlib.CertContainer
	for i := range store.Containers {
		allContainers = append(allContainers, &store.Containers[i])
	}
	structured := output.BuildStructuredOutput(allContainers, opts)
	return ScanCompleteMsg{Store: store, Opts: opts, Structured: structured}
}

// makeLoadedModel creates a RootModel with real certs loaded, ready for tree-state testing.
func makeLoadedModel(t *testing.T) RootModel {
	t.Helper()
	initStyles()
	initFormStyles()

	certsDir := filepath.Join("..", "..", "..", "tools", "testing", "certs")

	m := NewRootModel(certsDir, certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{
			ActiveCols: []string{"subject", "expiry", "algo"},
		})
	m.width = 120
	m.height = 40
	m.tree.width = 120
	m.tree.viewportHeight = 36

	// Inject scan results
	msg := scanTestCerts(t)
	result, _ := m.Update(msg)
	rm := result.(RootModel)
	return rm
}

// assertViewContains checks that View() contains the expected string.
func assertViewContains(t *testing.T, m RootModel, want string) {
	t.Helper()
	v := m.View()
	if !strings.Contains(v, want) {
		t.Errorf("View() missing %q (state=%d, len=%d)", want, m.state, len(v))
	}
}

// assertViewNotContains checks that View() does NOT contain the string.
func assertViewNotContains(t *testing.T, m RootModel, unwanted string) {
	t.Helper()
	v := m.View()
	if strings.Contains(v, unwanted) {
		t.Errorf("View() should not contain %q (state=%d)", unwanted, m.state)
	}
}

// sendKey sends a rune key through handleKey and returns the resulting model.
func sendKey(m RootModel, key string) RootModel {
	result, _ := m.handleKey(keyMsg(key))
	return result.(RootModel)
}

// sendKeyWithCmd sends a rune key and also returns the cmd.
func sendKeyWithCmd(m RootModel, key string) (RootModel, tea.Cmd) {
	result, cmd := m.handleKey(keyMsg(key))
	return result.(RootModel), cmd
}

// sendSpecial sends a special key through handleKey.
func sendSpecial(m RootModel, k tea.KeyType) RootModel {
	result, _ := m.handleKey(specialKeyMsg(k))
	return result.(RootModel)
}

// sendSpecialWithCmd sends a special key and also returns the cmd.
func sendSpecialWithCmd(m RootModel, k tea.KeyType) (RootModel, tea.Cmd) {
	result, cmd := m.handleKey(specialKeyMsg(k))
	return result.(RootModel), cmd
}

// sendUpdate sends an arbitrary tea.Msg through Update.
func sendUpdate(m RootModel, msg tea.Msg) RootModel {
	result, _ := m.Update(msg)
	return result.(RootModel)
}

// ---------------------------------------------------------------------------
// 1. Loading state
// ---------------------------------------------------------------------------

func TestLoading_SpinnerShown(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel("/tmp", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{})
	m.width = 120
	m.height = 40

	if m.state != stateLoading {
		t.Fatalf("expected stateLoading, got %d", m.state)
	}
	v := m.View()
	if !strings.Contains(v, "Scanning") {
		t.Errorf("loading view missing 'Scanning': %s", v)
	}
}

func TestLoading_ScanCompleteTransitionsToTree(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel("/tmp", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{})
	m.width = 120
	m.height = 40

	msg := scanTestCerts(t)
	rm := sendUpdate(m, msg)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if len(rm.allNodes) == 0 {
		t.Fatal("expected nodes after scan complete")
	}
}

func TestLoading_ScanErrorShowsError(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel("/tmp", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{})
	m.width = 120
	m.height = 40

	msg := ScanCompleteMsg{Err: fmt.Errorf("test error")}
	rm := sendUpdate(m, msg)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree after error, got %d", rm.state)
	}
	if rm.err == nil {
		t.Fatal("expected error to be set")
	}
}

func TestLoading_EmptyScan(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel("/tmp", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{})
	m.width = 120
	m.height = 40

	store := certlib.NewCertStore()
	msg := ScanCompleteMsg{Store: store, Opts: output.OutputOptions{}}
	rm := sendUpdate(m, msg)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if len(rm.allNodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(rm.allNodes))
	}
}

func TestLoading_StatusMessage(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel("/tmp", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{StatusMessage: "test status"})
	m.width = 120
	m.height = 40

	if m.statusMessage != "test status" {
		t.Errorf("expected statusMessage 'test status', got %q", m.statusMessage)
	}
}

// ---------------------------------------------------------------------------
// 2. Tree view -- navigation
// ---------------------------------------------------------------------------

func TestTree_CursorStartsAtFirst(t *testing.T) {
	m := makeLoadedModel(t)
	if m.tree.cursor != 0 {
		t.Fatalf("expected cursor at 0, got %d", m.tree.cursor)
	}
}

func TestTree_DownMovesDown(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendSpecial(m, tea.KeyDown)
	if m.tree.cursor != 1 {
		t.Fatalf("expected cursor at 1 after down, got %d", m.tree.cursor)
	}
}

func TestTree_UpMovesUp(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendSpecial(m, tea.KeyDown)
	m = sendSpecial(m, tea.KeyUp)
	if m.tree.cursor != 0 {
		t.Fatalf("expected cursor at 0 after down,up, got %d", m.tree.cursor)
	}
}

func TestTree_CursorStopsAtBottom(t *testing.T) {
	m := makeLoadedModel(t)
	last := len(m.visible) - 1
	for i := 0; i < len(m.visible)+5; i++ {
		m = sendSpecial(m, tea.KeyDown)
	}
	if m.tree.cursor != last {
		t.Fatalf("expected cursor clamped at %d, got %d", last, m.tree.cursor)
	}
}

func TestTree_CursorStopsAtTop(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendSpecial(m, tea.KeyUp)
	if m.tree.cursor != 0 {
		t.Fatalf("expected cursor clamped at 0, got %d", m.tree.cursor)
	}
}

func TestTree_EnterOpensDetail(t *testing.T) {
	m := makeLoadedModel(t)
	// Move to a non-bundle, non-locked item
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Fatalf("expected stateSplit after Enter, got %d", m.state)
	}
}

func TestTree_EscFromDetailReturnsToTree(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Fatalf("expected stateSplit, got %d", m.state)
	}
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Esc, got %d", m.state)
	}
}

func TestTree_PgDownPgUp(t *testing.T) {
	m := makeLoadedModel(t)
	if len(m.visible) < 3 {
		t.Skip("not enough items for paging test")
	}
	m = sendSpecial(m, tea.KeyPgDown)
	afterDown := m.tree.cursor
	if afterDown == 0 {
		t.Fatal("expected cursor to move after PgDown")
	}
	m = sendSpecial(m, tea.KeyPgUp)
	if m.tree.cursor != 0 {
		t.Fatalf("expected cursor at 0 after PgUp, got %d", m.tree.cursor)
	}
}

func TestTree_HomeEnd(t *testing.T) {
	m := makeLoadedModel(t)
	last := len(m.visible) - 1
	// Move down a few first
	for i := 0; i < 3; i++ {
		m = sendSpecial(m, tea.KeyDown)
	}
	m = sendSpecial(m, tea.KeyEnd)
	if m.tree.cursor != last {
		t.Fatalf("expected cursor at %d after End, got %d", last, m.tree.cursor)
	}
	m = sendSpecial(m, tea.KeyHome)
	if m.tree.cursor != 0 {
		t.Fatalf("expected cursor at 0 after Home, got %d", m.tree.cursor)
	}
}

func TestTree_WordWrapCycles(t *testing.T) {
	m := makeLoadedModel(t)
	original := m.tree.displayMode
	m = sendKey(m, "w")
	if m.tree.displayMode == original {
		t.Fatal("expected display mode to change after w")
	}
	m = sendKey(m, "w")
	m = sendKey(m, "w")
	if m.tree.displayMode != original {
		t.Fatalf("expected display mode to cycle back to %d, got %d", original, m.tree.displayMode)
	}
}

// ---------------------------------------------------------------------------
// 3. Tree view -- columns
// ---------------------------------------------------------------------------

func TestTree_DefaultColumnsShown(t *testing.T) {
	m := makeLoadedModel(t)
	v := m.View()
	for _, col := range []string{"SUBJECT", "EXPIRY", "ALGO"} {
		if !strings.Contains(v, col) {
			t.Errorf("View() missing column header %q", col)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Split view
// ---------------------------------------------------------------------------

func TestSplit_ShowsTreeAndDetail(t *testing.T) {
	m := makeLoadedModel(t)
	m.height = 40 // >= splitScreenMinHeight (32)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Fatalf("expected stateSplit, got %d", m.state)
	}
	v := m.View()
	// Should contain both tree content and detail content
	if len(v) < 100 {
		t.Error("split view seems too short")
	}
}

func TestSplit_TabSwitchesFocus(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in split state")
	}
	initialFocus := m.focus
	m = sendSpecial(m, tea.KeyTab)
	if m.focus == initialFocus {
		t.Fatal("expected focus to change after Tab")
	}
	m = sendSpecial(m, tea.KeyTab)
	if m.focus != initialFocus {
		t.Fatal("expected focus to return after second Tab")
	}
}

func TestSplit_EscReturnsToTree(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
}

func TestSplit_SmallTerminalFallsBack(t *testing.T) {
	m := makeLoadedModel(t)
	m.height = 20 // < splitScreenMinHeight (32)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in expected state")
	}
	// View should render full detail (not split) when height < 32
	v := m.View()
	if len(v) == 0 {
		t.Error("expected non-empty view")
	}
}

// ---------------------------------------------------------------------------
// 6. Search
// ---------------------------------------------------------------------------

func TestSearch_SlashOpensSearch(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "/")
	if m.state != stateSearch {
		t.Fatalf("expected stateSearch after /, got %d", m.state)
	}
}

func TestSearch_EnterCommitsAndCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "/")
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Enter in search, got %d", m.state)
	}
}

func TestSearch_EscClearsAndCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "/")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Esc in search, got %d", m.state)
	}
}

func TestSearch_TypingFilters(t *testing.T) {
	m := makeLoadedModel(t)
	totalBefore := len(m.visible)
	if totalBefore < 2 {
		t.Skip("not enough items to test filtering")
	}

	m = sendKey(m, "/")
	// Type a specific filename that exists
	for _, ch := range "server.pem" {
		result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = result.(RootModel)
	}

	if len(m.visible) >= totalBefore {
		t.Errorf("expected fewer visible items after filtering, got %d (was %d)", len(m.visible), totalBefore)
	}
}

// ---------------------------------------------------------------------------
// 8. New menu
// ---------------------------------------------------------------------------

func TestNewMenu_NOpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	if m.state != stateMenu {
		t.Fatalf("expected stateMenu, got %d", m.state)
	}
	if !m.menu.active {
		t.Fatal("expected menu.active=true")
	}
	if m.menu.title != "New" {
		t.Fatalf("expected menu title 'New', got %q", m.menu.title)
	}
}

func TestNewMenu_KSelectsCreateKey(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.state != stateForm {
		t.Fatalf("expected stateForm, got %d", m.state)
	}
	if m.activeFormKind != formCreateKey {
		t.Fatalf("expected formCreateKey, got %d", m.activeFormKind)
	}
}

func TestNewMenu_EscCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Esc, got %d", m.state)
	}
}

func TestNewMenu_CSelectsCreateCert(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "c")
	if m.state != stateForm {
		t.Fatalf("expected stateForm, got %d", m.state)
	}
	if m.activeFormKind != formCreateCert {
		t.Fatalf("expected formCreateCert, got %d", m.activeFormKind)
	}
}

func TestNewMenu_RSelectsCreateCSR(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "r")
	if m.state != stateForm {
		t.Fatalf("expected stateForm, got %d", m.state)
	}
	if m.activeFormKind != formCreateCSR {
		t.Fatalf("expected formCreateCSR, got %d", m.activeFormKind)
	}
}

// ---------------------------------------------------------------------------
// 9. Action menu
// ---------------------------------------------------------------------------

func TestActionMenu_AOpens(t *testing.T) {
	m := makeLoadedModel(t)
	m.tree.cursor = 0
	m = sendKey(m, "a")
	if m.state != stateMenu {
		t.Fatalf("expected stateMenu for action, got %d", m.state)
	}
	if m.menu.title != "Actions" {
		t.Fatalf("expected menu title 'Actions', got %q", m.menu.title)
	}
}

func TestActionMenu_EscCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "a")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Esc, got %d", m.state)
	}
}

// ---------------------------------------------------------------------------
// 10. Forms -- general behavior
// ---------------------------------------------------------------------------

func TestForm_EscOnCleanCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.state != stateForm {
		t.Fatalf("expected stateForm, got %d", m.state)
	}
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree after Esc on clean form, got %d", m.state)
	}
}

func TestForm_EscOnDirtyShowsConfirm(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.state != stateForm || m.activeForm == nil {
		t.Skip("form did not open")
	}

	// Make form dirty by changing a picker value
	m.activeForm.fields[m.activeForm.focusIdx].Update(specialKeyMsg(tea.KeyRight))

	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateForm {
		t.Fatalf("expected stateForm (dirty confirm), got %d", m.state)
	}
	if !m.confirmDiscard {
		t.Fatal("expected confirmDiscard=true")
	}
}

func TestForm_ConfirmDiscardYes(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.activeForm == nil {
		t.Skip("form did not open")
	}
	m.activeForm.fields[m.activeForm.focusIdx].Update(specialKeyMsg(tea.KeyRight))
	m = sendSpecial(m, tea.KeyEsc)
	m = sendKey(m, "y")
	if m.state != stateTree {
		t.Fatalf("expected stateTree after y, got %d", m.state)
	}
}

func TestForm_ConfirmDiscardNo(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.activeForm == nil {
		t.Skip("form did not open")
	}
	m.activeForm.fields[m.activeForm.focusIdx].Update(specialKeyMsg(tea.KeyRight))
	m = sendSpecial(m, tea.KeyEsc)
	m = sendKey(m, "n")
	if m.state != stateForm {
		t.Fatalf("expected stateForm after n, got %d", m.state)
	}
	if m.confirmDiscard {
		t.Fatal("expected confirmDiscard=false")
	}
}

func TestForm_TabAdvancesField(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.activeForm == nil {
		t.Skip("form did not open")
	}
	before := m.activeForm.focusIdx
	m = sendSpecial(m, tea.KeyTab)
	if m.activeForm.focusIdx == before {
		t.Fatal("expected focus to advance after Tab")
	}
}

// ---------------------------------------------------------------------------
// 11. Forms -- Create Key
// ---------------------------------------------------------------------------

func TestCreateKeyForm_OpensWithFields(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.activeForm == nil {
		t.Fatal("expected form to open")
	}
	v := m.View()
	if !strings.Contains(v, "Algorithm") {
		t.Error("form missing 'Algorithm' field")
	}
}

// ---------------------------------------------------------------------------
// 12. Forms -- Create Certificate
// ---------------------------------------------------------------------------

func TestCreateCertForm_OpensWithFields(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "c")
	if m.activeForm == nil {
		t.Fatal("expected form to open")
	}
	v := m.View()
	if !strings.Contains(v, "Subject") {
		t.Error("form missing 'Subject' field")
	}
}

// ---------------------------------------------------------------------------
// 13. Forms -- CSR
// ---------------------------------------------------------------------------

func TestCreateCSRForm_OpensWithFields(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "r")
	if m.activeForm == nil {
		t.Fatal("expected form to open")
	}
	v := m.View()
	if !strings.Contains(v, "Subject") {
		t.Error("form missing 'Subject' field")
	}
}

// ---------------------------------------------------------------------------
// 15. Multi-select mode
// ---------------------------------------------------------------------------

func TestMultiSelect_MEnters(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	if m.state != stateMultiSelect {
		t.Fatalf("expected stateMultiSelect, got %d", m.state)
	}
	if !m.multiSelectActive {
		t.Fatal("expected multiSelectActive=true")
	}
}

func TestMultiSelect_SpaceToggles(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	// Find a non-locked, non-bundle item
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeySpace)
	if m.multiSelect.count() != 1 {
		t.Fatalf("expected 1 selected after Space, got %d", m.multiSelect.count())
	}
	m = sendSpecial(m, tea.KeySpace)
	if m.multiSelect.count() != 0 {
		t.Fatalf("expected 0 selected after second Space, got %d", m.multiSelect.count())
	}
}

func TestMultiSelect_EscExits(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
	if m.multiSelectActive {
		t.Fatal("expected multiSelectActive=false")
	}
}

func TestMultiSelect_EnterOpensBundleForm(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	// Select two items
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			if m.multiSelect.count() >= 2 {
				break
			}
			m = sendSpecial(m, tea.KeyDown)
		}
	}
	if m.multiSelect.count() < 1 {
		t.Skip("could not select items")
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateForm {
		t.Fatalf("expected stateForm after Enter, got %d", m.state)
	}
	if m.activeFormKind != formBundle {
		t.Fatalf("expected formBundle, got %d", m.activeFormKind)
	}
}

func TestMultiSelect_DiffRequires2Certs(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	// Select only 1 cert
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil && node.Item.Type == certlib.ContentCertificate {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			break
		}
	}
	m = sendKey(m, "d")
	// Should show notice, not diff view
	if m.state == stateDiff {
		t.Fatal("should not enter diff with 1 cert")
	}
}

func TestMultiSelect_DiffWith2Certs(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	// Select 2 certs
	certCount := 0
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil &&
			node.Item.Type == certlib.ContentCertificate && node.Item.Certificate != nil {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			certCount++
			if certCount >= 2 {
				break
			}
			// Move to next
			for j := i + 1; j < len(m.visible); j++ {
				n := m.visible[j]
				if !n.IsBundle && !n.Locked && n.Item != nil &&
					n.Item.Type == certlib.ContentCertificate && n.Item.Certificate != nil {
					m.tree.cursor = j
					break
				}
			}
		}
	}
	if certCount < 2 {
		t.Skip("not enough certs for diff test")
	}
	m = sendKey(m, "d")
	if m.state != stateDiff {
		t.Fatalf("expected stateDiff, got %d", m.state)
	}
}

func TestMultiSelect_LockedItemNotSelectable(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	for i, node := range m.visible {
		if node.Locked {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			if m.multiSelect.count() != 0 {
				t.Fatal("locked item should not be selectable")
			}
			return
		}
	}
	t.Skip("no locked items found")
}

func TestMultiSelect_AutoChainA(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	// Find a cert that might have chain relations
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil &&
			node.Item.Type == certlib.ContentCertificate {
			m.tree.cursor = i
			break
		}
	}
	beforeCount := m.multiSelect.count()
	m = sendKey(m, "a")
	// Should have attempted auto-chain (count may or may not increase)
	_ = beforeCount
	// Just verify no crash and we're still in multi-select
	if m.state != stateMultiSelect {
		t.Fatalf("expected stateMultiSelect, got %d", m.state)
	}
}

func TestMultiSelect_AutoChainDuplicateRoot(t *testing.T) {
	initStyles()
	initFormStyles()

	// Generate root -> intermediate -> leaf chain
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDer, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	intTemplate := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDer, _ := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDer)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "leaf.local"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDer, _ := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, &leafKey.PublicKey, intKey)
	leafCert, _ := x509.ParseCertificate(leafDer)

	// Build store: leaf(0), intermediate(1), root(2), duplicate-root(3)
	store := certlib.NewCertStore()
	store.AddContainer(certlib.CertContainer{
		FilePath: "leaf.crt",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: leafCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "int.crt",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: intCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "root.crt",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: rootCert}},
	})
	store.AddContainer(certlib.CertContainer{
		FilePath: "root_copy.crt",
		Format:   certlib.FormatPEM,
		Items:    []certlib.CertItem{{Type: certlib.ContentCertificate, Certificate: rootCert}},
	})

	relations := certlib.DetectRelations(store)
	opts := output.OutputOptions{
		RelationIndex: certlib.BuildRelationIndex(relations, store),
		Chains:        certlib.AssembleChains(certlib.BuildRelationIndex(relations, store), store),
		Store:         store,
	}
	var allContainers []*certlib.CertContainer
	for i := range store.Containers {
		allContainers = append(allContainers, &store.Containers[i])
	}
	structured := output.BuildStructuredOutput(allContainers, opts)

	m := NewRootModel("/tmp", certlib.ScanOptions{}, false, output.OutputOptions{}, TUIOptions{
		ActiveCols: []string{"subject", "expiry", "algo"},
	})
	m.width = 120
	m.height = 40
	m.tree.width = 120
	m.tree.viewportHeight = 36
	m = sendUpdate(m, ScanCompleteMsg{Store: store, Opts: opts, Structured: structured})

	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
	if len(m.allNodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(m.allNodes))
	}

	// Enter multiselect mode
	m = sendKey(m, "m")
	if m.state != stateMultiSelect {
		t.Fatalf("expected stateMultiSelect, got %d", m.state)
	}

	// Position cursor on leaf cert (first visible node)
	leafIdx := -1
	for i, node := range m.visible {
		if node.Item != nil && node.Item.Certificate == leafCert {
			leafIdx = i
			break
		}
	}
	if leafIdx < 0 {
		t.Fatal("could not find leaf cert in visible nodes")
	}
	m.tree.cursor = leafIdx

	// Press 'a' for auto-chain
	m = sendKey(m, "a")

	// Should select exactly 3 items: leaf + intermediate + one root (not both roots)
	if m.multiSelect.count() != 3 {
		t.Fatalf("expected 3 selected (leaf+int+one root), got %d", m.multiSelect.count())
	}
}

func TestMultiSelect_CtrlDDeletePopup(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "m")
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			break
		}
	}
	if m.multiSelect.count() == 0 {
		t.Skip("could not select item")
	}
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	rm := result.(RootModel)
	if rm.popup.kind != popupConfirm {
		t.Fatalf("expected popupConfirm, got %d", rm.popup.kind)
	}
	if !strings.Contains(rm.popup.message, "Delete") {
		t.Errorf("popup message missing 'Delete': %q", rm.popup.message)
	}
}

// ---------------------------------------------------------------------------
// 16. Column editor
// ---------------------------------------------------------------------------

func TestColumnEditor_COpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "C")
	if m.state != stateColumnEditor {
		t.Fatalf("expected stateColumnEditor, got %d", m.state)
	}
}

func TestColumnEditor_EscCloses(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "C")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
}

func TestColumnEditor_ViewShowsColumns(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "C")
	v := m.View()
	if !strings.Contains(v, "SUBJECT") {
		t.Error("column editor missing SUBJECT")
	}
}

// ---------------------------------------------------------------------------
// 17. Options editor
// ---------------------------------------------------------------------------

func TestOptions_OOpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "O")
	if m.state != stateOptions {
		t.Fatalf("expected stateOptions, got %d", m.state)
	}
}

func TestOptions_EscNoChange(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "O")
	m, cmd := sendSpecialWithCmd(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
	if cmd != nil {
		t.Fatal("expected nil cmd when no options changed")
	}
}

func TestOptions_EscWithChangeTriggersRescan(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "O")
	// optionsEditor is a value type, always initialized by O key handler
	m.optionsEditor.toggleBool("recursive")
	m, cmd := sendSpecialWithCmd(m, tea.KeyEsc)
	if m.state != stateLoading {
		t.Fatalf("expected stateLoading (rescan), got %d", m.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd for rescan")
	}
}

func TestOptions_LockedNotToggleable(t *testing.T) {
	m := makeLoadedModel(t)
	m.lockedFlags = map[string]bool{"recursive": true}
	m = sendKey(m, "O")
	m.optionsEditor.toggleBool("recursive")
	if m.optionsEditor.bools["recursive"] {
		t.Fatal("expected recursive unchanged when locked")
	}
}

func TestOptions_Save(t *testing.T) {
	m := makeLoadedModel(t)
	var called bool
	m.saveOptions = func(opts SavedOptions) error {
		called = true
		return nil
	}
	m = sendKey(m, "O")
	m = sendKey(m, "s")
	if !called {
		t.Fatal("expected saveOptions to be called")
	}
}

func TestOptions_SaveError(t *testing.T) {
	m := makeLoadedModel(t)
	m.saveOptions = func(opts SavedOptions) error {
		return fmt.Errorf("disk full")
	}
	m = sendKey(m, "O")
	m = sendKey(m, "s")
	if !strings.Contains(m.statusMessage, "disk full") {
		t.Fatalf("expected error in status, got %q", m.statusMessage)
	}
}

// ---------------------------------------------------------------------------
// 18. Check view
// ---------------------------------------------------------------------------

func TestCheckView_WOpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	if m.state != stateCheckView {
		t.Fatalf("expected stateCheckView, got %d", m.state)
	}
}

func TestCheckView_EscReturns(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateTree {
		t.Fatalf("expected stateTree, got %d", m.state)
	}
}

func TestCheckView_SeverityFilter1(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "1")
	if m.checkView.minSeverity != 0 {
		t.Fatalf("expected minSeverity=0 (all), got %d", m.checkView.minSeverity)
	}
}

func TestCheckView_SeverityFilter2(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "2")
	if m.checkView.minSeverity != 1 {
		t.Fatalf("expected minSeverity=1 (warning+), got %d", m.checkView.minSeverity)
	}
}

func TestCheckView_SeverityFilter3(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "3")
	if m.checkView.minSeverity != 2 {
		t.Fatalf("expected minSeverity=2 (critical), got %d", m.checkView.minSeverity)
	}
}

func TestCheckView_SortCycles(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	before := m.checkView.sortMode
	m = sendKey(m, "s")
	if m.checkView.sortMode == before {
		t.Fatal("expected sort mode to change")
	}
}

func TestCheckView_SearchOpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "/")
	if !m.checkView.filterActive {
		t.Fatal("expected filter to be active after /")
	}
}

func TestCheckView_Navigation(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	if len(m.checkView.issues) < 2 {
		t.Skip("not enough issues to test navigation")
	}
	m = sendSpecial(m, tea.KeyDown)
	if m.checkView.cursor != 1 {
		t.Fatalf("expected cursor at 1, got %d", m.checkView.cursor)
	}
	m = sendSpecial(m, tea.KeyUp)
	if m.checkView.cursor != 0 {
		t.Fatalf("expected cursor at 0, got %d", m.checkView.cursor)
	}
}

// ---------------------------------------------------------------------------
// 19. Check catalog
// ---------------------------------------------------------------------------

func TestCheckCatalog_COpens(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "c")
	if m.state != stateCheckCatalog {
		t.Fatalf("expected stateCheckCatalog, got %d", m.state)
	}
	if m.checkCatalog == nil {
		t.Fatal("expected checkCatalog to be non-nil")
	}
}

func TestCheckCatalog_EscReturns(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "c")
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateCheckView {
		t.Fatalf("expected stateCheckView, got %d", m.state)
	}
}

// ---------------------------------------------------------------------------
// 20. Diff view
// ---------------------------------------------------------------------------

func makeDiffModel(t *testing.T) RootModel {
	t.Helper()
	m := makeLoadedModel(t)
	m = sendKey(m, "m")

	certCount := 0
	for i := 0; i < len(m.visible) && certCount < 2; i++ {
		node := m.visible[i]
		if !node.IsBundle && !node.Locked && node.Item != nil &&
			node.Item.Type == certlib.ContentCertificate && node.Item.Certificate != nil {
			m.tree.cursor = i
			m = sendSpecial(m, tea.KeySpace)
			certCount++
		}
	}
	if certCount < 2 {
		t.Skip("not enough certs for diff")
	}
	m = sendKey(m, "d")
	if m.state != stateDiff {
		t.Skipf("diff did not open (state=%d)", m.state)
	}
	return m
}

func TestDiff_DTogglesDetailed(t *testing.T) {
	m := makeDiffModel(t)
	before := m.diffDetailed
	m = sendKey(m, "d")
	if m.diffDetailed == before {
		t.Fatal("expected diffDetailed to toggle")
	}
}

func TestDiff_CTogglesOnlyChanges(t *testing.T) {
	m := makeDiffModel(t)
	before := m.diffOnlyDiff
	m = sendKey(m, "c")
	if m.diffOnlyDiff == before {
		t.Fatal("expected diffOnlyDiff to toggle")
	}
}

func TestDiff_SSwapsSides(t *testing.T) {
	m := makeDiffModel(t)
	leftBefore := m.diffLeftCert
	rightBefore := m.diffRightCert
	m = sendKey(m, "s")
	if m.diffLeftCert == leftBefore && m.diffRightCert == rightBefore {
		t.Fatal("expected sides to swap")
	}
}

func TestDiff_ScrollArrows(t *testing.T) {
	m := makeDiffModel(t)
	m = sendSpecial(m, tea.KeyDown)
	if m.diffScroll != 1 {
		t.Fatalf("expected diffScroll=1, got %d", m.diffScroll)
	}
	m = sendSpecial(m, tea.KeyUp)
	if m.diffScroll != 0 {
		t.Fatalf("expected diffScroll=0, got %d", m.diffScroll)
	}
}

func TestDiff_EscReturnsToMultiSelect(t *testing.T) {
	m := makeDiffModel(t)
	m = sendSpecial(m, tea.KeyEsc)
	if m.state != stateMultiSelect {
		t.Fatalf("expected stateMultiSelect, got %d", m.state)
	}
}

// ---------------------------------------------------------------------------
// 21. Popup dialogs
// ---------------------------------------------------------------------------

func TestPopup_NoticeClosesOnEnter(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupNotice, message: "test notice"}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone after Enter, got %d", rm.popup.kind)
	}
}

func TestPopup_ErrorClosesOnEsc(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupError, message: "test error"}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone after Esc, got %d", rm.popup.kind)
	}
}

func TestPopup_NoticeStaysOnOtherKey(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupNotice, message: "test notice"}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	rm := result.(RootModel)
	// Non-closing keys (not enter/space/esc) keep the popup
	if rm.popup.kind == popupNone {
		t.Fatal("popup should not close on 'x' key")
	}
}

func TestPopup_ConfirmY(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?"}
	m.deleteFilePaths = []string{"/tmp/nonexistent-test-file.pem"}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	// doDeleteFiles uses pointer receiver, so result may be *RootModel.
	// The confirm popup is cleared, but since the file doesn't exist,
	// doDeleteFiles sets popupError. Verify confirm is gone (not popupConfirm).
	switch rm := result.(type) {
	case RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be cleared after y")
		}
	case *RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be cleared after y")
		}
	default:
		t.Fatalf("unexpected type %T", result)
	}
}

func TestPopup_ConfirmN(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?"}
	m.deleteFilePaths = []string{"/tmp/fake.pem"}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone after n, got %d", rm.popup.kind)
	}
	if len(rm.deleteFilePaths) != 0 {
		t.Fatal("expected deleteFilePaths to be cleared")
	}
}

func TestPopup_ConfirmLeftRightNavigation(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?"}
	m.deleteFilePaths = []string{"/tmp/fake.pem"}

	// Default selection is 0 (Yes)
	if m.popup.selected != 0 {
		t.Fatalf("expected default selected=0, got %d", m.popup.selected)
	}

	// Right arrow moves to No (1)
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	rm := result.(RootModel)
	if rm.popup.kind != popupConfirm {
		t.Fatal("popup should still be open after right arrow")
	}
	if rm.popup.selected != 1 {
		t.Fatalf("expected selected=1 after right, got %d", rm.popup.selected)
	}

	// Left arrow moves back to Yes (0)
	result, _ = rm.Update(tea.KeyMsg{Type: tea.KeyLeft})
	rm = result.(RootModel)
	if rm.popup.selected != 0 {
		t.Fatalf("expected selected=0 after left, got %d", rm.popup.selected)
	}

	// Tab moves to No (1)
	result, _ = rm.Update(tea.KeyMsg{Type: tea.KeyTab})
	rm = result.(RootModel)
	if rm.popup.selected != 1 {
		t.Fatalf("expected selected=1 after tab, got %d", rm.popup.selected)
	}

	// Shift+Tab moves back to Yes (0)
	result, _ = rm.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	rm = result.(RootModel)
	if rm.popup.selected != 0 {
		t.Fatalf("expected selected=0 after shift+tab, got %d", rm.popup.selected)
	}
}

func TestPopup_ConfirmEnterOnYes(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?"}
	m.deleteFilePaths = []string{"/tmp/nonexistent-test-file.pem"}
	// selected=0 (Yes) by default

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	switch rm := result.(type) {
	case RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be cleared after Enter on Yes")
		}
	case *RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be cleared after Enter on Yes")
		}
	default:
		t.Fatalf("unexpected type %T", result)
	}
}

func TestPopup_ConfirmEnterOnNo(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?", selected: 1}
	m.deleteFilePaths = []string{"/tmp/fake.pem"}

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone after Enter on No, got %d", rm.popup.kind)
	}
	if len(rm.deleteFilePaths) != 0 {
		t.Fatal("expected deleteFilePaths to be cleared after Enter on No")
	}
}

func TestPopup_ConfirmEscCancels(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Delete?"}
	m.deleteFilePaths = []string{"/tmp/fake.pem"}

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone after Esc, got %d", rm.popup.kind)
	}
	if len(rm.deleteFilePaths) != 0 {
		t.Fatal("expected deleteFilePaths to be cleared after Esc")
	}
}

func TestPopup_ConfirmActionEnterDismisses(t *testing.T) {
	// Use a pointer so the closure captures *RootModel, matching real usage
	// (e.g. openRemoteSaveAll has a pointer receiver).
	m := makeLoadedModel(t)
	mp := &m
	mp.popup = popupState{kind: popupConfirm, message: "Proceed?"}

	called := false
	mp.confirmAction = func(cm *RootModel) (tea.Model, tea.Cmd) {
		called = true
		return cm, nil
	}

	// Enter with selected=0 (Yes) triggers confirmAction
	result, _ := mp.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !called {
		t.Fatal("confirmAction should have been called")
	}
	switch rm := result.(type) {
	case RootModel:
		if rm.popup.kind != popupNone {
			t.Fatalf("expected popupNone, got %d", rm.popup.kind)
		}
		if rm.confirmAction != nil {
			t.Fatal("confirmAction should be nil after confirm")
		}
	case *RootModel:
		if rm.popup.kind != popupNone {
			t.Fatalf("expected popupNone, got %d", rm.popup.kind)
		}
		if rm.confirmAction != nil {
			t.Fatal("confirmAction should be nil after confirm")
		}
	default:
		t.Fatalf("unexpected type %T", result)
	}
}

func TestPopup_ConfirmActionEnterOnNoDismisses(t *testing.T) {
	m := makeLoadedModel(t)
	m.popup = popupState{kind: popupConfirm, message: "Proceed?", selected: 1}

	called := false
	m.confirmAction = func(cm *RootModel) (tea.Model, tea.Cmd) {
		called = true
		return cm, nil
	}

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if called {
		t.Fatal("confirmAction should NOT have been called when No is selected")
	}
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popupNone, got %d", rm.popup.kind)
	}
	if rm.confirmAction != nil {
		t.Fatal("confirmAction should be nil after cancel")
	}
}

func TestPopup_SaveAllConfirmDismisses(t *testing.T) {
	m := makeLoadedModel(t)

	cert := makeTestCert(t, "test.example.com")

	m.remoteResult = &certops.FetchRemoteCertResult{
		TargetResults: []certops.TargetFetchResult{
			{
				Target: "test.example.com:443",
				Certs: []certops.RemoteCertInfo{
					{
						Index: 0,
						Role:  "leaf",
						Cert:  &certlib.CertItem{Certificate: cert},
					},
				},
			},
		},
	}

	m.openRemoteSaveAll()
	if m.popup.kind != popupConfirm {
		t.Fatalf("expected popupConfirm after openRemoteSaveAll, got %d", m.popup.kind)
	}
	if m.confirmAction == nil {
		t.Fatal("expected confirmAction to be set")
	}

	// Confirm with 'y' — the closure runs on *RootModel and should clear popup
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	switch rm := result.(type) {
	case RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be dismissed after save all")
		}
	case *RootModel:
		if rm.popup.kind == popupConfirm {
			t.Fatal("confirm popup should be dismissed after save all")
		}
	default:
		t.Fatalf("unexpected type %T", result)
	}
}

func TestPopup_ShellRendersInfo(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "!")
	if m.popup.kind != popupShell {
		t.Fatalf("expected popupShell, got %d", m.popup.kind)
	}
	if len(m.popup.lines) == 0 {
		t.Fatal("expected popup.lines to have shell info")
	}
}

func TestPopup_ShellEnterClears(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "!")
	if m.popup.kind != popupShell {
		t.Skip("shell popup did not open")
	}
	// Enter on shell popup would spawn shell; in test context just verify it clears popup
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popup cleared after Enter, got %d", rm.popup.kind)
	}
}

func TestPopup_ShellOtherKeyClears(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "!")
	if m.popup.kind != popupShell {
		t.Skip("shell popup did not open")
	}
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	rm := result.(RootModel)
	if rm.popup.kind != popupNone {
		t.Fatalf("expected popup cleared, got %d", rm.popup.kind)
	}
}

// ---------------------------------------------------------------------------
// 22. Delete flow
// ---------------------------------------------------------------------------

func TestDelete_CtrlDShowsInlineConfirm(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if node.Container != nil && !node.Locked {
			m.tree.cursor = i
			break
		}
	}
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	rm := result.(RootModel)
	if !rm.confirmDelete {
		t.Fatal("expected confirmDelete=true")
	}
	if rm.deleteFilePath == "" {
		t.Fatal("expected deleteFilePath to be set")
	}
}

func TestDelete_InlineConfirmCancels(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if node.Container != nil && !node.Locked {
			m.tree.cursor = i
			break
		}
	}
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	rm := result.(RootModel)
	if !rm.confirmDelete {
		t.Skip("delete confirm not set")
	}
	// Press 'n' to cancel
	result2, _ := rm.handleKey(keyMsg("n"))
	rm2 := result2.(RootModel)
	if rm2.confirmDelete {
		t.Fatal("expected confirmDelete=false after n")
	}
	if rm2.deleteFilePath != "" {
		t.Fatal("expected deleteFilePath to be cleared")
	}
}

func TestDelete_InlineConfirmFooter(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if node.Container != nil && !node.Locked {
			m.tree.cursor = i
			break
		}
	}
	result, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyCtrlD})
	rm := result.(RootModel)
	if !rm.confirmDelete {
		t.Skip("delete confirm not set")
	}
	v := rm.View()
	if !strings.Contains(v, "Delete") || !strings.Contains(v, "[y/N]") {
		t.Errorf("expected delete confirmation in view, got: %s", v[:min(200, len(v))])
	}
}

// ---------------------------------------------------------------------------
// 23. Rescan
// ---------------------------------------------------------------------------

func TestRescan_RTriggersRescan(t *testing.T) {
	m := makeLoadedModel(t)
	m, cmd := sendKeyWithCmd(m, "r")
	if m.state != stateLoading {
		t.Fatalf("expected stateLoading after r, got %d", m.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd for rescan")
	}
}

// ---------------------------------------------------------------------------
// 24. Quit
// ---------------------------------------------------------------------------

func TestQuit_QFromTree(t *testing.T) {
	m := makeLoadedModel(t)
	_, cmd := sendKeyWithCmd(m, "q")
	if cmd == nil {
		t.Fatal("expected quit cmd")
	}
}

func TestQuit_CtrlCFromTree(t *testing.T) {
	m := makeLoadedModel(t)
	_, cmd := sendSpecialWithCmd(m, tea.KeyCtrlC)
	if cmd == nil {
		t.Fatal("expected quit cmd")
	}
}

func TestQuit_QInSearchTypesQ(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "/")
	// 'q' in search should type 'q', not quit
	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	rm := result.(RootModel)
	if rm.state != stateSearch {
		t.Fatalf("expected stateSearch, got %d", rm.state)
	}
	// cmd should NOT be tea.Quit
	if cmd != nil {
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			t.Fatal("q in search should not quit")
		}
	}
}

func TestQuit_QInFormDoesNotQuit(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	m = sendKey(m, "k")
	if m.state != stateForm {
		t.Skip("form did not open")
	}
	result, cmd := m.handleKey(keyMsg("q"))
	rm := result.(RootModel)
	if rm.state != stateForm {
		t.Fatalf("expected stateForm, got %d", rm.state)
	}
	if cmd != nil {
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			t.Fatal("q in form should not quit")
		}
	}
}

func TestQuit_QInMenuDoesNotQuit(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "n")
	if m.state != stateMenu {
		t.Skip("menu did not open")
	}
	result, cmd := m.handleKey(keyMsg("q"))
	rm := result.(RootModel)
	// q should close menu or do nothing, but not quit
	if cmd != nil {
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			t.Fatal("q in menu should not quit")
		}
	}
	_ = rm
}

// ---------------------------------------------------------------------------
// 25. Window resize
// ---------------------------------------------------------------------------

func TestResize_UpdatesLayout(t *testing.T) {
	m := makeLoadedModel(t)
	result, _ := m.Update(tea.WindowSizeMsg{Width: 160, Height: 50})
	rm := result.(RootModel)
	if rm.width != 160 {
		t.Fatalf("expected width=160, got %d", rm.width)
	}
	if rm.height != 50 {
		t.Fatalf("expected height=50, got %d", rm.height)
	}
}

func TestResize_NarrowTerminal(t *testing.T) {
	m := makeLoadedModel(t)
	result, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 20})
	rm := result.(RootModel)
	// Should not crash
	v := rm.View()
	if len(v) == 0 {
		t.Error("expected non-empty view at narrow width")
	}
}

func TestResize_BelowSplitThreshold(t *testing.T) {
	m := makeLoadedModel(t)
	// Open split first
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in split")
	}
	// Resize below threshold
	result, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	rm := result.(RootModel)
	// View should still render (fullscreen detail mode)
	v := rm.View()
	if len(v) == 0 {
		t.Error("expected non-empty view")
	}
}

// ---------------------------------------------------------------------------
// Extra: state machine edge cases
// ---------------------------------------------------------------------------

func TestTree_EnterOnBundleTogglesExpand(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if node.IsBundle {
			m.tree.cursor = i
			wasExpanded := node.Expanded
			m = sendSpecial(m, tea.KeyEnter)
			// If it was expanded, it should need password or toggle; check state
			if needsPassword(node) {
				if m.state != statePassword {
					t.Fatalf("expected statePassword for locked bundle, got %d", m.state)
				}
			} else {
				// Either toggled or opened detail
				found := false
				for _, n := range m.visible {
					if n.IsBundle && n.ContainerIdx == node.ContainerIdx {
						if n.Expanded != wasExpanded || m.state == stateSplit {
							found = true
						}
						break
					}
				}
				if !found && m.state != stateSplit {
					t.Log("Enter on bundle did something unexpected but didn't crash")
				}
			}
			return
		}
	}
	t.Skip("no bundle found")
}

func TestSplit_NavigationUpdatesDetail(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in split")
	}
	// Move focus to tree and navigate
	m.focus = focusTree
	m = sendSpecial(m, tea.KeyDown)
	// Should still be in split with cursor moved
	if m.state != stateSplit {
		t.Fatalf("expected stateSplit, got %d", m.state)
	}
}

func TestCheckView_EnterNavigatesToFile(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	if len(m.checkView.issues) == 0 {
		t.Skip("no issues to navigate to")
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state == stateCheckView {
		t.Fatal("expected to leave check view after Enter on issue")
	}
}

func TestCheckView_FilterAndClear(t *testing.T) {
	m := makeLoadedModel(t)
	m = sendKey(m, "W")
	m = sendKey(m, "/")
	if !m.checkView.filterActive {
		t.Fatal("expected filter active")
	}
	// Type some text
	m = sendKey(m, "e")
	m = sendKey(m, "x")
	if m.checkView.filterText != "ex" {
		t.Fatalf("expected filterText='ex', got %q", m.checkView.filterText)
	}
	// Esc clears filter
	m = sendSpecial(m, tea.KeyEsc)
	if m.checkView.filterActive {
		t.Fatal("expected filter inactive after Esc")
	}
	if m.checkView.filterText != "" {
		t.Fatalf("expected empty filterText, got %q", m.checkView.filterText)
	}
}

func TestDiff_PgDownPgUp(t *testing.T) {
	m := makeDiffModel(t)
	m = sendSpecial(m, tea.KeyPgDown)
	if m.diffScroll == 0 {
		t.Fatal("expected scroll to advance after PgDown")
	}
	scrollAfterDown := m.diffScroll
	m = sendSpecial(m, tea.KeyPgUp)
	if m.diffScroll >= scrollAfterDown {
		t.Fatal("expected scroll to decrease after PgUp")
	}
}

func TestDiff_HomeEnd(t *testing.T) {
	m := makeDiffModel(t)
	m = sendSpecial(m, tea.KeyEnd)
	if m.diffScroll == 0 {
		t.Fatal("expected scroll at end")
	}
	m = sendSpecial(m, tea.KeyHome)
	if m.diffScroll != 0 {
		t.Fatalf("expected scroll=0 after Home, got %d", m.diffScroll)
	}
}

// ---------------------------------------------------------------------------
// 5. Detail view (requires split with certs loaded)
// ---------------------------------------------------------------------------

func TestDetail_CertificateFields(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil &&
			node.Item.Type == certlib.ContentCertificate {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in split view")
	}
	v := m.View()
	for _, field := range []string{"Subject", "Issuer"} {
		if !strings.Contains(v, field) {
			t.Errorf("detail view missing %q", field)
		}
	}
}

func TestDetail_HistoryBackForward(t *testing.T) {
	m := makeLoadedModel(t)
	for i, node := range m.visible {
		if !node.IsBundle && !node.Locked && node.Item != nil &&
			node.Item.Type == certlib.ContentCertificate {
			m.tree.cursor = i
			break
		}
	}
	m = sendSpecial(m, tea.KeyEnter)
	if m.state != stateSplit {
		t.Skip("not in split view")
	}
	// Navigate to a different item via tree
	m.focus = focusTree
	m = sendSpecial(m, tea.KeyDown)
	m = sendSpecial(m, tea.KeyEnter)
	// Try history back
	m = sendKey(m, "[")
	// Just verify no crash
	if m.state != stateSplit && m.state != stateTree {
		t.Fatalf("unexpected state %d after history back", m.state)
	}
}

func TestActionMenu_StandaloneCertNoExtract(t *testing.T) {
	m := makeLoadedModel(t)

	// Find a standalone (non-bundle, non-child) cert node
	var found bool
	for _, node := range m.visible {
		if node.IsBundle || node.IsChild || node.Locked || node.Item == nil {
			continue
		}
		if node.Item.Type != certlib.ContentCertificate {
			continue
		}
		items := buildActionMenu(node)
		for _, item := range items {
			if item.kind == formExtract {
				t.Fatalf("standalone cert %q must not have Extract in action menu", node.Filename)
			}
		}
		found = true
		break
	}
	if !found {
		t.Skip("no standalone cert node found in test certs")
	}
}

// ---------------------------------------------------------------------------
// viewLoading progress counter tests
// ---------------------------------------------------------------------------

func TestViewLoading_ShowsProgressCounters(t *testing.T) {
	initStyles()
	initFormStyles()
	m := NewRootModel(".", certlib.ScanOptions{}, false,
		output.OutputOptions{}, TUIOptions{})
	m.width = 120
	m.height = 40
	m.state = stateLoading
	m.scanProgress.DirsScanned.Store(5)
	m.scanProgress.FilesProbed.Store(42)
	m.scanProgress.PasswordChecks.Store(100)

	v := m.View()
	for _, want := range []string{"Dirs scanned: 5", "Files probed: 42", "Passwords probed: 100"} {
		if !strings.Contains(v, want) {
			t.Errorf("View() missing %q", want)
		}
	}
}

func TestViewLoading_NoCountersAfterScanComplete(t *testing.T) {
	m := makeLoadedModel(t)
	m.state = stateLoading
	// After ScanCompleteMsg, scanProgress is nil
	v := m.View()
	if strings.Contains(v, "Dirs scanned:") {
		t.Error("View() should not contain progress counters after scan complete")
	}
}
