package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// The key policy in keypolicy.go: Ctrl+C quits anywhere, q quits from a tree
// and closes everything else, Esc never quits, ? opens the key overlay.

func isQuitCmd(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func sizedLoadedModel(t *testing.T) RootModel {
	m := makeLoadedModel(t)
	res, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	return res.(RootModel)
}

// nestedViews opens each pane or overlay from the tree and names the state it
// must return to when closed.
var nestedViews = []struct {
	name  string
	open  func(m RootModel) RootModel
	state viewState
	back  viewState
}{
	{"details pane", func(m RootModel) RootModel { return sendSpecial(m, tea.KeyEnter) }, stateSplit, stateTree},
	{"check view", func(m RootModel) RootModel { return sendKey(m, "W") }, stateCheckView, stateTree},
	{"check catalogue", func(m RootModel) RootModel { return sendKey(sendKey(m, "W"), "c") }, stateCheckCatalog, stateCheckView},
	{"options", func(m RootModel) RootModel { return sendKey(m, "O") }, stateOptions, stateTree},
	{"column editor", func(m RootModel) RootModel { return sendKey(m, "C") }, stateColumnEditor, stateTree},
	{"multi-select", func(m RootModel) RootModel { return sendKey(m, "m") }, stateMultiSelect, stateTree},
	{"action menu", func(m RootModel) RootModel { return sendKey(m, "n") }, stateMenu, stateTree},
}

func TestKeyPolicy_QAndEscCloseNestedViews(t *testing.T) {
	for _, tc := range nestedViews {
		for _, key := range []string{"q", "esc"} {
			t.Run(tc.name+"/"+key, func(t *testing.T) {
				m := tc.open(sizedLoadedModel(t))
				if m.state != tc.state {
					t.Fatalf("setup: state %d, want %d", m.state, tc.state)
				}
				var res tea.Model
				var cmd tea.Cmd
				if key == "esc" {
					res, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
				} else {
					res, cmd = m.Update(keyMsg("q"))
				}
				got := res.(RootModel)
				if isQuitCmd(cmd) {
					t.Fatalf("%s quit the program from %s", key, tc.name)
				}
				if got.state != tc.back {
					t.Errorf("%s from %s: state %d, want %d", key, tc.name, got.state, tc.back)
				}
			})
		}
	}
}

func TestKeyPolicy_CtrlCQuitsFromNestedViews(t *testing.T) {
	for _, tc := range nestedViews {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.open(sizedLoadedModel(t))
			if m.state != tc.state {
				t.Fatalf("setup: state %d, want %d", m.state, tc.state)
			}
			if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC}); !isQuitCmd(cmd) {
				t.Errorf("ctrl+c did not quit from %s", tc.name)
			}
		})
	}
}

func TestKeyPolicy_TreeQuitsOnQOnly(t *testing.T) {
	m := sizedLoadedModel(t)
	if _, cmd := m.Update(keyMsg("q")); !isQuitCmd(cmd) {
		t.Error("q at the tree must quit")
	}
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if isQuitCmd(cmd) || res.(RootModel).state != stateTree {
		t.Error("Esc at the top of the tree must do nothing, never quit")
	}
}

func TestKeyPolicy_QIsNeverAMenuHotkey(t *testing.T) {
	m := sizedLoadedModel(t)
	menus := [][]menuItem{buildFunctionsMenu(), buildNewMenu()}
	for _, n := range m.allNodes {
		menus = append(menus, buildActionMenu(n))
	}
	for _, items := range menus {
		for _, it := range items {
			if strings.EqualFold(it.key, "q") {
				t.Errorf("menu item %q is bound to q, which closes the menu", it.label)
			}
		}
	}
}

func TestKeyPolicy_HelpOverlayListsEveryKeyOfTheView(t *testing.T) {
	for _, tc := range append([]struct {
		name  string
		open  func(m RootModel) RootModel
		state viewState
		back  viewState
	}{{"tree", func(m RootModel) RootModel { return m }, stateTree, stateTree}}, nestedViews[:6]...) {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.open(sizedLoadedModel(t))
			hints, _ := m.currentHints()
			if len(hints) == 0 {
				t.Fatalf("no hints for %s", tc.name)
			}
			res, cmd := m.Update(keyMsg("?"))
			got := res.(RootModel)
			if isQuitCmd(cmd) || got.popup.kind != popupHelp || got.state != tc.state {
				t.Fatalf("? in %s: popup=%d state=%d", tc.name, got.popup.kind, got.state)
			}
			view := got.View()
			if !strings.Contains(view, helpPopupTitle) {
				t.Errorf("overlay title missing:\n%s", view)
			}
			for _, h := range hints {
				if h.Key == "" {
					continue
				}
				if !strings.Contains(view, h.Key) || !strings.Contains(view, h.Label) {
					t.Errorf("overlay for %s lacks [%s] %s", tc.name, h.Key, h.Label)
				}
			}
			res, _ = got.Update(keyMsg("?"))
			if closed := res.(RootModel); closed.popup.kind != popupNone || closed.state != tc.state {
				t.Errorf("? must close the overlay and stay in %s", tc.name)
			}
			res, _ = got.Update(keyMsg("q"))
			if closed := res.(RootModel); closed.popup.kind != popupNone || closed.state != tc.state {
				t.Errorf("q must close the overlay without leaving %s", tc.name)
			}
		})
	}
}

func TestKeyPolicy_QuestionMarkIsTypedInTextInputs(t *testing.T) {
	m := sendKey(sizedLoadedModel(t), "/")
	res, _ := m.Update(keyMsg("?"))
	got := res.(RootModel)
	if got.popup.kind != popupNone || got.state != stateSearch {
		t.Fatalf("? in the search bar must be typed, got popup=%d state=%d", got.popup.kind, got.state)
	}

	m = sendKey(sendKey(sizedLoadedModel(t), "W"), "/")
	res, _ = m.Update(keyMsg("?"))
	got = res.(RootModel)
	if got.popup.kind != popupNone || !strings.Contains(got.checkView.filterText, "?") {
		t.Fatalf("? in the check filter must be typed, got popup=%d filter=%q", got.popup.kind, got.checkView.filterText)
	}
}
