package tui

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

func makeTestRootModel() RootModel {
	initStyles()
	initFormStyles()

	nodes := []TreeNode{
		{
			ContainerIdx: 0,
			ItemIdx:      0,
			Filename:     "server.pem",
			ContentType:  "pem/cert",
			Subject:      "server.example.com",
			Item:         &certlib.CertItem{Type: certlib.ContentCertificate},
			Container:    &certlib.CertContainer{FilePath: "/tmp/server.pem"},
			Searchable:   "server.pem pem/cert",
		},
		{
			ContainerIdx: 1,
			ItemIdx:      0,
			Filename:     "server.key",
			ContentType:  "pem/key",
			Item:         &certlib.CertItem{Type: certlib.ContentPrivateKey},
			Container:    &certlib.CertContainer{FilePath: "/tmp/server.key"},
			Searchable:   "server.key pem/key",
		},
		{
			ContainerIdx: 2,
			ItemIdx:      -1,
			Filename:     "bundle.p12",
			ContentType:  "pkcs12",
			IsBundle:     true,
			Expanded:     true,
			ChildCount:   2,
			Container:    &certlib.CertContainer{FilePath: "/tmp/bundle.p12"},
			Searchable:   "bundle.p12 pkcs12",
		},
	}

	m := RootModel{
		state:         stateTree,
		width:         80,
		height:        40,
		tree:          treeModel{width: 80, viewportHeight: 36},
		allNodes:      nodes,
		visible:       nodes,
		scanPath:      "/tmp",
		multiSelect:   newMultiSelectModel(),
		passwordCache: newPasswordCache(),
	}
	return m
}

func TestState_NOpensNewMenu(t *testing.T) {
	m := makeTestRootModel()

	result, _ := m.handleKey(keyMsg("n"))
	rm := result.(RootModel)

	if rm.state != stateMenu {
		t.Fatalf("expected stateMenu, got %d", rm.state)
	}
	if rm.prevState != stateTree {
		t.Fatalf("expected prevState=stateTree, got %d", rm.prevState)
	}
	if !rm.menu.active {
		t.Fatal("expected menu to be active")
	}
}

func TestState_AOpensActionMenu(t *testing.T) {
	m := makeTestRootModel()
	m.tree.cursor = 0

	result, _ := m.handleKey(keyMsg("a"))
	rm := result.(RootModel)

	if rm.state != stateMenu {
		t.Fatalf("expected stateMenu, got %d", rm.state)
	}
	if rm.prevState != stateTree {
		t.Fatalf("expected prevState=stateTree, got %d", rm.prevState)
	}
	if rm.menu.title != "Actions" {
		t.Fatalf("expected menu title 'Actions', got %q", rm.menu.title)
	}
}

func TestState_MOpensMultiSelect(t *testing.T) {
	m := makeTestRootModel()

	result, _ := m.handleKey(keyMsg("m"))
	rm := result.(RootModel)

	if rm.state != stateMultiSelect {
		t.Fatalf("expected stateMultiSelect, got %d", rm.state)
	}
	if !rm.multiSelectActive {
		t.Fatal("expected multiSelectActive=true")
	}
	if rm.multiSelectReturn != stateTree {
		t.Fatalf("expected multiSelectReturn=stateTree, got %d", rm.multiSelectReturn)
	}
}

func TestState_MenuSelectOpensForm(t *testing.T) {
	m := makeTestRootModel()
	m.openNewMenu()

	result, _ := m.handleKey(keyMsg("k"))
	rm := result.(RootModel)

	if rm.state != stateForm {
		t.Fatalf("expected stateForm, got %d", rm.state)
	}
	if rm.activeForm == nil {
		t.Fatal("expected activeForm to be non-nil")
	}
	if rm.activeFormKind != formCreateKey {
		t.Fatalf("expected formCreateKey, got %d", rm.activeFormKind)
	}
}

func TestState_EscFromMenuToTree(t *testing.T) {
	m := makeTestRootModel()
	m.openNewMenu()

	result, _ := m.handleKey(specialKeyMsg(tea.KeyEsc))
	rm := result.(RootModel)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if rm.menu.active {
		t.Fatal("expected menu to be closed")
	}
}

func TestState_EscFromCleanForm(t *testing.T) {
	m := makeTestRootModel()
	m.prevState = stateTree
	form := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	form.width = 80
	form.height = 40
	m.activeForm = form
	m.activeFormKind = formCreateKey
	m.state = stateForm

	result, _ := m.handleKey(specialKeyMsg(tea.KeyEsc))
	rm := result.(RootModel)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if rm.activeForm != nil {
		t.Fatal("expected activeForm to be nil")
	}
	if rm.activeFormKind != formNone {
		t.Fatalf("expected formNone, got %d", rm.activeFormKind)
	}
}

func TestState_EscFromDirtyForm(t *testing.T) {
	m := makeTestRootModel()
	m.prevState = stateTree
	form := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	form.width = 80
	form.height = 40
	m.activeForm = form
	m.activeFormKind = formCreateKey
	m.state = stateForm

	// Make the form dirty by sending Right arrow to the focused algo field to change selection
	form.fields[form.focusIdx].Update(specialKeyMsg(tea.KeyRight))

	result, _ := m.handleKey(specialKeyMsg(tea.KeyEsc))
	rm := result.(RootModel)

	if rm.state != stateForm {
		t.Fatalf("expected stateForm (still), got %d", rm.state)
	}
	if !rm.confirmDiscard {
		t.Fatal("expected confirmDiscard=true")
	}
	if rm.activeForm == nil {
		t.Fatal("expected activeForm to still be present")
	}
}

func TestState_ConfirmDiscardYes(t *testing.T) {
	m := makeTestRootModel()
	m.prevState = stateTree
	form := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	form.width = 80
	form.height = 40
	m.activeForm = form
	m.activeFormKind = formCreateKey
	m.state = stateForm
	m.confirmDiscard = true

	result, _ := m.handleKey(keyMsg("y"))
	rm := result.(RootModel)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if rm.confirmDiscard {
		t.Fatal("expected confirmDiscard=false")
	}
	if rm.activeForm != nil {
		t.Fatal("expected activeForm to be nil")
	}
	if rm.activeFormKind != formNone {
		t.Fatalf("expected formNone, got %d", rm.activeFormKind)
	}
}

func TestState_ConfirmDiscardNo(t *testing.T) {
	m := makeTestRootModel()
	m.prevState = stateTree
	form := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	form.width = 80
	form.height = 40
	m.activeForm = form
	m.activeFormKind = formCreateKey
	m.state = stateForm
	m.confirmDiscard = true

	result, _ := m.handleKey(keyMsg("n"))
	rm := result.(RootModel)

	if rm.state != stateForm {
		t.Fatalf("expected stateForm, got %d", rm.state)
	}
	if rm.confirmDiscard {
		t.Fatal("expected confirmDiscard=false")
	}
	if rm.activeForm == nil {
		t.Fatal("expected activeForm to still be present")
	}
}

func TestState_FormSubmitSuccess(t *testing.T) {
	m := makeTestRootModel()
	m.prevState = stateTree
	form := buildCreateKeyForm("/tmp", certlib.KeyGenOptions{})
	form.width = 80
	form.height = 40
	m.activeForm = form
	m.activeFormKind = formCreateKey
	m.state = stateForm

	// Set output path so validation passes
	outputField := form.fieldByName("output")
	outputField.SetValue("/tmp/test.key")

	// Tab to submit button
	for {
		if _, ok := form.fields[form.focusIdx].(*submitButtonField); ok {
			break
		}
		next := form.nextFocusable()
		form.setFocus(next)
	}

	// Press enter on submit
	result, cmd := m.handleKey(specialKeyMsg(tea.KeyEnter))
	rm := result.(RootModel)

	if rm.state != stateLoading {
		t.Fatalf("expected stateLoading, got %d", rm.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd on form submit")
	}
}

// --- Options panel tests ---

func TestState_OOpensOptions(t *testing.T) {
	m := makeTestRootModel()

	result, _ := m.handleKey(keyMsg("O"))
	rm := result.(RootModel)

	if rm.state != stateOptions {
		t.Fatalf("expected stateOptions, got %d", rm.state)
	}
	if rm.optionsReturn != stateTree {
		t.Fatalf("expected optionsReturn=stateTree, got %d", rm.optionsReturn)
	}
}

func TestState_OOpensOptionsFromSplit(t *testing.T) {
	m := makeTestRootModel()
	m.state = stateSplit
	m.focus = focusTree

	result, _ := m.handleKey(keyMsg("O"))
	rm := result.(RootModel)

	if rm.state != stateOptions {
		t.Fatalf("expected stateOptions, got %d", rm.state)
	}
	if rm.optionsReturn != stateSplit {
		t.Fatalf("expected optionsReturn=stateSplit, got %d", rm.optionsReturn)
	}
}

func TestState_OptionsEscNoChange(t *testing.T) {
	m := makeTestRootModel()
	m.optionsEditor = newOptionsModel(scanOptionSnapshot{}, nil)
	m.optionsReturn = stateTree
	m.state = stateOptions

	result, cmd := m.handleKey(specialKeyMsg(tea.KeyEsc))
	rm := result.(RootModel)

	if rm.state != stateTree {
		t.Fatalf("expected stateTree, got %d", rm.state)
	}
	if cmd != nil {
		t.Fatal("expected nil cmd when no changes")
	}
}

func TestState_OptionsEscWithChange(t *testing.T) {
	m := makeTestRootModel()
	m.optionsEditor = newOptionsModel(scanOptionSnapshot{}, nil)
	m.optionsReturn = stateTree
	m.state = stateOptions

	// Toggle recursive to make a change
	m.optionsEditor.toggleBool("recursive")

	result, cmd := m.handleKey(specialKeyMsg(tea.KeyEsc))
	rm := result.(RootModel)

	if rm.state != stateLoading {
		t.Fatalf("expected stateLoading (rescan), got %d", rm.state)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd for rescan")
	}
	if !rm.scanOpts.Recursive {
		t.Fatal("expected scanOpts.Recursive=true after apply")
	}
}

func TestState_OptionsLockedIgnored(t *testing.T) {
	m := makeTestRootModel()
	m.lockedFlags = map[string]bool{"recursive": true}
	m.optionsEditor = newOptionsModel(scanOptionSnapshot{}, m.lockedFlags)
	m.state = stateOptions

	// Cursor is on "recursive" (index 0), press space to toggle
	m.handleKey(specialKeyMsg(tea.KeySpace))

	if m.optionsEditor.bools["recursive"] {
		t.Fatal("expected recursive unchanged when locked")
	}
	if m.optionsEditor.changed {
		t.Fatal("expected changed=false when toggle blocked by lock")
	}
}

func TestState_OptionsSave(t *testing.T) {
	m := makeTestRootModel()
	m.optionsEditor = newOptionsModel(scanOptionSnapshot{Recursive: true}, nil)
	m.state = stateOptions

	var called bool
	m.saveOptions = func(opts SavedOptions) error {
		called = true
		if !opts.Recursive {
			t.Fatal("expected saved Recursive=true")
		}
		return nil
	}

	result, cmd := m.handleKey(keyMsg("s"))
	rm := result.(RootModel)

	if !called {
		t.Fatal("expected saveOptions callback to be invoked")
	}
	if rm.statusMessage != "options saved to config" {
		t.Fatalf("expected success status message, got %q", rm.statusMessage)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd (status clear timer)")
	}
}

func TestState_OptionsSaveError(t *testing.T) {
	m := makeTestRootModel()
	m.optionsEditor = newOptionsModel(scanOptionSnapshot{}, nil)
	m.state = stateOptions

	m.saveOptions = func(opts SavedOptions) error {
		return fmt.Errorf("disk full")
	}

	result, _ := m.handleKey(keyMsg("s"))
	rm := result.(RootModel)

	if rm.statusMessage != "save failed: disk full" {
		t.Fatalf("expected error in status message, got %q", rm.statusMessage)
	}
}
