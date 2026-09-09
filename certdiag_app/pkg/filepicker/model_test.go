package filepicker

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestModel_Init(t *testing.T) {
	dir := setupTestDir(t)

	m := makeTestModel(t, TypeOpenFile, dir)
	if len(m.entries) == 0 {
		t.Fatal("entries should be loaded")
	}
	if m.cursor != 0 {
		t.Errorf("cursor=%d, want 0", m.cursor)
	}

	// TypeSaveFile has filename input
	ms := makeTestModel(t, TypeSaveFile, dir)
	if ms.filename.charLimit != 255 {
		t.Errorf("filename charLimit=%d, want 255", ms.filename.charLimit)
	}

	// TypeOpenDir
	md := makeTestModel(t, TypeOpenDir, dir)
	if len(md.entries) == 0 {
		t.Fatal("OpenDir should load entries")
	}
}

func TestModel_WindowSize(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	m := newPickerModel(cfg, dir)

	// Before window size, View returns ""
	if m.View() != "" {
		t.Error("View should be empty before WindowSizeMsg")
	}

	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(pickerModel)
	if m.termW != 100 || m.termH != 30 {
		t.Errorf("termW=%d termH=%d, want 100, 30", m.termW, m.termH)
	}
}

func TestModel_Navigation_UpDown(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	start := m.cursor
	m = sendKey(m, "down")
	if m.cursor != start+1 {
		t.Errorf("down: cursor=%d, want %d", m.cursor, start+1)
	}

	m = sendKey(m, "up")
	if m.cursor != start {
		t.Errorf("up: cursor=%d, want %d", m.cursor, start)
	}

	// Up at top stays at 0
	m.cursor = 0
	m = sendKey(m, "up")
	if m.cursor != 0 {
		t.Errorf("up at 0: cursor=%d, want 0", m.cursor)
	}

	// Down at bottom stays at last
	last := len(m.entries) - 1
	m.cursor = last
	m = sendKey(m, "down")
	if m.cursor != last {
		t.Errorf("down at end: cursor=%d, want %d", m.cursor, last)
	}

	// Multiple moves
	m.cursor = 0
	m = sendKey(m, "down")
	m = sendKey(m, "down")
	m = sendKey(m, "down")
	if m.cursor != 3 {
		t.Errorf("triple down: cursor=%d, want 3", m.cursor)
	}

	m = sendKey(m, "up")
	if m.cursor != 2 {
		t.Errorf("after up: cursor=%d, want 2", m.cursor)
	}
}

func TestModel_Navigation_PgUpPgDown(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	m.cursor = 0
	m = sendKey(m, "pgdown")
	if m.cursor == 0 {
		t.Error("pgdown should move cursor")
	}

	// PgDown shouldn't exceed entries
	for i := 0; i < 10; i++ {
		m = sendKey(m, "pgdown")
	}
	if m.cursor >= len(m.entries) {
		t.Errorf("pgdown overflow: cursor=%d, len=%d", m.cursor, len(m.entries))
	}

	// PgUp
	m = sendKey(m, "pgup")
	prev := m.cursor
	m = sendKey(m, "pgup")
	if m.cursor > prev {
		t.Error("pgup should move cursor up")
	}

	// PgUp at top
	for i := 0; i < 10; i++ {
		m = sendKey(m, "pgup")
	}
	if m.cursor != 0 {
		t.Errorf("pgup at top: cursor=%d, want 0", m.cursor)
	}
}

func TestModel_Navigation_HomeEnd(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	m.cursor = 3
	m = sendKey(m, "home")
	if m.cursor != 0 {
		t.Errorf("home: cursor=%d, want 0", m.cursor)
	}

	m = sendKey(m, "end")
	if m.cursor != len(m.entries)-1 {
		t.Errorf("end: cursor=%d, want %d", m.cursor, len(m.entries)-1)
	}
}

func TestModel_Navigation_LetterJump(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Jump to 'a' (adir)
	m = sendKey(m, "a")
	if m.cursor < 0 || m.cursor >= len(m.entries) {
		t.Fatal("cursor out of range")
	}
	if m.entries[m.cursor].name != "adir" {
		t.Errorf("jump 'a': got %q, want 'adir'", m.entries[m.cursor].name)
	}

	// Jump to 'z' (zdir)
	m = sendKey(m, "z")
	if m.entries[m.cursor].name != "zdir" {
		t.Errorf("jump 'z': got %q, want 'zdir'", m.entries[m.cursor].name)
	}

	// Jump to 'x' (no match - cursor stays)
	prev := m.cursor
	m = sendKey(m, "x")
	if m.cursor != prev {
		t.Errorf("jump 'x': cursor moved from %d to %d", prev, m.cursor)
	}
}

func TestModel_DirectoryEntry(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Find subdir and enter it
	for i, e := range m.entries {
		if e.name == "subdir" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, "enter")
	if m.currentDir != filepath.Join(dir, "subdir") {
		t.Errorf("enter dir: currentDir=%q, want %q", m.currentDir, filepath.Join(dir, "subdir"))
	}

	// ".." goes back
	m.cursor = 0 // ".." is first
	m = sendKey(m, "enter")
	if m.currentDir != dir {
		t.Errorf("enter '..': currentDir=%q, want %q", m.currentDir, dir)
	}

	// Backspace also goes to parent
	for i, e := range m.entries {
		if e.name == "subdir" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, "enter")
	m = sendKey(m, "backspace")
	if m.currentDir != dir {
		t.Errorf("backspace: currentDir=%q, want %q", m.currentDir, dir)
	}
}

func TestModel_DirectoryExit_RemembersCursor(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Enter subdir
	for i, e := range m.entries {
		if e.name == "subdir" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, "enter")

	// Go back up
	m = sendKey(m, "backspace")

	// Cursor should be on "subdir"
	if m.cursor < len(m.entries) && m.entries[m.cursor].name != "subdir" {
		t.Errorf("after navigateUp, cursor on %q, want 'subdir'", m.entries[m.cursor].name)
	}
}

func TestModel_SearchMode(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// "/" enters search mode
	m = sendKey(m, "/")
	if !m.searchMode {
		t.Error("'/' should enter search mode")
	}

	// Typing filters
	m = sendKey(m, "p")
	m = sendKey(m, "e")
	m = sendKey(m, "m")
	if m.searchQuery != "pem" {
		t.Errorf("searchQuery=%q, want 'pem'", m.searchQuery)
	}

	// Results should be filtered
	found := false
	for _, e := range m.entries {
		if e.name != ".." && e.name == "file1.pem" {
			found = true
		}
	}
	if !found {
		t.Error("file1.pem should be in filtered results")
	}

	// ".." always visible
	if len(m.entries) == 0 || m.entries[0].name != ".." {
		t.Error("'..' should always be visible in search")
	}

	// Backspace in search
	m = sendKey(m, "backspace")
	if m.searchQuery != "pe" {
		t.Errorf("after backspace: searchQuery=%q, want 'pe'", m.searchQuery)
	}

	// Esc clears search
	m = sendKey(m, "esc")
	if m.searchMode {
		t.Error("esc should exit search mode")
	}
	if m.searchQuery != "" {
		t.Error("search query should be cleared")
	}

	// Case-insensitive
	m = sendKey(m, "/")
	m = sendKey(m, "F")
	m = sendKey(m, "I")
	m = sendKey(m, "L")
	m = sendKey(m, "E")
	foundCount := 0
	for _, e := range m.entries {
		if e.name != ".." {
			foundCount++
		}
	}
	if foundCount == 0 {
		t.Error("case-insensitive search should find files")
	}
}

func TestModel_FocusCycling(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	if m.focus != focusList {
		t.Errorf("initial focus=%d, want focusList", m.focus)
	}

	// Tab forward
	m = sendKey(m, "tab")
	if m.focus == focusList {
		t.Error("tab should move focus away from list")
	}

	// Shift+tab backward
	m = sendKey(m, "shift+tab")
	if m.focus != focusList {
		t.Errorf("shift+tab: focus=%d, want focusList", m.focus)
	}

	// Wraps around: keep pressing tab
	order := m.focusOrder()
	for i := 0; i < len(order)+1; i++ {
		m = sendKey(m, "tab")
	}
	if m.focus != order[1] {
		t.Errorf("wrap: focus=%d, want %d", m.focus, order[1])
	}

	// TypeSaveFile includes focusFilename
	ms := makeTestModel(t, TypeSaveFile, dir)
	ms = sendKey(ms, "tab")
	if ms.focus != focusFilename {
		t.Errorf("SaveFile tab: focus=%d, want focusFilename", ms.focus)
	}
}

func TestModel_FocusOrder(t *testing.T) {
	dir := setupTestDir(t)

	// OpenFile with filter
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}
	m := makeTestModelWithConfig(t, cfg, dir)
	order := m.focusOrder()
	if !containsFocus(order, focusShowHidden) {
		t.Error("OpenFile+filter should include focusShowHidden")
	}

	// OpenFile with filterOverridable
	cfg2 := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}, filterOverridable: true}
	m2 := makeTestModelWithConfig(t, cfg2, dir)
	order2 := m2.focusOrder()
	if !containsFocus(order2, focusAllFiles) {
		t.Error("OpenFile+filterOverridable should include focusAllFiles")
	}

	// OpenDir has no filter bar
	md := makeTestModel(t, TypeOpenDir, dir)
	orderD := md.focusOrder()
	if containsFocus(orderD, focusShowHidden) {
		t.Error("OpenDir should not include focusShowHidden")
	}
}

func TestShowsFilterBar(t *testing.T) {
	dir := setupTestDir(t)

	// OpenFile with fileFilter -> true
	m1 := makeTestModelWithConfig(t, &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}, dir)
	if !m1.showsFilterBar() {
		t.Error("OpenFile+fileFilter should show filter bar")
	}

	// OpenFile without fileFilter, with multiSelect -> true
	m2 := makeTestModelWithConfig(t, &config{dialogType: TypeOpenFile, multiSelect: true}, dir)
	if !m2.showsFilterBar() {
		t.Error("OpenFile+multiSelect should show filter bar")
	}

	// OpenFile without fileFilter, without multiSelect -> false
	m3 := makeTestModelWithConfig(t, &config{dialogType: TypeOpenFile}, dir)
	if m3.showsFilterBar() {
		t.Error("OpenFile without filter/multiSelect should not show filter bar")
	}

	// OpenDir -> false
	m4 := makeTestModel(t, TypeOpenDir, dir)
	if m4.showsFilterBar() {
		t.Error("OpenDir should not show filter bar")
	}

	// SaveFile without extensions -> false
	m5 := makeTestModel(t, TypeSaveFile, dir)
	if m5.showsFilterBar() {
		t.Error("SaveFile without extensions should not show filter bar")
	}

	// SaveFile with extensions -> false
	m6 := makeTestModelWithConfig(t, &config{dialogType: TypeSaveFile, saveExtensions: []string{".pem", ".crt"}}, dir)
	if m6.showsFilterBar() {
		t.Error("SaveFile with extensions should not show filter bar")
	}
}

func TestFocusOrder_SaveFileWithExtensions(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, saveExtensions: []string{".pem", ".crt"}}
	m := makeTestModelWithConfig(t, cfg, dir)
	order := m.focusOrder()

	if containsFocus(order, focusShowHidden) {
		t.Error("SaveFile+extensions should not include focusShowHidden")
	}
	if containsFocus(order, focusAllFiles) {
		t.Error("SaveFile+extensions should not include focusAllFiles")
	}
	if !containsFocus(order, focusFilename) {
		t.Error("SaveFile+extensions should include focusFilename")
	}
}

func TestListHeight_SaveFileWithExtensions(t *testing.T) {
	dir := setupTestDir(t)

	cfgExt := &config{dialogType: TypeSaveFile, saveExtensions: []string{".csr", ".pem"}}
	mExt := newPickerModel(cfgExt, dir)
	mExt.termW = 100
	mExt.termH = 30

	h := mExt.listHeight()
	if h < 1 {
		t.Errorf("SaveFile+extensions listHeight should be >= 1, got %d", h)
	}

	// showsFilterBar must be false, so no +2 overhead for filter bar
	if mExt.showsFilterBar() {
		t.Error("SaveFile+extensions should not report filter bar")
	}
}

func TestModel_EscCancels(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	updated, cmd := m.Update(keyMsg("esc"))
	m = updated.(pickerModel)
	if m.resultErr != ErrCancelled {
		t.Error("esc should set ErrCancelled")
	}
	if cmd == nil {
		t.Error("esc should return tea.Quit")
	}

	// Esc in search mode clears search instead
	m2 := makeTestModel(t, TypeOpenFile, dir)
	m2 = sendKey(m2, "/")
	m2 = sendKey(m2, "t")
	m2 = sendKey(m2, "esc")
	if m2.searchMode {
		t.Error("esc in search should clear search")
	}
	if m2.resultErr == ErrCancelled {
		t.Error("esc in search should NOT cancel dialog")
	}
}

func TestModel_ShowHiddenToggle(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	if m.showHidden {
		t.Error("showHidden should be false initially")
	}
	hasHidden := containsEntryName(m.entries, ".hidden")
	if hasHidden {
		t.Error("hidden files should not be visible initially")
	}

	// "." toggles
	m = sendKey(m, ".")
	if !m.showHidden {
		t.Error(". should toggle showHidden to true")
	}
	if !containsEntryName(m.entries, ".hidden") {
		t.Error(".hidden should be visible after .")
	}

	// Toggle back
	m = sendKey(m, ".")
	if m.showHidden {
		t.Error(". again should toggle showHidden to false")
	}
}

func TestModel_AllFilesToggle(t *testing.T) {
	dir := setupTestDir(t)

	// With filterOverridable
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}, filterOverridable: true}
	m := makeTestModelWithConfig(t, cfg, dir)

	m = sendKey(m, "ctrl+a")
	if !m.filterAll {
		t.Error("ctrl+a should toggle filterAll")
	}

	// Without filterOverridable - no-op
	cfg2 := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}
	m2 := makeTestModelWithConfig(t, cfg2, dir)
	m2 = sendKey(m2, "ctrl+a")
	if m2.filterAll {
		t.Error("ctrl+a without filterOverridable should be no-op")
	}
}

func TestModel_MultiSelect(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, multiSelect: true}
	m := makeTestModelWithConfig(t, cfg, dir)

	// Move to a file and select with space
	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, " ")
	path := filepath.Join(dir, "file1.pem")
	if !m.selected[path] {
		t.Error("space should select file")
	}

	// Deselect
	m = sendKey(m, " ")
	if m.selected[path] {
		t.Error("space again should deselect")
	}

	// Dirs can't be selected
	for i, e := range m.entries {
		if e.name == "adir" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, " ")
	if len(m.selected) != 0 {
		t.Error("should not be able to select directories")
	}

	// ".." can't be selected
	m.cursor = 0
	m = sendKey(m, " ")
	if len(m.selected) != 0 {
		t.Error("should not be able to select '..'")
	}

	// Non-passing files can't be selected (with filter)
	cfg2 := &config{dialogType: TypeOpenFile, multiSelect: true, fileFilter: []string{".pem"}}
	m2 := makeTestModelWithConfig(t, cfg2, dir)
	for i, e := range m2.entries {
		if e.name == "notes.txt" {
			m2.cursor = i
			break
		}
	}
	m2 = sendKey(m2, " ")
	if len(m2.selected) != 0 {
		t.Error("non-passing file should not be selectable")
	}
}

func TestModel_ActivateEntry_OpenFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Enter on passing file -> Quit
	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath != filepath.Join(dir, "file1.pem") {
		t.Errorf("confirmedPath=%q, want %q", m.confirmedPath, filepath.Join(dir, "file1.pem"))
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}

	// Non-passing file -> no-op (with filter)
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}
	m2 := makeTestModelWithConfig(t, cfg, dir)
	for i, e := range m2.entries {
		if e.name == "notes.txt" {
			m2.cursor = i
			break
		}
	}
	updated2, cmd2 := m2.Update(keyMsg("enter"))
	m2 = updated2.(pickerModel)
	if m2.confirmedPath != "" {
		t.Error("non-passing file should not set confirmedPath")
	}
	if cmd2 != nil {
		t.Error("non-passing file should not quit")
	}
}

func TestModel_ActivateEntry_SaveFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)

	// Enter on file fills filename
	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, "enter")
	if m.filename.Value() != "file1.pem" {
		t.Errorf("filename=%q, want 'file1.pem'", m.filename.Value())
	}

	// Enter on ".." navigates
	m.cursor = 0
	m = sendKey(m, "enter")
	if m.currentDir == filepath.Join(dir, "subdir") {
		t.Error("enter on '..' should navigate up, not into subdir")
	}
}

func TestModel_DoOK_OpenFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// OK on file
	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}
	m.focus = focusOK
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath == "" {
		t.Error("OK on file should set confirmedPath")
	}
	if cmd == nil {
		t.Error("OK should return tea.Quit")
	}

	// OK with multiselect+selected
	cfg := &config{dialogType: TypeOpenFile, multiSelect: true}
	m2 := makeTestModelWithConfig(t, cfg, dir)
	path1 := filepath.Join(dir, "file1.pem")
	m2.selected[path1] = true
	m2.focus = focusOK
	updated2, cmd2 := m2.Update(keyMsg("enter"))
	m2 = updated2.(pickerModel)
	if len(m2.results) == 0 {
		t.Error("OK with multiselect should set results")
	}
	if cmd2 == nil {
		t.Error("should return tea.Quit")
	}

	// OK on dir -> no-op
	m3 := makeTestModel(t, TypeOpenFile, dir)
	for i, e := range m3.entries {
		if e.name == "adir" {
			m3.cursor = i
			break
		}
	}
	m3.focus = focusOK
	updated3, cmd3 := m3.Update(keyMsg("enter"))
	m3 = updated3.(pickerModel)
	if m3.confirmedPath != "" {
		t.Error("OK on directory should not set confirmedPath")
	}
	if cmd3 != nil {
		t.Error("OK on dir should not quit")
	}
}

func TestModel_DoOK_OpenDir(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenDir, dir)

	m.focus = focusOK
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath != dir {
		t.Errorf("OK OpenDir: confirmedPath=%q, want %q", m.confirmedPath, dir)
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}
}

func TestModel_DoOK_SaveFile(t *testing.T) {
	dir := setupTestDir(t)

	// Empty filename -> alert
	m := makeTestModel(t, TypeSaveFile, dir)
	m.focus = focusOK
	m = sendKey(m, "enter")
	if m.modal != modalAlert {
		t.Error("empty filename should show alert")
	}

	// Valid filename -> confirm
	m2 := makeTestModel(t, TypeSaveFile, dir)
	m2.filename.SetValue("newfile.pem")
	m2.focus = focusOK
	updated, cmd := m2.Update(keyMsg("enter"))
	m2 = updated.(pickerModel)
	if m2.confirmedPath != filepath.Join(dir, "newfile.pem") {
		t.Errorf("save: confirmedPath=%q, want %q", m2.confirmedPath, filepath.Join(dir, "newfile.pem"))
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}

	// Wrong ext + strict -> alert
	cfg := &config{dialogType: TypeSaveFile, saveExtensions: []string{".pem"}, extensionMode: ExtensionModeStrict}
	m3 := makeTestModelWithConfig(t, cfg, dir)
	m3.filename.SetValue("file.txt")
	m3.focus = focusOK
	m3 = sendKey(m3, "enter")
	if m3.modal != modalAlert {
		t.Error("wrong ext + strict should show alert")
	}

	// Wrong ext + confirm -> modal
	cfg2 := &config{dialogType: TypeSaveFile, saveExtensions: []string{".pem"}, extensionMode: ExtensionModeConfirm}
	m4 := makeTestModelWithConfig(t, cfg2, dir)
	m4.filename.SetValue("file.txt")
	m4.focus = focusOK
	m4 = sendKey(m4, "enter")
	if m4.modal != modalConfirm {
		t.Errorf("wrong ext + confirm: modal=%d, want modalConfirm", m4.modal)
	}
}

func TestModel_DoSave_OverwriteCheck(t *testing.T) {
	dir := setupTestDir(t)

	// Existing file -> confirm modal
	cfg := &config{dialogType: TypeSaveFile, checkFileExists: true}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.filename.SetValue("file1.pem")
	m.focus = focusOK
	m = sendKey(m, "enter")
	if m.modal != modalConfirm {
		t.Error("existing file with checkFileExists should show confirm modal")
	}
	if m.confirm.kind != confirmOverwrite {
		t.Error("confirm kind should be confirmOverwrite")
	}

	// checkFileExists=false -> proceeds
	cfg2 := &config{dialogType: TypeSaveFile, checkFileExists: false}
	m2 := makeTestModelWithConfig(t, cfg2, dir)
	m2.filename.SetValue("file1.pem")
	m2.focus = focusOK
	updated, cmd := m2.Update(keyMsg("enter"))
	m2 = updated.(pickerModel)
	if m2.confirmedPath != filepath.Join(dir, "file1.pem") {
		t.Errorf("no overwrite check: confirmedPath=%q", m2.confirmedPath)
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}
}

func TestModel_ClampScroll(t *testing.T) {
	m := pickerModel{}
	m.cursor = 0
	m.scroll = 5
	m.clampScroll(10)
	if m.scroll != 0 {
		t.Errorf("cursor below scroll: scroll=%d, want 0", m.scroll)
	}

	m.cursor = 15
	m.scroll = 0
	m.clampScroll(10)
	if m.scroll != 6 {
		t.Errorf("cursor above scroll+listH: scroll=%d, want 6", m.scroll)
	}

	m.scroll = -1
	m.cursor = 0
	m.clampScroll(10)
	if m.scroll != 0 {
		t.Errorf("negative scroll: scroll=%d, want 0", m.scroll)
	}

	m.cursor = 5
	m.scroll = 3
	m.clampScroll(10)
	if m.scroll != 3 {
		t.Errorf("normal: scroll=%d, want 3", m.scroll)
	}
}

func TestModel_BoxDims(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}

	// Min clamping
	m := newPickerModel(cfg, dir)
	m.termW = 50
	m.termH = 10
	w, h := m.boxDims()
	if w != 80 {
		t.Errorf("min w: got %d, want 80", w)
	}
	if h != 22 {
		t.Errorf("min h: got %d, want 22", h)
	}

	// Max clamping
	m.termW = 200
	m.termH = 60
	w, h = m.boxDims()
	if w != 120 {
		t.Errorf("max w: got %d, want 120", w)
	}
	if h != 40 {
		t.Errorf("max h: got %d, want 40", h)
	}

	// Normal
	m.termW = 100
	m.termH = 30
	w, h = m.boxDims()
	if w != 100 {
		t.Errorf("normal w: got %d, want 100", w)
	}
	if h != 30 {
		t.Errorf("normal h: got %d, want 30", h)
	}

	// Edge: exactly at boundary
	m.termW = 80
	m.termH = 22
	w, h = m.boxDims()
	if w != 80 || h != 22 {
		t.Errorf("boundary: got %d,%d want 80,22", w, h)
	}
}

func TestModel_F5Refresh(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	initialCount := len(m.entries)

	// Add a new file
	os.WriteFile(filepath.Join(dir, "newfile.pem"), []byte("new"), 0644)

	// F5 should reload
	m = sendKey(m, "f5")
	if len(m.entries) != initialCount+1 {
		t.Errorf("F5: entries=%d, want %d", len(m.entries), initialCount+1)
	}
}

func TestModel_F7NewDir(t *testing.T) {
	dir := setupTestDir(t)

	// F7 with allowNewDir -> modal
	cfg := &config{dialogType: TypeOpenFile, allowNewDir: true}
	m := makeTestModelWithConfig(t, cfg, dir)
	m = sendKey(m, "f7")
	if m.modal != modalNewDir {
		t.Error("F7 with allowNewDir should open newDir modal")
	}

	// F7 without allowNewDir -> no-op
	m2 := makeTestModel(t, TypeOpenFile, dir)
	m2 = sendKey(m2, "f7")
	if m2.modal != modalNone {
		t.Error("F7 without allowNewDir should be no-op")
	}
}

func containsFocus(order []focusTarget, target focusTarget) bool {
	for _, f := range order {
		if f == target {
			return true
		}
	}
	return false
}

func containsEntryName(entries []fileEntry, name string) bool {
	for _, e := range entries {
		if e.name == name {
			return true
		}
	}
	return false
}
