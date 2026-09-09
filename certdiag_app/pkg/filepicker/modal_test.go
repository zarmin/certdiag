package filepicker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Alert Modal ---

func TestAlertModal_Dismiss(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.modal = modalAlert
	m.alert = alertState{message: "test error"}

	// Enter dismisses
	m1 := sendKey(m, "enter")
	if m1.modal != modalNone {
		t.Error("enter should dismiss alert")
	}

	// Space dismisses
	m.modal = modalAlert
	m2 := sendKey(m, " ")
	if m2.modal != modalNone {
		t.Error("space should dismiss alert")
	}

	// Esc dismisses
	m.modal = modalAlert
	m3 := sendKey(m, "esc")
	if m3.modal != modalNone {
		t.Error("esc should dismiss alert")
	}
}

func TestAlertModal_SaveFileReturnsFocus(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalAlert
	m.alert = alertState{message: "error"}

	m = sendKey(m, "enter")
	if m.focus != focusFilename {
		t.Errorf("after alert dismiss in SaveFile: focus=%d, want focusFilename", m.focus)
	}
}

// --- Confirm Modal ---

func TestConfirmModal_ToggleYesNo(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{kind: confirmOverwrite, yesNo: false}

	// Left/Right toggles
	m = sendKey(m, "right")
	if !m.confirm.yesNo {
		t.Error("right should toggle to Yes")
	}
	m = sendKey(m, "left")
	if m.confirm.yesNo {
		t.Error("left should toggle to No")
	}

	// Tab toggles
	m = sendKey(m, "tab")
	if !m.confirm.yesNo {
		t.Error("tab should toggle to Yes")
	}

	// Initial yesNo is false
	m2 := makeTestModel(t, TypeSaveFile, dir)
	m2.filename.SetValue("file1.pem")
	m2.modal = modalConfirm
	m2.confirm = confirmState{kind: confirmOverwrite, payload: filepath.Join(dir, "file1.pem"), yesNo: false}
	if m2.confirm.yesNo {
		t.Error("initial yesNo should be false")
	}
}

func TestConfirmModal_EnterYes_Overwrite(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{
		kind:    confirmOverwrite,
		payload: filepath.Join(dir, "file1.pem"),
		yesNo:   true,
	}

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath != filepath.Join(dir, "file1.pem") {
		t.Errorf("confirmedPath=%q", m.confirmedPath)
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}
}

func TestConfirmModal_EnterNo(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{kind: confirmOverwrite, yesNo: false}

	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("No should close modal")
	}
}

func TestConfirmModal_Esc(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{kind: confirmOverwrite, yesNo: true}

	m = sendKey(m, "esc")
	if m.modal != modalNone {
		t.Error("esc should close confirm modal")
	}
}

// --- Bookmarks Modal ---

func TestBookmarksModal_Navigation(t *testing.T) {
	dir := setupTestDir(t)
	bm1 := Bookmark{Label: "Custom1", Path: dir}
	sub := filepath.Join(dir, "subdir")
	bm2 := Bookmark{Label: "Custom2", Path: sub}
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{bm1, bm2}}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.modal = modalBookmarks
	m.bmMod.cursor = 0

	// Down
	m = sendKey(m, "down")
	if m.bmMod.cursor != 1 {
		t.Errorf("down: cursor=%d, want 1", m.bmMod.cursor)
	}

	// Up
	m = sendKey(m, "up")
	if m.bmMod.cursor != 0 {
		t.Errorf("up: cursor=%d, want 0", m.bmMod.cursor)
	}

	// Up at 0 stays
	m = sendKey(m, "up")
	if m.bmMod.cursor != 0 {
		t.Errorf("up at 0: cursor=%d, want 0", m.bmMod.cursor)
	}
}

func TestBookmarksModal_Enter(t *testing.T) {
	dir := setupTestDir(t)
	sub := filepath.Join(dir, "subdir")
	bm := Bookmark{Label: "Subdir", Path: sub}
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{bm}}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.modal = modalBookmarks

	bms := visibleBookmarks(m)
	// Find the Subdir bookmark
	for i, b := range bms {
		if b.Path == sub {
			m.bmMod.cursor = i
			break
		}
	}

	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("enter should close bookmarks modal")
	}
	if m.currentDir != sub {
		t.Errorf("currentDir=%q, want %q", m.currentDir, sub)
	}
}

func TestBookmarksModal_Esc(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{{Label: "X", Path: dir}}}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.modal = modalBookmarks

	m = sendKey(m, "esc")
	if m.modal != modalNone {
		t.Error("esc should close bookmarks modal")
	}
}

func TestVisibleBookmarks(t *testing.T) {
	dir := setupTestDir(t)
	sub := filepath.Join(dir, "subdir")

	// Start dir different from home
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{{Label: "Custom", Path: sub}}}
	m := makeTestModelWithConfig(t, cfg, dir)

	bms := visibleBookmarks(m)
	if len(bms) == 0 {
		t.Fatal("should have at least Home bookmark")
	}

	// Home first
	if bms[0].Label != "Home" {
		t.Errorf("first bookmark label=%q, want 'Home'", bms[0].Label)
	}

	// Start dir present if different from home
	home, _ := os.UserHomeDir()
	if dir != home {
		found := false
		for _, b := range bms {
			if b.Path == dir {
				found = true
				break
			}
		}
		if !found {
			t.Error("start dir should be in bookmarks if different from home")
		}
	}

	// Custom bookmarks that exist
	found := false
	for _, b := range bms {
		if b.Path == sub {
			found = true
		}
	}
	if !found {
		t.Error("custom bookmark should be present when path exists")
	}
}

// --- NewDir Modal ---

func TestNewDirModal_CreateDir(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, allowNewDir: true}
	m := makeTestModelWithConfig(t, cfg, dir)
	m = sendKey(m, "f7")

	// Type name
	m = sendKey(m, "t")
	m = sendKey(m, "e")
	m = sendKey(m, "s")
	m = sendKey(m, "t")

	// Enter creates
	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("enter should close newDir modal")
	}

	newPath := filepath.Join(dir, "test")
	info, err := os.Stat(newPath)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}

	// Cursor should be on the new dir
	if m.entries[m.cursor].name != "test" {
		t.Errorf("cursor on %q, want 'test'", m.entries[m.cursor].name)
	}
}

func TestNewDirModal_EmptyName(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, allowNewDir: true}
	m := makeTestModelWithConfig(t, cfg, dir)
	m = sendKey(m, "f7")

	initialCount := len(m.entries)
	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("enter with empty should close modal")
	}

	// Reload to check no dir was created
	m = sendKey(m, "f5")
	if len(m.entries) != initialCount {
		t.Error("no directory should have been created")
	}
}

func TestNewDirModal_Esc(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, allowNewDir: true}
	m := makeTestModelWithConfig(t, cfg, dir)
	m = sendKey(m, "f7")

	m = sendKey(m, "esc")
	if m.modal != modalNone {
		t.Error("esc should close newDir modal")
	}
}

// --- Path Modal ---

func TestPathModal_Open(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	m = sendKey(m, "ctrl+p")
	if m.modal != modalPath {
		t.Error("ctrl+p should open path modal")
	}
	val := m.pathMod.input.Value()
	if val != dir+"/" {
		t.Errorf("path input=%q, want %q", val, dir+"/")
	}
}

func TestPathModal_CommitValidDir(t *testing.T) {
	dir := setupTestDir(t)
	sub := filepath.Join(dir, "subdir")
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	// Set path to subdir
	m.pathMod.input.SetValue(sub)
	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("enter on valid dir should close modal")
	}
	if m.currentDir != sub {
		t.Errorf("currentDir=%q, want %q", m.currentDir, sub)
	}
}

func TestPathModal_CommitInvalidPath(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	m.pathMod.input.SetValue("/nonexistent/path/that/does/not/exist")
	m = sendKey(m, "enter")
	if !m.pathMod.isRed {
		t.Error("invalid path should set isRed=true")
	}
	if m.modal != modalPath {
		t.Error("should stay in path modal")
	}
}

func TestPathModal_CommitFile_OpenFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	filePath := filepath.Join(dir, "file1.pem")
	m.pathMod.input.SetValue(filePath)
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath != filePath {
		t.Errorf("confirmedPath=%q, want %q", m.confirmedPath, filePath)
	}
	if cmd == nil {
		t.Error("should return tea.Quit")
	}
}

func TestPathModal_TabCompletion(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	// Set path to dir + "/s" to get "subdir" completion
	m.pathMod.input.SetValue(dir + "/s")
	m = m.resetAndUpdateCompletions()

	if len(m.pathMod.completions) == 0 {
		t.Fatal("should have completions for 's'")
	}

	// Single completion: tab should complete
	m = sendKey(m, "tab")
	val := m.pathMod.input.Value()
	if val == dir+"/s" {
		t.Error("tab should have completed the path")
	}

	// LCP with multiple: test with "dir/" prefix (adir, zdir both start differently)
	m2 := makeTestModel(t, TypeOpenFile, dir)
	m2 = sendKey(m2, "ctrl+p")
	m2.pathMod.input.SetValue(dir + "/")
	m2 = m2.resetAndUpdateCompletions()
	// There should be multiple completions (adir, subdir, zdir, .hiddendir-if-shown)
	if len(m2.pathMod.completions) < 2 {
		t.Fatalf("should have multiple completions, got %d", len(m2.pathMod.completions))
	}

	// Accept highlighted: navigate down then tab
	m2 = sendKey(m2, "down")
	if m2.pathMod.dropCursor != 0 {
		t.Errorf("dropCursor=%d, want 0", m2.pathMod.dropCursor)
	}
	m2 = sendKey(m2, "tab")
	if m2.pathMod.input.Value() == dir+"/" {
		t.Error("accepting highlighted should update path")
	}
}

func TestPathModal_CtrlW(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	m.pathMod.input.SetValue(dir + "/subdir/")
	m = sendKey(m, "ctrl+w")
	val := m.pathMod.input.Value()
	if val == dir+"/subdir/" {
		t.Error("ctrl+w should remove last segment")
	}

	// Single segment
	m.pathMod.input.SetValue("/usr/")
	m = sendKey(m, "ctrl+w")
	val = m.pathMod.input.Value()
	if val != "/" {
		t.Errorf("ctrl+w single: got %q, want '/'", val)
	}
}

func TestPathModal_DropdownNavigation(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")
	m.pathMod.input.SetValue(dir + "/")
	m = m.resetAndUpdateCompletions()

	if len(m.pathMod.completions) < 2 {
		t.Skip("need at least 2 completions")
	}

	// Down
	m = sendKey(m, "down")
	if m.pathMod.dropCursor != 0 {
		t.Errorf("down: dropCursor=%d, want 0", m.pathMod.dropCursor)
	}

	m = sendKey(m, "down")
	if m.pathMod.dropCursor != 1 {
		t.Errorf("down again: dropCursor=%d, want 1", m.pathMod.dropCursor)
	}

	// Up
	m = sendKey(m, "up")
	if m.pathMod.dropCursor != 0 {
		t.Errorf("up: dropCursor=%d, want 0", m.pathMod.dropCursor)
	}
}

// --- Pure functions ---

func TestLongestCommonPrefix(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{"empty", nil, ""},
		{"single", []string{"hello"}, "hello"},
		{"abc abd", []string{"abc", "abd"}, "ab"},
		{"identical", []string{"same", "same"}, "same"},
		{"case insensitive", []string{"Abc", "abd"}, "Ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := longestCommonPrefix(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClampDropScroll(t *testing.T) {
	// Below window
	m := pickerModel{}
	m.pathMod.dropCursor = 0
	m.pathMod.dropScroll = 3
	m.clampDropScroll()
	if m.pathMod.dropScroll != 0 {
		t.Errorf("below: dropScroll=%d, want 0", m.pathMod.dropScroll)
	}

	// Above window
	m.pathMod.dropCursor = 8
	m.pathMod.dropScroll = 0
	m.clampDropScroll()
	if m.pathMod.dropScroll != 4 { // 8 - 5 + 1
		t.Errorf("above: dropScroll=%d, want 4", m.pathMod.dropScroll)
	}

	// Within
	m.pathMod.dropCursor = 3
	m.pathMod.dropScroll = 2
	m.clampDropScroll()
	if m.pathMod.dropScroll != 2 {
		t.Errorf("within: dropScroll=%d, want 2", m.pathMod.dropScroll)
	}

	// Negative
	m.pathMod.dropCursor = -1
	m.pathMod.dropScroll = -1
	m.clampDropScroll()
	if m.pathMod.dropScroll != 0 {
		t.Errorf("negative: dropScroll=%d, want 0", m.pathMod.dropScroll)
	}
}

func TestConfirmModal_RenderWrapsLongMessage(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{
		kind:    confirmInvalidExtension,
		message: "Extension not in recommended list (.pem .crt .cer .p12 .pfx .key .csr .der .p7b .p7c). Save anyway?",
		yesNo:   false,
	}

	view := m.View()

	// Full message must be present (no truncation with "...")
	for _, word := range []string{".pem", ".crt", ".cer", ".p12", ".pfx", ".key", ".csr", ".der", ".p7b", ".p7c", "Save anyway?"} {
		if !strings.Contains(view, word) {
			t.Errorf("confirm modal missing %q in rendered output", word)
		}
	}
	if strings.Contains(view, "…") {
		t.Error("confirm modal should not truncate the message")
	}
}

func TestConfirmModal_RenderExtraWarning(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{
		kind:    confirmInvalidExtension,
		message: "Extension not in recommended list (.pem). Save anyway?",
		extra:   "Signature scanning is disabled.",
		yesNo:   false,
	}

	view := m.View()
	if !strings.Contains(view, "Signature scanning is disabled.") {
		t.Error("confirm modal should render extra warning text")
	}
}

func TestAlertModal_RenderExtraWarning(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalAlert
	m.alert = alertState{
		message: "File must have one of these extensions: .pem",
		extra:   "Signature scanning is disabled.",
	}

	view := m.View()
	if !strings.Contains(view, "Signature scanning is disabled.") {
		t.Error("alert modal should render extra warning text")
	}
}

func TestConfirmModal_RenderNoExtra(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalConfirm
	m.confirm = confirmState{
		kind:    confirmInvalidExtension,
		message: "Extension not in recommended list (.pem). Save anyway?",
		yesNo:   false,
	}

	view := m.View()
	if !strings.Contains(view, "Confirm") {
		t.Error("confirm modal should render title")
	}
	if !strings.Contains(view, "recommended") {
		t.Error("confirm modal should render main message")
	}
	// With no extra, the grey warning text should not appear
	if strings.Contains(view, "Signature scanning") {
		t.Error("confirm modal should not render extra warning when empty")
	}
}

func TestAlertModal_RenderWrapsLongMessage(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.modal = modalAlert
	m.alert = alertState{
		message: "File must have one of these extensions: .pem .crt .cer .p12 .pfx .key .csr .der .p7b .p7c",
	}

	view := m.View()

	for _, word := range []string{".pem", ".crt", ".cer", ".p12", ".pfx", ".key", ".csr", ".der", ".p7b", ".p7c"} {
		if !strings.Contains(view, word) {
			t.Errorf("alert modal missing %q in rendered output", word)
		}
	}
	if strings.Contains(view, "…") {
		t.Error("alert modal should not truncate the message")
	}
}
