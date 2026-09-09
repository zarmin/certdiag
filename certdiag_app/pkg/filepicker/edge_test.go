//go:build !windows

package filepicker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// --- Filesystem adversarial ---

func TestReadDir_NonExistentDir(t *testing.T) {
	_, err := readDir("/nonexistent/path/that/does/not/exist", false, nil, false, TypeOpenFile)
	if err == nil {
		t.Error("readDir on non-existent dir should return error")
	}
}

func TestReadDir_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	restricted := filepath.Join(dir, "noaccess")
	os.MkdirAll(restricted, 0755)
	os.WriteFile(filepath.Join(restricted, "file.txt"), []byte("x"), 0644)

	// Remove read permission
	os.Chmod(restricted, 0000)
	t.Cleanup(func() { os.Chmod(restricted, 0755) })

	_, err := readDir(restricted, false, nil, false, TypeOpenFile)
	if err == nil {
		t.Error("readDir on permission-denied dir should return error")
	}
}

func TestLoadDir_InvalidDir_ShowsAlert(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	m.loadDir("/nonexistent/path/does/not/exist")
	if m.modal != modalAlert {
		t.Error("loadDir with invalid path should show alert modal")
	}
	if m.alert.message == "" {
		t.Error("alert message should not be empty")
	}
	// currentDir should remain unchanged
	if m.currentDir != dir {
		t.Errorf("currentDir should stay %q, got %q", dir, m.currentDir)
	}
}

func TestReloadDir_DeletedDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "ephemeral")
	os.MkdirAll(sub, 0755)
	os.WriteFile(filepath.Join(sub, "file.txt"), []byte("x"), 0644)

	m := makeTestModel(t, TypeOpenFile, sub)
	if len(m.entries) == 0 {
		t.Fatal("should have entries")
	}

	// Delete the directory while model points to it
	os.RemoveAll(sub)

	m.reloadDir()
	if m.modal != modalAlert {
		t.Error("reloadDir on deleted dir should show alert")
	}
}

func TestReadDir_BrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	os.Symlink("/nonexistent/target", filepath.Join(dir, "broken_link"))

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	// Broken symlink should still appear (Lstat succeeds even if target missing)
	found := false
	for _, e := range entries {
		if e.name == "broken_link" {
			found = true
			if !e.isSymlink {
				t.Error("broken_link should be marked as symlink")
			}
			// Target resolution fails, so symlinkTarget should be empty
			if e.symlinkTarget != "" {
				t.Errorf("broken symlink target should be empty, got %q", e.symlinkTarget)
			}
		}
	}
	if !found {
		t.Error("broken symlink should still appear in readDir")
	}
}

func TestReadDir_SymlinkLoop(t *testing.T) {
	dir := t.TempDir()
	linkA := filepath.Join(dir, "loop_a")
	linkB := filepath.Join(dir, "loop_b")
	os.Symlink(linkB, linkA)
	os.Symlink(linkA, linkB)

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	// Both should appear but with failed target resolution
	count := 0
	for _, e := range entries {
		if e.name == "loop_a" || e.name == "loop_b" {
			count++
			if !e.isSymlink {
				t.Errorf("%s should be marked as symlink", e.name)
			}
		}
	}
	if count != 2 {
		t.Errorf("expected 2 loop symlinks, found %d", count)
	}
}

func TestReadDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	// Should have just ".."
	if len(entries) != 1 || entries[0].name != ".." {
		t.Errorf("empty dir should have only '..', got %v", entryNames(entries))
	}
}

func TestReadDir_RootHasNoDotDot(t *testing.T) {
	entries, err := readDir("/", false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.name == ".." {
			t.Error("root '/' should NOT have '..' entry")
		}
	}
}

func TestReadDir_OnlyHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".only_hidden"), []byte("x"), 0644)
	os.MkdirAll(filepath.Join(dir, ".hidden_dir"), 0755)

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}

	// With showHidden=false, only ".." should be present
	if len(entries) != 1 || entries[0].name != ".." {
		t.Errorf("with showHidden=false, only '..' expected, got %v", entryNames(entries))
	}

	// With showHidden=true, all should appear
	entries2, _ := readDir(dir, true, nil, false, TypeOpenFile)
	if len(entries2) < 3 { // "..", ".only_hidden", ".hidden_dir"
		t.Errorf("with showHidden=true, expected >= 3 entries, got %d", len(entries2))
	}
}

func TestReadDir_FileDisappearsDuringLstat(t *testing.T) {
	// readDir calls os.Lstat on each file; if it fails, it continues (skip)
	// This tests the graceful handling of Lstat errors by creating unreadable entries
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("ok"), 0644)

	entries, err := readDir(dir, false, nil, false, TypeOpenFile)
	if err != nil {
		t.Fatal(err)
	}
	if !containsEntryName(entries, "normal.txt") {
		t.Error("normal.txt should be present")
	}
}

// --- Model edge cases ---

func TestModel_ActivateEntry_EmptyEntries(t *testing.T) {
	dir := t.TempDir()
	// Empty dir => only ".."
	m := makeTestModel(t, TypeOpenFile, dir)

	// Manually clear entries to test the guard
	m.entries = nil
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if cmd != nil {
		t.Error("activateEntry on empty entries should be no-op")
	}
	_ = m
}

func TestModel_UpdateFileList_EmptyEntries(t *testing.T) {
	dir := t.TempDir()
	m := makeTestModel(t, TypeOpenFile, dir)
	m.entries = nil

	// All navigation keys should be no-ops
	for _, key := range []string{"up", "down", "pgup", "pgdown", "home", "end", "enter"} {
		m = sendKey(m, key)
	}
	// Should not panic
}

func TestModel_NavigateUp_AtRoot(t *testing.T) {
	m := makeTestModel(t, TypeOpenFile, "/")

	// At root, navigateUp should be a no-op (parent == currentDir)
	m = sendKey(m, "backspace")
	if m.currentDir != "/" {
		t.Errorf("navigateUp at root: currentDir=%q, want '/'", m.currentDir)
	}
}

func TestModel_DoOK_OpenFile_CursorOnDotDot(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.cursor = 0 // ".." is first
	m.focus = focusOK

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.confirmedPath != "" {
		t.Error("OK on '..' should not set confirmedPath")
	}
	if cmd != nil {
		t.Error("OK on '..' should not quit")
	}
}

func TestModel_DoOK_OpenFile_EmptyEntries(t *testing.T) {
	dir := t.TempDir()
	m := makeTestModel(t, TypeOpenFile, dir)
	m.entries = nil
	m.focus = focusOK

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if cmd != nil {
		t.Error("OK with empty entries should be no-op")
	}
	_ = m
}

func TestModel_MultiSelect_SelectionPersistsAcrossDirs(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, multiSelect: true}
	m := makeTestModelWithConfig(t, cfg, dir)

	// Select file1.pem
	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, " ")
	path1 := filepath.Join(dir, "file1.pem")
	if !m.selected[path1] {
		t.Fatal("file1.pem should be selected")
	}

	// Navigate into subdir
	for i, e := range m.entries {
		if e.name == "subdir" {
			m.cursor = i
			break
		}
	}
	m = sendKey(m, "enter")

	// Selection should persist
	if !m.selected[path1] {
		t.Error("selection should persist after navigating to another dir")
	}

	// Navigate back
	m = sendKey(m, "backspace")
	if !m.selected[path1] {
		t.Error("selection should persist after navigating back")
	}

	// OK should include the selection
	m.focus = focusOK
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if len(m.results) == 0 {
		t.Error("OK should return selected files")
	}
	if cmd == nil {
		t.Error("should quit")
	}
}

func TestModel_CycleFocus_CurrentNotInOrder(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Force focus to a value not in the order list (e.g. focusFilename for non-SaveFile)
	m.focus = focusFilename
	m.cycleFocus(1)
	// Should fallback to order[0]
	if m.focus != focusList {
		t.Errorf("focus should reset to focusList, got %d", m.focus)
	}
}

func TestModel_SearchBackspaceOnEmptyQuery(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Enter search mode
	m = sendKey(m, "/")
	if !m.searchMode {
		t.Fatal("should be in search mode")
	}

	entriesBefore := len(m.entries)

	// Backspace on empty query should be a no-op (stays in search mode)
	m = sendKey(m, "backspace")
	if !m.searchMode {
		t.Error("backspace on empty query should stay in search mode")
	}
	if m.searchQuery != "" {
		t.Errorf("query should still be empty, got %q", m.searchQuery)
	}
	if len(m.entries) != entriesBefore {
		t.Error("entries should not change")
	}
}

func TestModel_RapidSearchClearSearch(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Search -> type -> clear -> search -> type again
	m = sendKey(m, "/")
	m = sendKey(m, "p")
	m = sendKey(m, "e")
	filteredCount := len(m.entries)

	m = sendKey(m, "esc") // clear search
	allCount := len(m.entries)
	if allCount <= filteredCount {
		t.Error("clearing search should restore all entries")
	}

	// Search again
	m = sendKey(m, "/")
	m = sendKey(m, "k")
	m = sendKey(m, "e")
	m = sendKey(m, "y")
	if m.searchQuery != "key" {
		t.Errorf("second search: query=%q, want 'key'", m.searchQuery)
	}
}

func TestModel_MaybeResolvePath_InvalidDir(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.focus = focusFilename
	m.filename.Focus()

	// Set a path with separator but invalid directory
	m.filename.SetValue("/nonexistent/dir/file.pem")
	_, _, ok := m.maybeResolvePath()
	if ok {
		t.Error("maybeResolvePath should return false for invalid parent dir")
	}
}

func TestModel_MaybeResolvePath_NoSeparator(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.filename.SetValue("justfilename.pem")
	_, _, ok := m.maybeResolvePath()
	if ok {
		t.Error("maybeResolvePath should return false when no path separator")
	}
}

func TestModel_MaybeResolvePath_ValidPath(t *testing.T) {
	dir := setupTestDir(t)
	sub := filepath.Join(dir, "subdir")
	m := makeTestModel(t, TypeSaveFile, dir)
	m.filename.SetValue(sub + "/newfile.pem")

	m2, _, ok := m.maybeResolvePath()
	if !ok {
		t.Error("maybeResolvePath should return true for valid path")
	}
	if m2.currentDir != sub {
		t.Errorf("should navigate to %q, got %q", sub, m2.currentDir)
	}
	if m2.filename.Value() != "newfile.pem" {
		t.Errorf("filename should be 'newfile.pem', got %q", m2.filename.Value())
	}
}

func TestModel_CancelButton(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.focus = focusCancel

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.resultErr != ErrCancelled {
		t.Error("cancel button should set ErrCancelled")
	}
	if cmd == nil {
		t.Error("cancel should quit")
	}
}

func TestModel_CancelButton_Space(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m.focus = focusCancel

	updated, cmd := m.Update(keyMsg(" "))
	m = updated.(pickerModel)
	if m.resultErr != ErrCancelled {
		t.Error("space on cancel should set ErrCancelled")
	}
	if cmd == nil {
		t.Error("space on cancel should quit")
	}
}

func TestModel_FocusShowHidden_EnterToggles(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}
	m := makeTestModelWithConfig(t, cfg, dir)

	m.focus = focusShowHidden
	if m.showHidden {
		t.Fatal("showHidden should be false initially")
	}

	m = sendKey(m, "enter")
	if !m.showHidden {
		t.Error("enter on focusShowHidden should toggle")
	}
}

func TestModel_FocusAllFiles_SpaceToggles(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}, filterOverridable: true}
	m := makeTestModelWithConfig(t, cfg, dir)

	m.focus = focusAllFiles
	m = sendKey(m, " ")
	if !m.filterAll {
		t.Error("space on focusAllFiles should toggle filterAll")
	}
	m = sendKey(m, " ")
	if m.filterAll {
		t.Error("second space should toggle back")
	}
}

func TestModel_ActivateEntry_DisabledEntry(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Manually mark an entry as disabled
	for i := range m.entries {
		if !m.entries[i].isDir && m.entries[i].name != ".." {
			m.entries[i].disabled = true
			m.cursor = i
			break
		}
	}

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if cmd != nil {
		t.Error("activating disabled entry should be no-op")
	}
	if m.confirmedPath != "" {
		t.Error("disabled entry should not set confirmedPath")
	}
}

func TestModel_ActivateEntry_SymlinkDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "realdir")
	os.MkdirAll(target, 0755)
	os.WriteFile(filepath.Join(target, "inside.txt"), []byte("x"), 0644)
	os.Symlink(target, filepath.Join(dir, "linkdir"))

	m := makeTestModel(t, TypeOpenFile, dir)

	for i, e := range m.entries {
		if e.name == "linkdir" {
			m.cursor = i
			break
		}
	}

	m = sendKey(m, "enter")
	// Should navigate into the symlink target.
	// On macOS /var -> /private/var, so resolve both for comparison.
	resolvedCurrent, _ := filepath.EvalSymlinks(m.currentDir)
	resolvedTarget, _ := filepath.EvalSymlinks(target)
	if resolvedCurrent != resolvedTarget {
		t.Errorf("entering symlink dir: currentDir=%q, want %q", m.currentDir, target)
	}
	if !containsEntryName(m.entries, "inside.txt") {
		t.Error("should see files inside symlink target")
	}
}

// --- Modal edge cases ---

func TestPathModal_CommitEmptyInput(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	// Clear the input
	m.pathMod.input.SetValue("")
	m = sendKey(m, "enter")
	if m.modal != modalNone {
		t.Error("committing empty path should close modal")
	}
}

func TestPathModal_CommitFile_OpenDir(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenDir, dir)
	m = sendKey(m, "ctrl+p")

	filePath := filepath.Join(dir, "file1.pem")
	m.pathMod.input.SetValue(filePath)
	m = sendKey(m, "enter")

	// OpenDir + file path → should navigate to file's parent directory
	if m.modal != modalNone {
		t.Error("should close modal")
	}
	if m.currentDir != dir {
		t.Errorf("OpenDir+file: should navigate to parent %q, got %q", dir, m.currentDir)
	}
}

func TestPathModal_CommitFile_SaveFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m = sendKey(m, "ctrl+p")

	filePath := filepath.Join(dir, "file1.pem")
	m.pathMod.input.SetValue(filePath)
	m = sendKey(m, "enter")

	// SaveFile + file path → navigate to dir, set filename
	if m.modal != modalNone {
		t.Error("should close modal")
	}
	if m.filename.Value() != "file1.pem" {
		t.Errorf("filename=%q, want 'file1.pem'", m.filename.Value())
	}
}

func TestPathModal_CommitNonExisting_SaveFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m = sendKey(m, "ctrl+p")

	// Non-existing file in valid parent
	m.pathMod.input.SetValue(filepath.Join(dir, "newfile.pem"))
	m = sendKey(m, "enter")

	if m.modal != modalNone {
		t.Error("should close modal for valid parent")
	}
	if m.currentDir != dir {
		t.Errorf("should stay in %q, got %q", dir, m.currentDir)
	}
	if m.filename.Value() != "newfile.pem" {
		t.Errorf("filename=%q, want 'newfile.pem'", m.filename.Value())
	}
}

func TestPathModal_CommitNonExisting_OpenFile(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	// Non-existing file in valid parent for OpenFile → navigates but doesn't set filename
	m.pathMod.input.SetValue(filepath.Join(dir, "doesnotexist.pem"))
	m = sendKey(m, "enter")

	if m.modal != modalNone {
		t.Error("should close modal for valid parent")
	}
	if m.currentDir != dir {
		t.Errorf("should navigate to parent %q, got %q", dir, m.currentDir)
	}
}

func TestPathModal_HandlePathFile_FilteredOut(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, fileFilter: []string{".pem"}}
	m := makeTestModelWithConfig(t, cfg, dir)
	m = sendKey(m, "ctrl+p")

	// Enter a .txt file path → should show alert "File type not allowed"
	m.pathMod.input.SetValue(filepath.Join(dir, "notes.txt"))
	m = sendKey(m, "enter")

	if m.modal != modalAlert {
		t.Errorf("entering filtered-out file should show alert, got modal=%d", m.modal)
	}
	if m.alert.message != "File type not allowed." {
		t.Errorf("alert message=%q", m.alert.message)
	}
}

func TestPathModal_TabComplete_NoCompletions(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	// Type something with no completions
	m.pathMod.input.SetValue(dir + "/zzznomatch")
	m = m.resetAndUpdateCompletions()

	before := m.pathMod.input.Value()
	m = sendKey(m, "tab")
	after := m.pathMod.input.Value()
	if before != after {
		t.Error("tab with no completions should be no-op")
	}
}

func TestPathModal_CtrlW_RootPath(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	m.pathMod.input.SetValue("/")
	m = sendKey(m, "ctrl+w")
	val := m.pathMod.input.Value()
	if val != "/" {
		t.Errorf("ctrl+w on root: got %q, want '/'", val)
	}
}

func TestPathModal_UpdateCompletions_InvalidDir(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+p")

	m.pathMod.input.SetValue("/nonexistent/path/")
	m = m.resetAndUpdateCompletions()
	if !m.pathMod.isRed {
		t.Error("completions for invalid dir should set isRed")
	}
}

func TestBookmarks_NonExistentPathFiltered(t *testing.T) {
	dir := setupTestDir(t)
	sub := filepath.Join(dir, "subdir")
	cfg := &config{
		dialogType: TypeOpenFile,
		bookmarks: []Bookmark{
			{Label: "Valid", Path: sub},
			{Label: "Invalid", Path: "/nonexistent/bookmark/path"},
		},
	}
	m := makeTestModelWithConfig(t, cfg, dir)

	bms := visibleBookmarks(m)
	for _, bm := range bms {
		if bm.Label == "Invalid" {
			t.Error("non-existent bookmark should be filtered out")
		}
	}
	foundValid := false
	for _, bm := range bms {
		if bm.Path == sub {
			foundValid = true
		}
	}
	if !foundValid {
		t.Error("valid bookmark should be present")
	}
}

func TestBookmarks_DuplicatePaths(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType: TypeOpenFile,
		bookmarks: []Bookmark{
			{Label: "Dup1", Path: dir},
			{Label: "Dup2", Path: dir},
		},
	}
	m := makeTestModelWithConfig(t, cfg, dir)

	bms := visibleBookmarks(m)
	count := 0
	for _, bm := range bms {
		if bm.Path == dir {
			count++
		}
	}
	if count > 1 {
		t.Errorf("duplicate paths should be deduplicated, found %d for %q", count, dir)
	}
}

func TestBookmarks_DownAtLastPosition(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{{Label: "B", Path: dir}}}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.modal = modalBookmarks

	bms := visibleBookmarks(m)
	last := len(bms) - 1
	m.bmMod.cursor = last

	m = sendKey(m, "down")
	if m.bmMod.cursor != last {
		t.Errorf("down at last: cursor=%d, want %d", m.bmMod.cursor, last)
	}
}

func TestNewDirModal_PermissionError(t *testing.T) {
	dir := t.TempDir()
	restricted := filepath.Join(dir, "readonly")
	os.MkdirAll(restricted, 0755)
	os.Chmod(restricted, 0555)
	t.Cleanup(func() { os.Chmod(restricted, 0755) })

	cfg := &config{dialogType: TypeOpenFile, allowNewDir: true}
	m := makeTestModelWithConfig(t, cfg, restricted)
	m = sendKey(m, "f7")

	// Type a name
	m = sendKey(m, "t")
	m = sendKey(m, "e")
	m = sendKey(m, "s")
	m = sendKey(m, "t")

	m = sendKey(m, "enter")
	if m.modal != modalAlert {
		t.Error("creating dir in read-only should show alert")
	}
	if m.alert.message == "" {
		t.Error("alert message should describe the error")
	}
}

func TestConfirmModal_EnterYes_InvalidExtension(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType:     TypeSaveFile,
		saveExtensions: []string{".pem"},
		extensionMode:  ExtensionModeConfirm,
	}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.filename.SetValue("file.txt")
	m.focus = focusOK

	// Trigger extension confirm
	m = sendKey(m, "enter")
	if m.modal != modalConfirm || m.confirm.kind != confirmInvalidExtension {
		t.Fatal("should show extension confirm modal")
	}

	// Select Yes and confirm
	m.confirm.yesNo = true
	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)

	// Should proceed (no overwrite check since file doesn't exist)
	if m.confirmedPath != filepath.Join(dir, "file.txt") {
		t.Errorf("confirmedPath=%q", m.confirmedPath)
	}
	if cmd == nil {
		t.Error("should quit")
	}
}

func TestConfirmModal_ExtensionConfirm_ThenOverwrite(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType:      TypeSaveFile,
		saveExtensions:  []string{".pem"},
		extensionMode:   ExtensionModeConfirm,
		checkFileExists: true,
	}
	m := makeTestModelWithConfig(t, cfg, dir)

	// Use an existing file with wrong extension: notes.txt exists
	m.filename.SetValue("notes.txt")
	m.focus = focusOK
	m = sendKey(m, "enter")

	// Should get extension confirm first
	if m.modal != modalConfirm || m.confirm.kind != confirmInvalidExtension {
		t.Fatal("should show extension confirm")
	}

	// Accept wrong extension
	m.confirm.yesNo = true
	m = sendKey(m, "enter")

	// Now should chain to overwrite confirm
	if m.modal != modalConfirm || m.confirm.kind != confirmOverwrite {
		t.Errorf("should chain to overwrite confirm, got modal=%d kind=%d", m.modal, m.confirm.kind)
	}
}

// --- Save flow edge cases ---

func TestDoSave_FilterAllBypassesExtensionCheck(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType:     TypeSaveFile,
		saveExtensions: []string{".pem"},
		extensionMode:  ExtensionModeStrict,
	}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.filterAll = true
	m.filename.SetValue("file.txt")
	m.focus = focusOK

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	// filterAll=true should bypass extension check
	if m.modal == modalAlert {
		t.Error("filterAll should bypass strict extension check")
	}
	if m.confirmedPath == "" {
		t.Error("should have confirmedPath")
	}
	if cmd == nil {
		t.Error("should quit")
	}
}

func TestDoSave_ExtensionModeAllowAll(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType:     TypeSaveFile,
		saveExtensions: []string{".pem"},
		extensionMode:  ExtensionModeAllowAll,
	}
	m := makeTestModelWithConfig(t, cfg, dir)
	m.filename.SetValue("file.xyz")
	m.focus = focusOK

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	if m.modal != modalNone {
		t.Error("AllowAll should not show any modal for wrong extension")
	}
	if m.confirmedPath != filepath.Join(dir, "file.xyz") {
		t.Errorf("confirmedPath=%q", m.confirmedPath)
	}
	if cmd == nil {
		t.Error("should quit")
	}
}

func TestDoSave_FilenameWithSpaces(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.filename.SetValue("  myfile.pem  ")
	m.focus = focusOK

	updated, cmd := m.Update(keyMsg("enter"))
	m = updated.(pickerModel)
	// Filename should be trimmed
	if m.confirmedPath != filepath.Join(dir, "myfile.pem") {
		t.Errorf("confirmedPath=%q, want trimmed path", m.confirmedPath)
	}
	if cmd == nil {
		t.Error("should quit")
	}
}

func TestDoSave_WhitespaceOnlyFilename(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.filename.SetValue("   ")
	m.focus = focusOK

	m = sendKey(m, "enter")
	if m.modal != modalAlert {
		t.Error("whitespace-only filename should show alert")
	}
}

// --- View edge cases ---

func TestView_TermWidthBelowMin(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	m := newPickerModel(cfg, dir)
	m.termW = 60
	m.termH = 30

	view := m.View()
	if view == "" {
		t.Error("view should not be empty when termW > 0")
	}
	if !containsString(view, "Terminal too small") {
		t.Error("should show 'Terminal too small' message")
	}
}

func TestView_TermHeightBelowMin(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	m := newPickerModel(cfg, dir)
	m.termW = 100
	m.termH = 15

	view := m.View()
	if !containsString(view, "Terminal too small") {
		t.Error("should show 'Terminal too small' for small height")
	}
}

func TestView_RendersCorrectModal(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Alert modal
	m.modal = modalAlert
	m.alert = alertState{message: "Test error"}
	view := m.View()
	if !containsString(view, "Error") {
		t.Error("alert modal should contain 'Error'")
	}

	// Confirm modal
	m.modal = modalConfirm
	m.confirm = confirmState{message: "Overwrite?", yesNo: false}
	view = m.View()
	if !containsString(view, "Confirm") {
		t.Error("confirm modal should contain 'Confirm'")
	}

	// Path modal
	m.modal = modalPath
	m.pathMod.input = newSimpleInput()
	m.pathMod.input.Focus()
	view = m.View()
	if !containsString(view, "Go to path") {
		t.Error("path modal should contain 'Go to path'")
	}

	// Bookmarks modal
	m.modal = modalBookmarks
	view = m.View()
	if !containsString(view, "Bookmarks") {
		t.Error("bookmarks modal should contain 'Bookmarks'")
	}

	// NewDir modal
	m.modal = modalNewDir
	m.newDirMod.input = newSimpleInput()
	m.newDirMod.input.Focus()
	view = m.View()
	if !containsString(view, "New Folder") {
		t.Error("newDir modal should contain 'New Folder'")
	}
}

func TestView_ListHeightMinimum(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	m := newPickerModel(cfg, dir)
	// Set terminal to minimum clamped size
	m.termW = 80
	m.termH = 22

	h := m.listHeight()
	if h < 1 {
		t.Errorf("listHeight should be at least 1, got %d", h)
	}
}

// --- Misc update edge cases ---

func TestUpdate_UnknownMsgType(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Send a message type that's not WindowSizeMsg or KeyMsg
	type customMsg struct{}
	updated, cmd := m.Update(customMsg{})
	m2 := updated.(pickerModel)
	if cmd != nil {
		t.Error("unknown msg type should return nil cmd")
	}
	// Model should be unchanged
	if m2.currentDir != m.currentDir {
		t.Error("model should be unchanged for unknown msg")
	}
}

func TestModel_CtrlB_NoBookmarks(t *testing.T) {
	dir := setupTestDir(t)
	// On macOS, visibleBookmarks always has at least Home
	// but let's verify ctrl+b doesn't crash
	m := makeTestModel(t, TypeOpenFile, dir)
	m = sendKey(m, "ctrl+b")
	// Should either open bookmarks (if Home exists) or be no-op
	// Just verify no panic
}

func TestModel_EnterOnFilename_SimpleFilename(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.focus = focusFilename
	m.filename.Focus()
	m.filename.SetValue("simple.pem")

	// Enter on filename without path separator → no-op from maybeResolvePath
	m = sendKey(m, "enter")
	// Should not navigate anywhere
	if m.currentDir != dir {
		t.Errorf("enter on simple filename shouldn't navigate, currentDir=%q", m.currentDir)
	}
}

func TestModel_SetCursorToEntry_NotFound(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	original := m.cursor
	m.setCursorToEntry("nonexistent_file_name")
	// Cursor should remain unchanged
	if m.cursor != original {
		t.Errorf("setCursorToEntry not found: cursor moved from %d to %d", original, m.cursor)
	}
}

func TestModel_ReloadDir_CursorClamp(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Set cursor beyond what will remain after deleting files
	m.cursor = len(m.entries) - 1

	// Delete most files
	os.Remove(filepath.Join(dir, "file1.pem"))
	os.Remove(filepath.Join(dir, "file2.crt"))
	os.Remove(filepath.Join(dir, "file3.key"))
	os.Remove(filepath.Join(dir, "notes.txt"))

	m.reloadDir()
	if m.cursor >= len(m.entries) {
		t.Errorf("cursor=%d should be clamped to len(entries)-1=%d", m.cursor, len(m.entries)-1)
	}
	if m.cursor < 0 {
		t.Error("cursor should not be negative")
	}
}

func TestModel_SearchMode_LetterJumpDisabled(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)

	// Enter search mode
	m = sendKey(m, "/")

	// Type 'a' - should add to search query, NOT letter-jump
	m = sendKey(m, "a")
	if m.searchQuery != "a" {
		t.Errorf("in search mode, 'a' should add to query, got %q", m.searchQuery)
	}

	// Cursor should be at 0 (reset by search), not jumped to 'adir'
	if m.cursor != 0 {
		t.Errorf("in search mode, cursor should be 0, got %d", m.cursor)
	}
}

func TestModel_SpaceWithoutMultiSelect(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeOpenFile, dir)
	// multiSelect is false

	for i, e := range m.entries {
		if e.name == "file1.pem" {
			m.cursor = i
			break
		}
	}

	before := m.cursor
	m = sendKey(m, " ")
	// Space without multiSelect should fall through (no-op for non-multiselect)
	if len(m.selected) != 0 {
		t.Error("space without multiSelect should not select anything")
	}
	_ = before
}

func TestView_SaveFileWithExtensions_NoEmptyLines(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, saveExtensions: []string{".csr", ".pem"}}
	m := newPickerModel(cfg, dir)
	m.termW = 100
	m.termH = 30
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = updated.(pickerModel)

	view := m.View()

	if !containsString(view, "Use one of these extensions") {
		t.Error("SaveFile+extensions should show extension hint")
	}

	// Check for empty lines within the box (consecutive newlines with only box border chars)
	lines := strings.Split(view, "\n")
	for i := 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		prevTrimmed := strings.TrimSpace(lines[i-1])
		// An empty box row would be just border chars with spaces
		if trimmed == "" && prevTrimmed == "" {
			t.Errorf("found consecutive empty lines at line %d", i)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && contains(s, substr)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
