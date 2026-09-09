package filepicker

import (
	"bytes"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

func newTeatestModel(t *testing.T, cfg *config, dir string, w, h int) *teatest.TestModel {
	t.Helper()
	m := newPickerModel(cfg, dir)
	return teatest.NewTestModel(t, m, teatest.WithInitialTermSize(w, h))
}

func waitForOutput(t *testing.T, tm *teatest.TestModel, substr string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(bts []byte) bool {
		return bytes.Contains(bts, []byte(substr))
	}, teatest.WithDuration(3*time.Second))
}

// triggerRender sends a benign key event to force a render cycle,
// which helps when the initial view isn't flushed via ANSICompressor.
func triggerRender(tm *teatest.TestModel) {
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	time.Sleep(100 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyUp})
	time.Sleep(100 * time.Millisecond)
}

func TestTeatest_InitialView_OpenFile(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile, title: "Open File"}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Open File")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_InitialView_SaveFile(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, title: "Save File"}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Save File")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_SaveFileWithExtensions(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, title: "Save CSR", saveExtensions: []string{".csr", ".pem"}}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	teatest.WaitFor(t, tm.Output(), func(bts []byte) bool {
		s := string(bts)
		return strings.Contains(s, "Use one of these extensions") && strings.Contains(s, "Filename")
	}, teatest.WithDuration(3*time.Second))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_InitialView_OpenDir(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenDir, title: "Open Directory"}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Open Directory")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_NavigateAndSelect(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "file1.pem")

	// Navigate down past ".." and directories to reach files
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
		time.Sleep(50 * time.Millisecond)
	}

	// Select with Enter
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_NavigateIntoDir(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "subdir")

	// Jump to 's' for subdir
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	time.Sleep(100 * time.Millisecond)

	// Enter into subdir
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForOutput(t, tm, "nested.pem")

	// Backspace to go back
	tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	waitForOutput(t, tm, "subdir")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_SearchFilter(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "file1.pem")

	// Enter search mode
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	time.Sleep(100 * time.Millisecond)

	// Type "pem"
	tm.Type("pem")
	waitForOutput(t, tm, "Search:")

	// Esc to restore
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(100 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_HiddenFilesToggle(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "file1.pem")

	// "." to show hidden
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'.'}})
	waitForOutput(t, tm, ".hidden")

	// "." again to hide
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'.'}})
	time.Sleep(200 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_SaveFileWorkflow(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, title: "Save File"}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Save File")

	// Tab to filename (focusList -> focusFilename)
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Type filename
	tm.Type("output.pem")
	time.Sleep(100 * time.Millisecond)

	// Tab to OK (focusFilename -> focusOK)
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Enter to save
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	finalModel := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second))
	pm := finalModel.(pickerModel)
	if pm.confirmedPath == "" {
		t.Error("should have a confirmed path")
	}
	if !strings.HasSuffix(pm.confirmedPath, "output.pem") {
		t.Errorf("confirmedPath=%q, should end with output.pem", pm.confirmedPath)
	}
}

func TestTeatest_AlertModal(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeSaveFile, title: "Save File"}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Save File")

	// Tab to filename, then tab to OK (skip filename input)
	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // -> filename
	time.Sleep(50 * time.Millisecond)
	tm.Send(tea.KeyMsg{Type: tea.KeyTab}) // -> OK
	time.Sleep(50 * time.Millisecond)

	// Enter with empty filename -> alert
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitForOutput(t, tm, "Filename must not be empty")

	// Dismiss
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(100 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_BookmarksModal(t *testing.T) {
	dir := setupTestDir(t)
	sub := dir + "/subdir"
	cfg := &config{dialogType: TypeOpenFile, bookmarks: []Bookmark{{Label: "MyBM", Path: sub}}}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "file1.pem")

	// Ctrl+B to open bookmarks
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlB})
	waitForOutput(t, tm, "Bookmarks")

	// Enter to select first bookmark (Home)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	time.Sleep(200 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_PathModal(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "file1.pem")

	// Ctrl+P to open path modal
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlP})
	waitForOutput(t, tm, "Go to path")

	// Esc to close
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(100 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_ConfirmModalWrapsExtensionMessage(t *testing.T) {
	dir := setupTestDir(t)
	exts := []string{".pem", ".crt", ".cer", ".p12", ".pfx", ".key", ".csr", ".der", ".p7b", ".p7c"}
	cfg := &config{
		dialogType:     TypeSaveFile,
		title:          "Save Cert",
		saveExtensions: exts,
		extensionMode:  ExtensionModeConfirm,
	}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Save Cert")

	// Tab to filename
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Type a filename with wrong extension
	tm.Type("test.xyz")
	time.Sleep(100 * time.Millisecond)

	// Tab to OK
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Enter to trigger extension confirm
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	// Last extension in the list must be visible (not truncated)
	waitForOutput(t, tm, ".p7c")

	// Dismiss with Esc
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(100 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_ConfirmModalShowsExtensionWarning(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{
		dialogType:       TypeSaveFile,
		title:            "Save Cert",
		saveExtensions:   []string{".pem", ".crt"},
		extensionMode:    ExtensionModeConfirm,
		extensionWarning: "Signature scanning is disabled.",
	}
	tm := newTeatestModel(t, cfg, dir, 100, 30)

	triggerRender(tm)
	waitForOutput(t, tm, "Save Cert")

	// Tab to filename
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Type a filename with wrong extension
	tm.Type("test.xyz")
	time.Sleep(100 * time.Millisecond)

	// Tab to OK
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	time.Sleep(100 * time.Millisecond)

	// Enter to trigger extension confirm
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	// Warning text must appear
	waitForOutput(t, tm, "Signature scanning is disabled.")

	// Dismiss with Esc
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	time.Sleep(100 * time.Millisecond)

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_SmallTerminal(t *testing.T) {
	dir := setupTestDir(t)
	cfg := &config{dialogType: TypeOpenFile}
	tm := newTeatestModel(t, cfg, dir, 60, 15)

	// Small terminal should immediately render the error message
	waitForOutput(t, tm, "Terminal too small")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}
