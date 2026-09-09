package filepicker

import (
	"path/filepath"
	"testing"
)

// E10 (M31): Enter in the filename field of a save dialog confirms the typed
// name, the same as the OK button.
func TestSaveFile_EnterInFilenameConfirms(t *testing.T) {
	dir := setupTestDir(t)
	m := makeTestModel(t, TypeSaveFile, dir)
	m.focus = focusFilename
	m.filename.Focus()
	m.filename.SetValue("fresh.pem")

	updated, cmd := m.Update(keyMsg("enter"))
	got := updated.(pickerModel)
	if got.confirmedPath != filepath.Join(dir, "fresh.pem") {
		t.Errorf("confirmedPath = %q, want the typed file in %s", got.confirmedPath, dir)
	}
	if cmd == nil {
		t.Error("expected the dialog to quit on confirm")
	}
}
