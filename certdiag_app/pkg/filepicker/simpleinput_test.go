package filepicker

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestSimpleInput_SetValueAndValue(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("hello")
	if ti.Value() != "hello" {
		t.Errorf("got %q, want %q", ti.Value(), "hello")
	}

	ti.SetValue("")
	if ti.Value() != "" {
		t.Errorf("got %q, want empty", ti.Value())
	}

	ti.SetValue("abc")
	if ti.cursor != 3 {
		t.Errorf("cursor=%d, want 3 (at end)", ti.cursor)
	}
}

func TestSimpleInput_InsertCharacter(t *testing.T) {
	ti := newSimpleInput()
	ti.Focus()

	// Insert at end (empty)
	ti, _ = ti.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if ti.Value() != "a" {
		t.Errorf("got %q, want %q", ti.Value(), "a")
	}

	// Insert at end
	ti, _ = ti.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
	ti, _ = ti.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if ti.Value() != "abc" {
		t.Errorf("got %q, want %q", ti.Value(), "abc")
	}

	// Insert at beginning
	ti.cursor = 0
	ti, _ = ti.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if ti.Value() != "xabc" {
		t.Errorf("got %q, want %q", ti.Value(), "xabc")
	}

	// Insert at middle
	ti.cursor = 2
	ti, _ = ti.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if ti.Value() != "xaybc" {
		t.Errorf("got %q, want %q", ti.Value(), "xaybc")
	}

	// CharLimit rejection
	ti2 := newSimpleInput()
	ti2.charLimit = 3
	ti2.SetValue("abc")
	ti2, _ = ti2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if ti2.Value() != "abc" {
		t.Errorf("charLimit: got %q, want %q", ti2.Value(), "abc")
	}
}

func TestSimpleInput_Backspace(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("abc")

	// Normal backspace at end
	ti, _ = ti.Update(keyMsg("backspace"))
	if ti.Value() != "ab" {
		t.Errorf("got %q, want %q", ti.Value(), "ab")
	}

	// Backspace at cursor=0 (no-op)
	ti.cursor = 0
	ti, _ = ti.Update(keyMsg("backspace"))
	if ti.Value() != "ab" {
		t.Errorf("got %q, want %q", ti.Value(), "ab")
	}

	// Backspace on empty
	ti3 := newSimpleInput()
	ti3, _ = ti3.Update(keyMsg("backspace"))
	if ti3.Value() != "" {
		t.Errorf("got %q, want empty", ti3.Value())
	}
}

func TestSimpleInput_Delete(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("abc")

	// Delete at position 1
	ti.cursor = 1
	ti, _ = ti.Update(keyMsg("delete"))
	if ti.Value() != "ac" {
		t.Errorf("got %q, want %q", ti.Value(), "ac")
	}

	// Delete at end (no-op)
	ti.cursor = len(ti.value)
	ti, _ = ti.Update(keyMsg("delete"))
	if ti.Value() != "ac" {
		t.Errorf("got %q, want %q", ti.Value(), "ac")
	}

	// Delete on empty
	ti2 := newSimpleInput()
	ti2, _ = ti2.Update(keyMsg("delete"))
	if ti2.Value() != "" {
		t.Errorf("got %q, want empty", ti2.Value())
	}
}

func TestSimpleInput_CursorMovement(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("abcde")

	// Left
	ti, _ = ti.Update(keyMsg("left"))
	if ti.cursor != 4 {
		t.Errorf("left: cursor=%d, want 4", ti.cursor)
	}

	// Right back to end
	ti, _ = ti.Update(keyMsg("right"))
	if ti.cursor != 5 {
		t.Errorf("right: cursor=%d, want 5", ti.cursor)
	}

	// Right at end (clamped)
	ti, _ = ti.Update(keyMsg("right"))
	if ti.cursor != 5 {
		t.Errorf("right clamped: cursor=%d, want 5", ti.cursor)
	}

	// Left at 0 (clamped)
	ti.cursor = 0
	ti, _ = ti.Update(keyMsg("left"))
	if ti.cursor != 0 {
		t.Errorf("left clamped: cursor=%d, want 0", ti.cursor)
	}

	// Home
	ti.cursor = 3
	ti, _ = ti.Update(keyMsg("home"))
	if ti.cursor != 0 {
		t.Errorf("home: cursor=%d, want 0", ti.cursor)
	}

	// End
	ti, _ = ti.Update(keyMsg("end"))
	if ti.cursor != 5 {
		t.Errorf("end: cursor=%d, want 5", ti.cursor)
	}
}

func TestSimpleInput_KillToEnd(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("abcde")

	// Kill from middle
	ti.cursor = 2
	ti, _ = ti.Update(keyMsg("ctrl+k"))
	if ti.Value() != "ab" {
		t.Errorf("ctrl+k mid: got %q, want %q", ti.Value(), "ab")
	}

	// Kill from start
	ti.SetValue("hello")
	ti.cursor = 0
	ti, _ = ti.Update(keyMsg("ctrl+k"))
	if ti.Value() != "" {
		t.Errorf("ctrl+k start: got %q, want empty", ti.Value())
	}
}

func TestSimpleInput_KillToBeginning(t *testing.T) {
	ti := newSimpleInput()
	ti.SetValue("abcde")

	// Kill to beginning from middle
	ti.cursor = 3
	ti, _ = ti.Update(keyMsg("ctrl+u"))
	if ti.Value() != "de" {
		t.Errorf("ctrl+u mid: got %q, want %q", ti.Value(), "de")
	}
	if ti.cursor != 0 {
		t.Errorf("ctrl+u cursor=%d, want 0", ti.cursor)
	}

	// Kill to beginning from start (no-op)
	ti.SetValue("hello")
	ti.cursor = 0
	ti, _ = ti.Update(keyMsg("ctrl+u"))
	if ti.Value() != "hello" {
		t.Errorf("ctrl+u at start: got %q, want %q", ti.Value(), "hello")
	}
}

func TestSimpleInput_FocusBlur(t *testing.T) {
	ti := newSimpleInput()
	if ti.focused {
		t.Error("expected unfocused initially")
	}

	ti.Focus()
	if !ti.focused {
		t.Error("expected focused after Focus()")
	}

	ti.Blur()
	if ti.focused {
		t.Error("expected unfocused after Blur()")
	}
}
