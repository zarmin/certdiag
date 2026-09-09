package filepicker

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Files
	os.WriteFile(filepath.Join(dir, "file1.pem"), []byte("pem"), 0644)
	os.WriteFile(filepath.Join(dir, "file2.crt"), []byte("crt"), 0644)
	os.WriteFile(filepath.Join(dir, "file3.key"), []byte("key content"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("text"), 0644)
	os.WriteFile(filepath.Join(dir, ".hidden"), []byte("hidden"), 0644)

	// Directories
	os.MkdirAll(filepath.Join(dir, ".hiddendir"), 0755)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.MkdirAll(filepath.Join(dir, "adir"), 0755)
	os.MkdirAll(filepath.Join(dir, "zdir"), 0755)

	// Nested file
	os.WriteFile(filepath.Join(dir, "subdir", "nested.pem"), []byte("nested"), 0644)

	return dir
}

func makeTestModel(t *testing.T, dt DialogType, dir string) pickerModel {
	t.Helper()
	cfg := &config{dialogType: dt}
	m := newPickerModel(cfg, dir)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return updated.(pickerModel)
}

func makeTestModelWithConfig(t *testing.T, cfg *config, dir string) pickerModel {
	t.Helper()
	m := newPickerModel(cfg, dir)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	return updated.(pickerModel)
}

func sendKey(m pickerModel, key string) pickerModel {
	msg := keyMsg(key)
	updated, _ := m.Update(msg)
	return updated.(pickerModel)
}

func typeString(m pickerModel, s string) pickerModel {
	for _, r := range s {
		m = sendKey(m, string(r))
	}
	return m
}

func keyMsg(key string) tea.KeyMsg {
	switch key {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "home":
		return tea.KeyMsg{Type: tea.KeyHome}
	case "end":
		return tea.KeyMsg{Type: tea.KeyEnd}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "delete":
		return tea.KeyMsg{Type: tea.KeyDelete}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "f5":
		return tea.KeyMsg{Type: tea.KeyF5}
	case "f7":
		return tea.KeyMsg{Type: tea.KeyF7}
	case "ctrl+a":
		return tea.KeyMsg{Type: tea.KeyCtrlA}
	case "ctrl+b":
		return tea.KeyMsg{Type: tea.KeyCtrlB}
	case "ctrl+e":
		return tea.KeyMsg{Type: tea.KeyCtrlE}
	case "ctrl+h":
		return tea.KeyMsg{Type: tea.KeyCtrlH}
	case "ctrl+k":
		return tea.KeyMsg{Type: tea.KeyCtrlK}
	case "ctrl+p":
		return tea.KeyMsg{Type: tea.KeyCtrlP}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "ctrl+w":
		return tea.KeyMsg{Type: tea.KeyCtrlW}
	case "/":
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}}
	default:
		if len([]rune(key)) == 1 {
			return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
		}
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
}
