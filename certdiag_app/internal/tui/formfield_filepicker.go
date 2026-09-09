package tui

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

type filePickerField struct {
	typedHint        bool // a key was typed into the field since the last Enter
	name             string
	label            string
	mode             filepicker.DialogType
	autoExt          string
	saveExtensions   []string
	extensionWarning string
	fileFilter       []string
	currentPath      string
	initial          string
	visible          bool
	scanPath         string
	placeholder      func() string
}

func newFilePickerField(name, label string, mode filepicker.DialogType, scanPath string, autoExt string, saveExts []string) *filePickerField {
	return &filePickerField{
		name:           name,
		label:          label,
		mode:           mode,
		autoExt:        autoExt,
		saveExtensions: saveExts,
		visible:        true,
		scanPath:       scanPath,
	}
}

func (f *filePickerField) View(focused bool, width int) string {
	labelW := width / 4
	if labelW < 12 {
		labelW = 12
	}
	if labelW > 20 {
		labelW = 20
	}
	label := fmt.Sprintf("%-*s", labelW, f.label+":")
	if focused {
		label = styleFormLabelFoc.Render(label)
	} else {
		label = styleFormLabel.Render(label)
	}

	var value string
	if f.currentPath != "" {
		value = f.currentPath
		// Truncate long paths
		maxValW := width - labelW - 2
		if maxValW > 0 && len(value) > maxValW {
			value = "..." + value[len(value)-(maxValW-3):]
		}
	} else {
		hint := ""
		if f.placeholder != nil {
			hint = f.placeholder()
		}
		if hint != "" {
			value = styleFormHint.Render(hint)
		} else {
			hint := "(press Enter to browse)"
			if f.typedHint {
				hint = "(typing has no effect here; press Enter to browse)"
			}
			value = styleFormHint.Render(hint)
		}
	}

	return label + " " + value
}

func (f *filePickerField) Height() int { return 1 }

func (f *filePickerField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	if !isKeyEnter(msg) {
		// Typing into a picker field does nothing; say so instead of
		// swallowing the keys (M31 E9).
		if msg.Type == tea.KeyRunes {
			f.typedHint = true
		}
		return f, nil
	}
	f.typedHint = false

	picker := filepicker.New(f.mode).
		WithTitle(f.label).
		WithStartDir(scanDir(f.scanPath)).
		WithBookmarks(scanPathBookmark(f.scanPath)).
		WithAllowNewDir(f.mode == filepicker.TypeSaveFile || f.mode == filepicker.TypeOpenDir)

	if f.mode == filepicker.TypeOpenFile {
		exts := []string{".pem", ".crt", ".cer", ".key"}
		if len(f.fileFilter) > 0 {
			exts = f.fileFilter
		}
		picker = picker.
			WithFileFilter(exts).
			WithFilterOverridable(true)
	}

	if f.mode == filepicker.TypeSaveFile && len(f.saveExtensions) > 0 {
		picker = picker.
			WithSaveExtensions(f.saveExtensions).
			WithExtensionMode(filepicker.ExtensionModeConfirm).
			WithExtensionWarning(f.extensionWarning)
	}

	name := f.name
	autoExt := f.autoExt

	cmd := tea.Exec(picker, func(err error) tea.Msg {
		if err != nil {
			return nil
		}
		path, perr := picker.Result()
		if perr != nil {
			return nil
		}
		if path == "" {
			return nil
		}
		if autoExt != "" && filepath.Ext(path) == "" {
			path += autoExt
		}
		return filePickedMsg{fieldName: name, path: path}
	})

	return f, cmd
}

func (f *filePickerField) Focus() {}
func (f *filePickerField) Blur()  {}

func (f *filePickerField) Value() string {
	return f.currentPath
}

// ResolvedValue returns the chosen path, or - when the field was left empty but
// a non-empty placeholder is suggested - the placeholder resolved into the scan
// directory. This mirrors what the user sees on screen so that save-file fields
// left blank still write to the suggested location instead of writing nothing.
func (f *filePickerField) ResolvedValue() string {
	if f.currentPath != "" {
		return f.currentPath
	}
	if f.placeholder == nil {
		return ""
	}
	p := f.placeholder()
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) || f.scanPath == "" {
		return p
	}
	return filepath.Join(scanDir(f.scanPath), p)
}

func (f *filePickerField) SetValue(v string) {
	f.currentPath = v
	f.initial = v
}

func (f *filePickerField) Validate() error {
	if f.currentPath == "" {
		if f.placeholder != nil && f.placeholder() != "" {
			return nil
		}
		return fmt.Errorf("%s is required", f.label)
	}
	return nil
}

func (f *filePickerField) SetSaveExtensions(exts []string) { f.saveExtensions = exts }
func (f *filePickerField) SetAutoExt(ext string)           { f.autoExt = ext }
func (f *filePickerField) SetExtensionWarning(msg string)  { f.extensionWarning = msg }
func (f *filePickerField) SetFileFilter(exts []string)     { f.fileFilter = exts }

func (f *filePickerField) IsDirty() bool       { return f.currentPath != f.initial }
func (f *filePickerField) Visible() bool       { return f.visible }
func (f *filePickerField) SetVisible(v bool)   { f.visible = v }
func (f *filePickerField) Focusable() bool     { return true }
func (f *filePickerField) AtBoundary(int) bool { return true }

func scanPathBookmark(scanPath string) []filepicker.Bookmark {
	home, _ := os.UserHomeDir()

	info, err := os.Stat(scanPath)
	var dir string
	if err == nil && info.IsDir() {
		dir = scanPath
	} else {
		dir = filepath.Dir(scanPath)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	if home != "" && abs == home {
		return nil
	}
	label := filepath.Base(abs)
	if label == "." || label == "" {
		label = abs
	}
	return []filepicker.Bookmark{{Label: label, Path: abs}}
}

// resolvedFilePath returns the effective path for a file-picker field, falling
// back to its placeholder-suggested path when the field was left empty.
func resolvedFilePath(form *formModel, name string) string {
	if fp, ok := form.fieldByName(name).(*filePickerField); ok {
		return fp.ResolvedValue()
	}
	return form.fieldValue(name)
}

func scanDir(scanPath string) string {
	info, err := os.Stat(scanPath)
	var dir string
	if err == nil && info.IsDir() {
		dir = scanPath
	} else {
		dir = filepath.Dir(scanPath)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	if _, err := os.Stat(abs); err == nil {
		return abs
	}
	home, err := os.UserHomeDir()
	if err == nil {
		return home
	}
	return "."
}
