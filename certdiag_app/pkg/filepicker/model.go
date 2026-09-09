package filepicker

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

type focusTarget int

const (
	focusList       focusTarget = iota
	focusFilename               // TypeSaveFile only
	focusShowHidden             // when filter bar visible
	focusAllFiles               // when filterOverridable
	focusOK
	focusCancel
)

type modalKind int

const (
	modalNone modalKind = iota
	modalPath
	modalBookmarks
	modalNewDir
	modalAlert
	modalConfirm
)

type confirmKind int

const (
	confirmOverwrite confirmKind = iota
	confirmInvalidExtension
)

// Sub-modal state

type alertState struct {
	message string
	extra   string
}

type confirmState struct {
	kind    confirmKind
	message string
	extra   string
	payload string // path to pass on confirm
	yesNo   bool   // false = No focused, true = Yes focused
}

type pathState struct {
	input       simpleInput
	completions []string
	dropCursor  int // -1 = none selected; >=0 = that completion is highlighted
	dropScroll  int // index of first visible completion row
	isRed       bool
}

type bookmarksState struct {
	cursor int
}

type newDirState struct {
	input simpleInput
}

type pickerModel struct {
	cfg        *config
	startDir   string
	currentDir string
	allEntries []fileEntry // full readDir result
	entries    []fileEntry // filtered view (by name search)
	cursor     int
	scroll     int
	showHidden bool
	filterAll  bool
	focus      focusTarget
	filename   simpleInput // TypeSaveFile

	// search state
	searchMode  bool
	searchQuery string

	// multi-select state
	selected map[string]bool
	results  []string

	modal     modalKind
	alert     alertState
	confirm   confirmState
	pathMod   pathState
	bmMod     bookmarksState
	newDirMod newDirState

	termW int
	termH int

	confirmedPath string
	resultErr     error
}

func newPickerModel(cfg *config, startDir string) pickerModel {
	m := pickerModel{
		cfg:        cfg,
		startDir:   startDir,
		currentDir: startDir,
		showHidden: cfg.showHidden,
		focus:      focusList,
		selected:   make(map[string]bool),
	}

	fn := newSimpleInput()
	fn.placeholder = "filename"
	fn.charLimit = 255
	fn.width = 40
	if cfg.saveName != "" {
		fn.SetValue(cfg.saveName)
	}
	m.filename = fn

	m.loadDir(startDir)
	return m
}

func (m *pickerModel) loadDir(dir string) {
	entries, err := readDir(dir, m.showHidden, m.cfg.fileFilter, m.filterAll, m.cfg.dialogType)
	if err != nil {
		m.modal = modalAlert
		m.alert = alertState{message: err.Error()}
		return
	}
	m.currentDir = dir
	m.allEntries = entries
	m.searchMode = false
	m.searchQuery = ""
	m.entries = entries
	m.cursor = 0
	m.scroll = 0
}

func (m pickerModel) Init() tea.Cmd {
	return nil
}

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.termW = msg.Width
		m.termH = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.modal {
		case modalAlert:
			return m.updateAlertModal(msg)
		case modalConfirm:
			return m.updateConfirmModal(msg)
		case modalPath:
			return m.updatePathModal(msg)
		case modalBookmarks:
			return m.updateBookmarksModal(msg)
		case modalNewDir:
			return m.updateNewDirModal(msg)
		}
		return m.updateMain(msg)
	}
	return m, nil
}

func (m pickerModel) updateMain(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Toggle hidden files while browsing the list. Kept off ctrl+h so that
	// terminals sending BS (0x08 == ctrl+h) keep working as Backspace.
	if key == keyDot && m.focus == focusList && !m.searchMode {
		m.showHidden = !m.showHidden
		m.reloadDir()
		return m, nil
	}

	switch key {
	case keyEsc:
		// In search mode, Esc clears search instead of cancelling the dialog
		if m.focus == focusList && m.searchMode {
			m.searchMode = false
			m.searchQuery = ""
			m.entries = m.allEntries
			m.cursor = 0
			m.scroll = 0
			return m, nil
		}
		m.resultErr = ErrCancelled
		return m, tea.Quit

	case keyTab:
		m.cycleFocus(1)
		m.syncFocus()
		return m, nil

	case keyShiftTab:
		m.cycleFocus(-1)
		m.syncFocus()
		return m, nil

	case keyCtrlP:
		return m.openPathModal()

	case keyCtrlB:
		if len(visibleBookmarks(m)) > 0 {
			return m.openBookmarksModal()
		}
		return m, nil

	case keyCtrlA:
		if m.cfg.filterOverridable {
			m.filterAll = !m.filterAll
			m.reloadDir()
		}
		return m, nil

	case keyF5:
		m.reloadDir()
		return m, nil

	case keyF7:
		if m.cfg.allowNewDir && m.currentDir != "" {
			return m.openNewDirModal()
		}
		return m, nil
	}

	switch m.focus {
	case focusList:
		return m.updateFileList(msg)

	case focusFilename:
		if key == keyEnter {
			if m2, cmd, ok := m.maybeResolvePath(); ok {
				return m2, cmd
			}
			// A typed name is a choice: Enter confirms it, as OK would.
			if strings.TrimSpace(m.filename.Value()) != "" {
				return m.doOK()
			}
			return m, nil
		}
		var cmd tea.Cmd
		m.filename, cmd = m.filename.Update(msg)
		return m, cmd

	case focusShowHidden:
		if key == keyEnter || key == keySpace {
			m.showHidden = !m.showHidden
			m.reloadDir()
		}
		return m, nil

	case focusAllFiles:
		if key == keyEnter || key == keySpace {
			m.filterAll = !m.filterAll
			m.reloadDir()
		}
		return m, nil

	case focusOK:
		if key == keyEnter || key == keySpace {
			return m.doOK()
		}
		return m, nil

	case focusCancel:
		if key == keyEnter || key == keySpace {
			m.resultErr = ErrCancelled
			return m, tea.Quit
		}
		return m, nil
	}

	return m, nil
}

func (m *pickerModel) syncFocus() {
	if m.focus == focusFilename {
		m.filename.Focus()
	} else {
		m.filename.Blur()
	}
}

func (m pickerModel) maybeResolvePath() (pickerModel, tea.Cmd, bool) {
	val := strings.TrimSpace(m.filename.Value())
	if val == "" || !strings.Contains(val, string(filepath.Separator)) {
		return m, nil, false
	}
	dir := filepath.Dir(val)
	base := filepath.Base(val)
	if _, err := os.Stat(dir); err != nil {
		return m, nil, false
	}
	m.loadDir(dir)
	m.filename.SetValue(base)
	return m, nil, true
}

func (m pickerModel) updateFileList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	listH := m.listHeight()
	n := len(m.entries)
	if n == 0 {
		return m, nil
	}

	switch key {
	case keyUp:
		if m.cursor > 0 {
			m.cursor--
			m.clampScroll(listH)
		}

	case keyDown:
		if m.cursor < n-1 {
			m.cursor++
			m.clampScroll(listH)
		}

	case keyPgUp:
		m.cursor -= listH
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.clampScroll(listH)

	case keyPgDown:
		m.cursor += listH
		if m.cursor >= n {
			m.cursor = n - 1
		}
		m.clampScroll(listH)

	case keyHome:
		m.cursor = 0
		m.scroll = 0

	case keyEnd:
		m.cursor = n - 1
		m.clampScroll(listH)

	case keySlash:
		m.searchMode = true
		m.searchQuery = ""
		m.entries = applyNameFilter(m.allEntries, m.searchQuery)
		m.cursor = 0
		m.scroll = 0

	case keyBackspace, keyCtrlH:
		if m.searchMode {
			runes := []rune(m.searchQuery)
			if len(runes) > 0 {
				m.searchQuery = string(runes[:len(runes)-1])
				m.entries = applyNameFilter(m.allEntries, m.searchQuery)
				m.cursor = 0
				m.scroll = 0
			}
			return m, nil
		}
		return m.navigateUp()

	case keySpace:
		if m.cfg.multiSelect {
			if m.cursor < len(m.entries) {
				e := m.entries[m.cursor]
				if !e.isDir && e.name != ".." && e.passesFilter {
					absPath := filepath.Join(m.currentDir, e.name)
					if m.selected[absPath] {
						delete(m.selected, absPath)
					} else {
						m.selected[absPath] = true
					}
				}
			}
			return m, nil
		}
		if m.searchMode {
			m.searchQuery += " "
			m.entries = applyNameFilter(m.allEntries, m.searchQuery)
			m.cursor = 0
			m.clampScroll(listH)
		}
		return m, nil

	case keyEnter:
		return m.activateEntry()

	default:
		if m.searchMode {
			if len(msg.Runes) == 1 {
				m.searchQuery += string(msg.Runes[0])
				m.entries = applyNameFilter(m.allEntries, m.searchQuery)
				m.cursor = 0
				m.clampScroll(listH)
			}
			return m, nil
		}
		if len(msg.Runes) == 1 {
			r := unicode.ToLower(msg.Runes[0])
			if r >= 'a' && r <= 'z' {
				m.letterJump(r)
				m.clampScroll(listH)
			}
		}
	}

	return m, nil
}

func (m *pickerModel) clampScroll(listH int) {
	if m.cursor < m.scroll {
		m.scroll = m.cursor
	}
	if m.cursor >= m.scroll+listH {
		m.scroll = m.cursor - listH + 1
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
}

func (m *pickerModel) reloadDir() {
	entries, err := readDir(m.currentDir, m.showHidden, m.cfg.fileFilter, m.filterAll, m.cfg.dialogType)
	if err != nil {
		m.modal = modalAlert
		m.alert = alertState{message: err.Error()}
		return
	}
	m.allEntries = entries
	m.entries = applyNameFilter(m.allEntries, m.searchQuery)
	if m.cursor >= len(m.entries) {
		m.cursor = len(m.entries) - 1
		if m.cursor < 0 {
			m.cursor = 0
		}
	}
	listH := m.listHeight()
	if maxScroll := len(m.entries) - listH; m.scroll > maxScroll {
		m.scroll = maxScroll
	}
	m.clampScroll(listH)
}

func (m *pickerModel) setCursorToEntry(name string) {
	for i, e := range m.entries {
		if e.name == name {
			m.cursor = i
			m.clampScroll(m.listHeight())
			break
		}
	}
}

func (m pickerModel) navigateUp() (tea.Model, tea.Cmd) {
	if m.currentDir == "" {
		return m, nil // already at virtual root
	}
	if isDriveRoot(m.currentDir) {
		// Go to virtual drive list; reposition cursor to the drive we came from
		prev := m.currentDir
		m.loadDir("")
		m.setCursorToEntry(prev)
		return m, nil
	}
	parent := filepath.Dir(m.currentDir)
	if parent == m.currentDir {
		return m, nil
	}
	oldBase := filepath.Base(m.currentDir)
	m.loadDir(parent)
	m.setCursorToEntry(oldBase)
	return m, nil
}

func (m pickerModel) activateEntry() (tea.Model, tea.Cmd) {
	if len(m.entries) == 0 {
		return m, nil
	}
	e := m.entries[m.cursor]

	if e.name == ".." {
		return m.navigateUp()
	}

	if e.disabled {
		return m, nil
	}

	if e.isDir {
		var target string
		if m.currentDir == "" {
			target = e.name // drive root, e.g. "C:\"
		} else if e.isSymlink && e.symlinkTarget != "" {
			target = e.symlinkTarget
		} else {
			target = filepath.Join(m.currentDir, e.name)
		}
		m.loadDir(target)
		return m, nil
	}

	if m.cfg.dialogType == TypeOpenFile && e.passesFilter {
		path := filepath.Join(m.currentDir, e.name)
		if m.cfg.multiSelect {
			m.results = []string{path}
		} else {
			m.confirmedPath = path
		}
		return m, tea.Quit
	}
	if m.cfg.dialogType == TypeSaveFile {
		m.filename.SetValue(e.name)
		m.focus = focusFilename
	}
	return m, nil
}

func (m pickerModel) doOK() (tea.Model, tea.Cmd) {
	switch m.cfg.dialogType {
	case TypeOpenFile:
		if m.cfg.multiSelect && len(m.selected) > 0 {
			paths := make([]string, 0, len(m.selected))
			for p := range m.selected {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			m.results = paths
			return m, tea.Quit
		}
		if len(m.entries) > 0 && m.cursor < len(m.entries) {
			e := m.entries[m.cursor]
			if !e.isDir && e.passesFilter {
				path := filepath.Join(m.currentDir, e.name)
				if m.cfg.multiSelect {
					m.results = []string{path}
				} else {
					m.confirmedPath = path
				}
				return m, tea.Quit
			}
		}
		return m, nil

	case TypeOpenDir:
		if m.currentDir == "" {
			return m, nil // can't confirm virtual root as a directory
		}
		m.confirmedPath = m.currentDir
		return m, tea.Quit

	case TypeSaveFile:
		return m.doSave()
	}
	return m, nil
}

func (m pickerModel) doSave() (tea.Model, tea.Cmd) {
	if m.currentDir == "" {
		return m, nil // can't save at virtual root
	}
	name := strings.TrimSpace(m.filename.Value())
	if name == "" {
		m.modal = modalAlert
		m.alert = alertState{message: "Filename must not be empty."}
		return m, nil
	}

	if len(m.cfg.saveExtensions) > 0 && !m.filterAll && m.cfg.extensionMode != ExtensionModeAllowAll {
		ext := strings.ToLower(filepath.Ext(name))
		ok := false
		for _, ae := range m.cfg.saveExtensions {
			if strings.ToLower(ae) == ext {
				ok = true
				break
			}
		}
		if !ok {
			allowed := strings.Join(m.cfg.saveExtensions, "  ")
			switch m.cfg.extensionMode {
			case ExtensionModeStrict:
				m.modal = modalAlert
				m.alert = alertState{message: "File must have one of these extensions: " + allowed, extra: m.cfg.extensionWarning}
				return m, nil
			case ExtensionModeConfirm:
				fullPath := filepath.Join(m.currentDir, name)
				m.modal = modalConfirm
				m.confirm = confirmState{
					kind:    confirmInvalidExtension,
					message: "Extension not in recommended list (" + allowed + "). Save anyway?",
					extra:   m.cfg.extensionWarning,
					payload: fullPath,
					yesNo:   false,
				}
				return m, nil
			}
		}
	}

	fullPath := filepath.Join(m.currentDir, name)

	if m.cfg.checkFileExists {
		if _, err := os.Stat(fullPath); err == nil {
			m.modal = modalConfirm
			m.confirm = confirmState{
				kind:    confirmOverwrite,
				message: "File already exists. Overwrite?",
				payload: fullPath,
				yesNo:   false,
			}
			return m, nil
		}
	}

	return m.touchAndReturn(fullPath)
}

func (m pickerModel) proceedAfterExtensionConfirm() (tea.Model, tea.Cmd) {
	fullPath := m.confirm.payload
	if m.cfg.checkFileExists {
		if _, err := os.Stat(fullPath); err == nil {
			m.modal = modalConfirm
			m.confirm = confirmState{
				kind:    confirmOverwrite,
				message: "File already exists. Overwrite?",
				payload: fullPath,
				yesNo:   false,
			}
			return m, nil
		}
	}
	return m.touchAndReturn(fullPath)
}

func (m pickerModel) touchAndReturn(path string) (tea.Model, tea.Cmd) {
	m.confirmedPath = path
	return m, tea.Quit
}

func (m *pickerModel) letterJump(r rune) {
	for i, e := range m.entries {
		if e.name == ".." {
			continue
		}
		if len(e.name) > 0 && unicode.ToLower([]rune(e.name)[0]) == r {
			m.cursor = i
			return
		}
	}
}

func (m *pickerModel) cycleFocus(dir int) {
	order := m.focusOrder()
	if len(order) == 0 {
		return
	}
	cur := -1
	for i, f := range order {
		if f == m.focus {
			cur = i
			break
		}
	}
	if cur == -1 {
		m.focus = order[0]
		return
	}
	next := (cur + dir + len(order)) % len(order)
	m.focus = order[next]
}

func (m *pickerModel) focusOrder() []focusTarget {
	order := []focusTarget{focusList}
	if m.cfg.dialogType == TypeSaveFile {
		order = append(order, focusFilename)
	}
	if m.showsFilterBar() {
		order = append(order, focusShowHidden)
		if m.cfg.filterOverridable {
			order = append(order, focusAllFiles)
		}
	}
	order = append(order, focusOK, focusCancel)
	return order
}

func (m *pickerModel) showsFilterBar() bool {
	switch m.cfg.dialogType {
	case TypeOpenDir:
		return false
	case TypeOpenFile:
		return len(m.cfg.fileFilter) > 0 || m.cfg.multiSelect
	case TypeSaveFile:
		return false
	}
	return false
}

func (m *pickerModel) listHeight() int {
	_, boxH := m.boxDims()
	fixed := 2 + 2 + 2 + 2 + 2 + 2 // title, path, header+rule, status, buttons, hints+borders
	if m.cfg.dialogType == TypeSaveFile {
		fixed += 3
	} else if m.cfg.dialogType == TypeOpenDir {
		fixed += 2
	}
	if m.showsFilterBar() {
		fixed += 2
	}
	h := boxH - fixed
	if h < 1 {
		return 1
	}
	return h
}

func (m *pickerModel) boxDims() (int, int) {
	w := m.termW
	h := m.termH
	if w > 120 {
		w = 120
	}
	if h > 40 {
		h = 40
	}
	if w < 80 {
		w = 80
	}
	if h < 22 {
		h = 22
	}
	return w, h
}

func (m pickerModel) openPathModal() (tea.Model, tea.Cmd) {
	ti := newSimpleInput()
	ti.placeholder = "path"
	ti.charLimit = 512
	ti.width = 36
	if m.currentDir != "" {
		ti.SetValue(m.currentDir + "/")
	}
	ti.Focus()
	m.pathMod = pathState{input: ti, dropCursor: -1}
	m.modal = modalPath
	m = m.updateCompletions()
	return m, nil
}

func (m pickerModel) openBookmarksModal() (tea.Model, tea.Cmd) {
	m.modal = modalBookmarks
	bms := visibleBookmarks(m)
	if m.bmMod.cursor >= len(bms) {
		m.bmMod.cursor = 0
	}
	return m, nil
}

func (m pickerModel) openNewDirModal() (tea.Model, tea.Cmd) {
	ti := newSimpleInput()
	ti.placeholder = "folder name"
	ti.charLimit = 255
	ti.width = 30
	ti.Focus()
	m.newDirMod = newDirState{input: ti}
	m.modal = modalNewDir
	return m, nil
}
