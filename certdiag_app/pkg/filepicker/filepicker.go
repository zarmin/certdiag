package filepicker

import (
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

type DialogType int

const (
	TypeOpenFile DialogType = iota
	TypeOpenDir
	TypeSaveFile
)

type ExtensionMode int

const (
	ExtensionModeConfirm  ExtensionMode = iota // ask yes/no for non-matching extensions
	ExtensionModeAllowAll                      // accept any extension
	ExtensionModeStrict                        // block non-matching extensions
)

type Bookmark struct {
	Label string
	Path  string
}

type config struct {
	dialogType        DialogType
	startDir          string
	fileFilter        []string
	filterOverridable bool
	showHidden        bool
	allowNewDir       bool
	bookmarks         []Bookmark
	saveExtensions    []string
	extensionMode     ExtensionMode
	extensionWarning  string
	title             string
	multiSelect       bool
	checkFileExists   bool
	saveName          string
}

type Picker struct {
	cfg       config
	stdin     io.Reader
	stdout    io.Writer
	stderr    io.Writer
	result    string
	resultErr error
	results   []string
	hasRun    bool
}

func New(dt DialogType) *Picker {
	title := ""
	switch dt {
	case TypeOpenFile:
		title = "Open File"
	case TypeOpenDir:
		title = "Open Directory"
	case TypeSaveFile:
		title = "Save File"
	}
	return &Picker{
		cfg: config{
			dialogType: dt,
			title:      title,
		},
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
}

func (p *Picker) WithStartDir(path string) *Picker {
	p.cfg.startDir = path
	return p
}

func (p *Picker) WithFileFilter(exts []string) *Picker {
	p.cfg.fileFilter = exts
	return p
}

func (p *Picker) WithFilterOverridable(v bool) *Picker {
	p.cfg.filterOverridable = v
	return p
}

func (p *Picker) WithShowHidden(v bool) *Picker {
	p.cfg.showHidden = v
	return p
}

func (p *Picker) WithAllowNewDir(v bool) *Picker {
	p.cfg.allowNewDir = v
	return p
}

func (p *Picker) WithBookmarks(bm []Bookmark) *Picker {
	p.cfg.bookmarks = bm
	return p
}

func (p *Picker) WithSaveExtensions(exts []string) *Picker {
	p.cfg.saveExtensions = exts
	return p
}

func (p *Picker) WithExtensionMode(mode ExtensionMode) *Picker {
	p.cfg.extensionMode = mode
	return p
}

func (p *Picker) WithExtensionWarning(msg string) *Picker {
	p.cfg.extensionWarning = msg
	return p
}

func (p *Picker) WithTitle(title string) *Picker {
	p.cfg.title = title
	return p
}

func (p *Picker) WithMultiSelect(v bool) *Picker {
	p.cfg.multiSelect = v
	return p
}

func (p *Picker) WithCheckFileExists(v bool) *Picker {
	p.cfg.checkFileExists = v
	return p
}

func (p *Picker) WithSaveName(name string) *Picker {
	p.cfg.saveName = name
	return p
}

// SetStdin implements tea.ExecCommand.
func (p *Picker) SetStdin(r io.Reader) {
	p.stdin = r
}

// SetStdout implements tea.ExecCommand.
func (p *Picker) SetStdout(w io.Writer) {
	p.stdout = w
}

// SetStderr implements tea.ExecCommand.
func (p *Picker) SetStderr(w io.Writer) {
	p.stderr = w
}

// Run implements tea.ExecCommand and also serves as the standalone entry point.
func (p *Picker) Run() error {
	startDir := p.cfg.startDir
	if startDir == "" {
		var err error
		startDir, err = os.Getwd()
		if err != nil {
			startDir = os.Getenv("HOME")
		}
	}

	opts := []tea.ProgramOption{
		tea.WithAltScreen(),
		tea.WithInput(p.stdin),
		tea.WithOutput(p.stdout),
	}

	prog := tea.NewProgram(newPickerModel(&p.cfg, startDir), opts...)
	finalModel, err := prog.Run()
	if err != nil {
		return err
	}

	m, ok := finalModel.(pickerModel)
	if !ok {
		return nil
	}
	p.result = m.confirmedPath
	p.results = m.results
	p.resultErr = m.resultErr
	p.hasRun = true
	return nil
}

// Result returns the selected path and error after Run() has completed.
// Returns ErrNotRun if Run() has not been called.
// For multi-select, returns the first selected path; use Results() for all paths.
func (p *Picker) Result() (string, error) {
	if !p.hasRun {
		return "", ErrNotRun
	}
	if len(p.results) > 0 {
		return p.results[0], p.resultErr
	}
	return p.result, p.resultErr
}

// Results returns all selected paths after Run() has completed (multi-select mode).
func (p *Picker) Results() []string {
	return p.results
}

// RunAndResult runs the picker and returns the result in one call.
// For multi-select use RunAndResults.
func (p *Picker) RunAndResult() (string, error) {
	if err := p.Run(); err != nil {
		return "", err
	}
	return p.Result()
}

// RunAndResults runs the picker and returns all selected paths in one call.
func (p *Picker) RunAndResults() ([]string, error) {
	if err := p.Run(); err != nil {
		return nil, err
	}
	return p.Results(), nil
}
