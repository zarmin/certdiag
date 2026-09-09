package tui

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	tea "github.com/charmbracelet/bubbletea"
)

// --- Shell ---

type shellExitMsg struct {
	err error
}

type shellExecCmd struct {
	cmd       *exec.Cmd
	introText string
}

func (s *shellExecCmd) Run() error {
	fmt.Fprintln(os.Stdout, s.introText)
	return s.cmd.Run()
}

func (s *shellExecCmd) SetStdin(r io.Reader)  { s.cmd.Stdin = r }
func (s *shellExecCmd) SetStdout(w io.Writer) { s.cmd.Stdout = w }
func (s *shellExecCmd) SetStderr(w io.Writer) { s.cmd.Stderr = w }

func defaultShell() string {
	if runtime.GOOS == "windows" {
		if path, err := exec.LookPath("pwsh"); err == nil {
			return path
		}
		if path, err := exec.LookPath("powershell"); err == nil {
			return path
		}
		if s := os.Getenv("COMSPEC"); s != "" {
			return s
		}
		return "cmd.exe"
	}
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/sh"
}

func (m *RootModel) spawnShell(dir, file string) tea.Cmd {
	shell := defaultShell()
	c := exec.Command(shell)
	c.Dir = dir
	c.Env = append(os.Environ(),
		"CERTDIAG_SHELL=1",
		"FILE="+file,
	)
	intro := "certdiag shell -- type 'exit' to return"
	return tea.Exec(&shellExecCmd{cmd: c, introText: intro}, func(err error) tea.Msg {
		return shellExitMsg{err: err}
	})
}

func (m *RootModel) shellContextFromTree() (string, string) {
	if len(m.visible) > 0 && m.tree.cursor < len(m.visible) {
		node := m.visible[m.tree.cursor]
		if node.Container != nil {
			absPath, _ := filepath.Abs(node.Container.FilePath)
			return filepath.Dir(absPath), absPath
		}
	}
	return m.shellFallbackDir(), ""
}

func (m *RootModel) shellContextFromSplit() (string, string) {
	if m.focus == focusDetail && m.detail != nil {
		node := m.detail.node
		if node.Container != nil {
			absPath, _ := filepath.Abs(node.Container.FilePath)
			return filepath.Dir(absPath), absPath
		}
	}
	return m.shellContextFromTree()
}

func (m *RootModel) shellFallbackDir() string {
	abs, _ := filepath.Abs(m.scanPath)
	return abs
}

func (m *RootModel) showShellPopup(dir, file string) {
	m.shellName = defaultShell()
	m.shellDir = dir
	m.shellFile = file
	lines := []string{m.shellName, dir}
	if file != "" {
		lines = append(lines, file)
	}
	m.popup = popupState{kind: popupShell, lines: lines}
}
