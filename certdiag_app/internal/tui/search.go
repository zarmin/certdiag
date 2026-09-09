package tui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type searchModel struct {
	textInput  textinput.Model
	active     bool
	filterText string
}

func newSearchModel() searchModel {
	ti := textinput.New()
	ti.Prompt = "Search: "
	ti.CharLimit = 100
	return searchModel{
		textInput: ti,
	}
}

func (s *searchModel) activate() tea.Cmd {
	s.active = true
	s.textInput.SetValue(s.filterText)
	return s.textInput.Focus()
}

func (s *searchModel) commitAndClose() {
	s.filterText = s.textInput.Value()
	s.active = false
	s.textInput.Blur()
}

func (s *searchModel) clearAndClose() {
	s.filterText = ""
	s.textInput.SetValue("")
	s.active = false
	s.textInput.Blur()
}

func (s *searchModel) update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	s.textInput, cmd = s.textInput.Update(msg)
	s.filterText = s.textInput.Value()
	return cmd
}

func (s *searchModel) view(width int) string {
	s.textInput.Width = width - 10
	return s.textInput.View()
}
