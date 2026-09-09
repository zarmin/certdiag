package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type FormField interface {
	View(focused bool, width int) string
	Height() int
	Update(msg tea.KeyMsg) (FormField, tea.Cmd)
	Focus()
	Blur()
	Value() string
	SetValue(string)
	Validate() error
	IsDirty() bool
	Visible() bool
	SetVisible(bool)
	Focusable() bool
	AtBoundary(direction int) bool // -1 = top, +1 = bottom
}

// --- textInputField ---

type textInputField struct {
	label      string
	input      textinput.Model
	required   bool
	validateFn func(string) error
	visible    bool
	initial    string
}

func newTextInputField(label string, placeholder string, required bool, validateFn func(string) error) *textInputField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	return &textInputField{
		label:      label,
		input:      ti,
		required:   required,
		validateFn: validateFn,
		visible:    true,
	}
}

func newPasswordInputField(label string, placeholder string, required bool, validateFn func(string) error) *textInputField {
	f := newTextInputField(label, placeholder, required, validateFn)
	f.input.EchoMode = textinput.EchoPassword
	f.input.EchoCharacter = '*'
	return f
}

func (f *textInputField) View(focused bool, width int) string {
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
	f.input.Width = width - labelW - 2
	return label + " " + f.input.View()
}

func (f *textInputField) Height() int { return 1 }

func (f *textInputField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	var cmd tea.Cmd
	f.input, cmd = f.input.Update(msg)
	return f, cmd
}

func (f *textInputField) Focus() { f.input.Focus() }
func (f *textInputField) Blur()  { f.input.Blur() }

func (f *textInputField) Value() string     { return f.input.Value() }
func (f *textInputField) SetValue(v string) { f.input.SetValue(v); f.initial = v }

func (f *textInputField) Validate() error {
	v := f.input.Value()
	if f.required && strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is required", f.label)
	}
	if f.validateFn != nil {
		return f.validateFn(v)
	}
	return nil
}

func (f *textInputField) IsDirty() bool       { return f.input.Value() != f.initial }
func (f *textInputField) Visible() bool       { return f.visible }
func (f *textInputField) SetVisible(v bool)   { f.visible = v }
func (f *textInputField) Focusable() bool     { return true }
func (f *textInputField) AtBoundary(int) bool { return true }

// --- radioGroupField ---

type radioGroupField struct {
	label    string
	options  []string
	selected int
	visible  bool
	initial  int
}

func newRadioGroupField(label string, options []string, defaultIdx int) *radioGroupField {
	if defaultIdx < 0 || defaultIdx >= len(options) {
		defaultIdx = 0
	}
	return &radioGroupField{
		label:    label,
		options:  options,
		selected: defaultIdx,
		visible:  true,
		initial:  defaultIdx,
	}
}

func (f *radioGroupField) View(focused bool, width int) string {
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

	var opts []string
	for i, o := range f.options {
		if i == f.selected {
			if focused {
				opts = append(opts, styleFormButtonFoc.Render("["+o+"]"))
			} else {
				opts = append(opts, styleFormButton.Render("["+o+"]"))
			}
		} else {
			opts = append(opts, " "+o+" ")
		}
	}
	return label + " " + strings.Join(opts, " ")
}

func (f *radioGroupField) Height() int { return 1 }

func (f *radioGroupField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	switch {
	case isKeyRight(msg):
		f.selected = (f.selected + 1) % len(f.options)
	case isKeyLeft(msg):
		f.selected = (f.selected - 1 + len(f.options)) % len(f.options)
	}
	return f, nil
}

func (f *radioGroupField) Focus()        {}
func (f *radioGroupField) Blur()         {}
func (f *radioGroupField) Value() string { return f.options[f.selected] }
func (f *radioGroupField) SetValue(v string) {
	for i, o := range f.options {
		if o == v {
			f.selected = i
			f.initial = i
			return
		}
	}
}
func (f *radioGroupField) Validate() error     { return nil }
func (f *radioGroupField) IsDirty() bool       { return f.selected != f.initial }
func (f *radioGroupField) Visible() bool       { return f.visible }
func (f *radioGroupField) SetVisible(v bool)   { f.visible = v }
func (f *radioGroupField) Focusable() bool     { return true }
func (f *radioGroupField) AtBoundary(int) bool { return true }

// --- checkboxField ---

type checkboxField struct {
	label   string
	checked bool
	visible bool
	initial bool
}

func newCheckboxField(label string, defaultChecked bool) *checkboxField {
	return &checkboxField{
		label:   label,
		checked: defaultChecked,
		visible: true,
		initial: defaultChecked,
	}
}

func (f *checkboxField) View(focused bool, width int) string {
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

	check := "[ ]"
	if f.checked {
		check = "[x]"
	}
	if focused {
		check = styleFormButtonFoc.Render(check)
	}
	return label + " " + check
}

func (f *checkboxField) Height() int { return 1 }

func (f *checkboxField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	if msg.String() == " " {
		f.checked = !f.checked
	}
	return f, nil
}

func (f *checkboxField) Focus() {}
func (f *checkboxField) Blur()  {}
func (f *checkboxField) Value() string {
	if f.checked {
		return "true"
	}
	return "false"
}
func (f *checkboxField) SetValue(v string) {
	f.checked = v == "true"
	f.initial = f.checked
}
func (f *checkboxField) Validate() error     { return nil }
func (f *checkboxField) IsDirty() bool       { return f.checked != f.initial }
func (f *checkboxField) Visible() bool       { return f.visible }
func (f *checkboxField) SetVisible(v bool)   { f.visible = v }
func (f *checkboxField) Focusable() bool     { return true }
func (f *checkboxField) AtBoundary(int) bool { return true }

// --- dynamicListField ---

type dynamicListField struct {
	label    string
	inputs   []textinput.Model
	focusIdx int
	visible  bool
	initial  string
}

func newDynamicListField(label string, placeholder string) *dynamicListField {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	return &dynamicListField{
		label:   label,
		inputs:  []textinput.Model{ti},
		visible: true,
	}
}

func (f *dynamicListField) View(focused bool, width int) string {
	labelW := width / 4
	if labelW < 12 {
		labelW = 12
	}
	if labelW > 20 {
		labelW = 20
	}
	inputW := width - labelW - 2

	var lines []string
	for i, inp := range f.inputs {
		var label string
		if i == 0 {
			label = fmt.Sprintf("%-*s", labelW, f.label+":")
		} else {
			label = fmt.Sprintf("%-*s", labelW, "")
		}

		isFocusedRow := focused && i == f.focusIdx
		if i == 0 && focused {
			label = styleFormLabelFoc.Render(label)
		} else if i == 0 {
			label = styleFormLabel.Render(label)
		}

		inp.Width = inputW
		if isFocusedRow {
			f.inputs[i].Width = inputW
		}
		lines = append(lines, label+" "+f.inputs[i].View())
		_ = isFocusedRow
	}

	if focused {
		hint := fmt.Sprintf("%-*s (Enter: add, Backspace on empty: remove)", labelW, "")
		lines = append(lines, styleFormHint.Render(hint))
	}

	return strings.Join(lines, "\n")
}

func (f *dynamicListField) Height() int {
	return len(f.inputs) + 1 // +1 for hint line when focused
}

func (f *dynamicListField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	switch {
	case isKeyDown(msg):
		if f.focusIdx < len(f.inputs)-1 {
			f.inputs[f.focusIdx].Blur()
			f.focusIdx++
			f.inputs[f.focusIdx].Focus()
		}
		return f, nil
	case isKeyUp(msg):
		if f.focusIdx > 0 {
			f.inputs[f.focusIdx].Blur()
			f.focusIdx--
			f.inputs[f.focusIdx].Focus()
		}
		return f, nil
	case isKeyEnter(msg):
		ti := textinput.New()
		ti.Placeholder = f.inputs[0].Placeholder
		ti.CharLimit = 256
		idx := f.focusIdx + 1
		f.inputs = append(f.inputs, textinput.Model{})
		copy(f.inputs[idx+1:], f.inputs[idx:])
		f.inputs[idx] = ti
		f.inputs[f.focusIdx].Blur()
		f.focusIdx = idx
		f.inputs[f.focusIdx].Focus()
		return f, nil
	case msg.String() == "backspace":
		if len(f.inputs) > 1 && f.inputs[f.focusIdx].Value() == "" {
			f.inputs[f.focusIdx].Blur()
			f.inputs = append(f.inputs[:f.focusIdx], f.inputs[f.focusIdx+1:]...)
			if f.focusIdx >= len(f.inputs) {
				f.focusIdx = len(f.inputs) - 1
			}
			f.inputs[f.focusIdx].Focus()
			return f, nil
		}
	}

	var cmd tea.Cmd
	f.inputs[f.focusIdx], cmd = f.inputs[f.focusIdx].Update(msg)
	return f, cmd
}

func (f *dynamicListField) Focus() {
	if f.focusIdx < len(f.inputs) {
		f.inputs[f.focusIdx].Focus()
	}
}

func (f *dynamicListField) Blur() {
	for i := range f.inputs {
		f.inputs[i].Blur()
	}
}

func (f *dynamicListField) Value() string {
	var vals []string
	for _, inp := range f.inputs {
		v := strings.TrimSpace(inp.Value())
		if v != "" {
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, ",")
}

func (f *dynamicListField) SetValue(v string) {
	parts := strings.Split(v, ",")
	f.inputs = nil
	for _, p := range parts {
		p = strings.TrimSpace(p)
		ti := textinput.New()
		ti.Placeholder = ""
		ti.CharLimit = 256
		ti.SetValue(p)
		f.inputs = append(f.inputs, ti)
	}
	if len(f.inputs) == 0 {
		ti := textinput.New()
		ti.CharLimit = 256
		f.inputs = []textinput.Model{ti}
	}
	f.focusIdx = 0
	f.initial = f.Value()
}

func (f *dynamicListField) Validate() error   { return nil }
func (f *dynamicListField) IsDirty() bool     { return f.Value() != f.initial }
func (f *dynamicListField) Visible() bool     { return f.visible }
func (f *dynamicListField) SetVisible(v bool) { f.visible = v }
func (f *dynamicListField) Focusable() bool   { return true }
func (f *dynamicListField) AtBoundary(direction int) bool {
	if direction < 0 {
		return f.focusIdx == 0
	}
	return f.focusIdx == len(f.inputs)-1
}

// --- multiCheckField ---

type multiCheckOption struct {
	label string
	value string
}

type multiCheckField struct {
	label    string
	options  []multiCheckOption
	selected []bool
	cursor   int
	visible  bool
	initial  string
}

func newMultiCheckField(label string, options []multiCheckOption, defaultValues string) *multiCheckField {
	selected := make([]bool, len(options))
	if defaultValues != "" {
		vals := make(map[string]bool)
		for _, v := range strings.Split(defaultValues, ",") {
			vals[strings.TrimSpace(v)] = true
		}
		for i, opt := range options {
			if vals[opt.value] {
				selected[i] = true
			}
		}
	}
	f := &multiCheckField{
		label:    label,
		options:  options,
		selected: selected,
		visible:  true,
	}
	f.initial = f.Value()
	return f
}

func (f *multiCheckField) View(focused bool, width int) string {
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

	contentW := width - labelW - 1
	var rows [][]string
	var currentRow []string
	rowLen := 0
	for i, opt := range f.options {
		var item string
		if f.selected[i] {
			item = "[" + opt.label + "]"
		} else {
			item = " " + opt.label + " "
		}
		itemLen := len([]rune(item)) + 1
		if len(currentRow) > 0 && rowLen+itemLen > contentW {
			rows = append(rows, currentRow)
			currentRow = nil
			rowLen = 0
		}
		if focused && i == f.cursor {
			item = styleFormButtonFoc.Render(item)
		} else if f.selected[i] {
			item = styleFormButton.Render(item)
		}
		currentRow = append(currentRow, item)
		rowLen += itemLen
	}
	if len(currentRow) > 0 {
		rows = append(rows, currentRow)
	}

	var lines []string
	pad := strings.Repeat(" ", labelW+1)
	for ri, row := range rows {
		prefix := pad
		if ri == 0 {
			prefix = label + " "
		}
		lines = append(lines, prefix+strings.Join(row, " "))
	}
	if len(lines) == 0 {
		lines = append(lines, label)
	}
	return strings.Join(lines, "\n")
}

func (f *multiCheckField) Height() int {
	return strings.Count(f.View(false, 80), "\n") + 1
}

func (f *multiCheckField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	switch {
	case isKeyRight(msg):
		f.cursor = (f.cursor + 1) % len(f.options)
	case isKeyLeft(msg):
		f.cursor = (f.cursor - 1 + len(f.options)) % len(f.options)
	case msg.String() == " ":
		f.selected[f.cursor] = !f.selected[f.cursor]
	}
	return f, nil
}

func (f *multiCheckField) Focus() {}
func (f *multiCheckField) Blur()  {}
func (f *multiCheckField) Value() string {
	var vals []string
	for i, opt := range f.options {
		if f.selected[i] {
			vals = append(vals, opt.value)
		}
	}
	return strings.Join(vals, ",")
}
func (f *multiCheckField) SetValue(v string) {
	for i := range f.selected {
		f.selected[i] = false
	}
	if v != "" {
		vals := make(map[string]bool)
		for _, s := range strings.Split(v, ",") {
			vals[strings.TrimSpace(s)] = true
		}
		for i, opt := range f.options {
			if vals[opt.value] {
				f.selected[i] = true
			}
		}
	}
	f.initial = f.Value()
}
func (f *multiCheckField) Validate() error     { return nil }
func (f *multiCheckField) IsDirty() bool       { return f.Value() != f.initial }
func (f *multiCheckField) Visible() bool       { return f.visible }
func (f *multiCheckField) SetVisible(v bool)   { f.visible = v }
func (f *multiCheckField) Focusable() bool     { return true }
func (f *multiCheckField) AtBoundary(int) bool { return true }

// --- submitButtonField ---

type submitButtonField struct {
	label   string
	visible bool
}

func newSubmitButtonField(label string) *submitButtonField {
	return &submitButtonField{label: label, visible: true}
}

func (f *submitButtonField) View(focused bool, width int) string {
	text := "[ " + f.label + " ]"
	if focused {
		return styleFormButtonFoc.Render(text)
	}
	return styleFormButton.Render(text)
}

func (f *submitButtonField) Height() int                                { return 1 }
func (f *submitButtonField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) { return f, nil }
func (f *submitButtonField) Focus()                                     {}
func (f *submitButtonField) Blur()                                      {}
func (f *submitButtonField) Value() string                              { return "" }
func (f *submitButtonField) SetValue(string)                            {}
func (f *submitButtonField) Validate() error                            { return nil }
func (f *submitButtonField) IsDirty() bool                              { return false }
func (f *submitButtonField) Visible() bool                              { return f.visible }
func (f *submitButtonField) SetVisible(v bool)                          { f.visible = v }
func (f *submitButtonField) Focusable() bool                            { return true }
func (f *submitButtonField) AtBoundary(int) bool                        { return true }

// --- readOnlyTextField ---

type readOnlyTextField struct {
	label   string
	content string
	visible bool
}

func newReadOnlyTextField(label, content string) *readOnlyTextField {
	return &readOnlyTextField{label: label, content: content, visible: true}
}

func (f *readOnlyTextField) View(focused bool, width int) string {
	labelW := width / 4
	if labelW < 12 {
		labelW = 12
	}
	if labelW > 20 {
		labelW = 20
	}
	label := fmt.Sprintf("%-*s", labelW, f.label+":")
	label = styleFormLabel.Render(label)

	lines := strings.Split(f.content, "\n")
	var result []string
	result = append(result, label+" "+lines[0])
	pad := strings.Repeat(" ", labelW+1)
	for _, line := range lines[1:] {
		result = append(result, pad+line)
	}
	return strings.Join(result, "\n")
}

func (f *readOnlyTextField) Height() int {
	return 1 + strings.Count(f.content, "\n")
}

func (f *readOnlyTextField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) { return f, nil }
func (f *readOnlyTextField) Focus()                                     {}
func (f *readOnlyTextField) Blur()                                      {}
func (f *readOnlyTextField) Value() string                              { return f.content }
func (f *readOnlyTextField) SetValue(v string)                          { f.content = v }
func (f *readOnlyTextField) Validate() error                            { return nil }
func (f *readOnlyTextField) IsDirty() bool                              { return false }
func (f *readOnlyTextField) Visible() bool                              { return f.visible }
func (f *readOnlyTextField) SetVisible(v bool)                          { f.visible = v }
func (f *readOnlyTextField) Focusable() bool                            { return false }
func (f *readOnlyTextField) AtBoundary(int) bool                        { return true }

// --- itemAliasField ---

type itemAliasField struct {
	items      []string
	inputs     []textinput.Model // one per item, but only aliasable items get shown
	aliasable  []bool            // which items accept alias input (certs yes, keys no)
	focusables []int             // indices of aliasable items for focus cycling
	focusPos   int               // position within focusables
	showAlias  bool
	visible    bool
	initial    string
}

func newItemAliasField(items []string, aliases []string, aliasable []bool) *itemAliasField {
	var inputs []textinput.Model
	var focusables []int
	for i := range items {
		ti := textinput.New()
		ti.CharLimit = 128
		ti.Placeholder = "alias"
		if i < len(aliases) {
			ti.SetValue(aliases[i])
		}
		inputs = append(inputs, ti)
		if i < len(aliasable) && aliasable[i] {
			focusables = append(focusables, i)
		}
	}
	f := &itemAliasField{
		items:      items,
		inputs:     inputs,
		aliasable:  aliasable,
		focusables: focusables,
		visible:    true,
	}
	f.initial = f.Value()
	return f
}

func (f *itemAliasField) currentInputIdx() int {
	if len(f.focusables) == 0 || f.focusPos >= len(f.focusables) {
		return -1
	}
	return f.focusables[f.focusPos]
}

func (f *itemAliasField) View(focused bool, width int) string {
	var lines []string
	curIdx := f.currentInputIdx()
	for i, item := range f.items {
		line := "  " + item
		if f.showAlias && i < len(f.aliasable) && f.aliasable[i] {
			isFocusedRow := focused && i == curIdx
			var aliasLabel string
			if isFocusedRow {
				aliasLabel = "  " + styleFormLabelFoc.Render("alias:") + " "
			} else {
				aliasLabel = "  " + styleFormLabel.Render("alias:") + " "
			}
			usedW := len([]rune(item)) + 2 + 10
			inputW := width - usedW
			if inputW < 10 {
				inputW = 10
			}
			f.inputs[i].Width = inputW
			line += aliasLabel + f.inputs[i].View()
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (f *itemAliasField) Height() int { return len(f.items) }

func (f *itemAliasField) Update(msg tea.KeyMsg) (FormField, tea.Cmd) {
	if !f.showAlias || len(f.focusables) == 0 {
		return f, nil
	}
	idx := f.currentInputIdx()
	switch {
	case isKeyDown(msg):
		if f.focusPos < len(f.focusables)-1 {
			if idx >= 0 {
				f.inputs[idx].Blur()
			}
			f.focusPos++
			f.inputs[f.currentInputIdx()].Focus()
		}
		return f, nil
	case isKeyUp(msg):
		if f.focusPos > 0 {
			if idx >= 0 {
				f.inputs[idx].Blur()
			}
			f.focusPos--
			f.inputs[f.currentInputIdx()].Focus()
		}
		return f, nil
	}
	if idx >= 0 {
		var cmd tea.Cmd
		f.inputs[idx], cmd = f.inputs[idx].Update(msg)
		return f, cmd
	}
	return f, nil
}

func (f *itemAliasField) Focus() {
	if f.showAlias {
		idx := f.currentInputIdx()
		if idx >= 0 {
			f.inputs[idx].Focus()
		}
	}
}

func (f *itemAliasField) Blur() {
	for i := range f.inputs {
		f.inputs[i].Blur()
	}
}

func (f *itemAliasField) Value() string {
	var vals []string
	for i, inp := range f.inputs {
		if i < len(f.aliasable) && f.aliasable[i] {
			vals = append(vals, inp.Value())
		} else {
			vals = append(vals, "")
		}
	}
	return strings.Join(vals, "\n")
}

func (f *itemAliasField) SetValue(v string) {
	parts := strings.Split(v, "\n")
	for i := range f.inputs {
		if i < len(parts) {
			f.inputs[i].SetValue(parts[i])
		}
	}
	f.initial = f.Value()
}

func (f *itemAliasField) Validate() error {
	if !f.showAlias {
		return nil
	}
	seen := make(map[string]bool)
	for _, idx := range f.focusables {
		v := strings.TrimSpace(f.inputs[idx].Value())
		if v == "" {
			return fmt.Errorf("alias for item %d is empty", idx+1)
		}
		lower := strings.ToLower(v)
		if seen[lower] {
			return fmt.Errorf("duplicate alias: %s", v)
		}
		seen[lower] = true
	}
	return nil
}

func (f *itemAliasField) IsDirty() bool     { return f.Value() != f.initial }
func (f *itemAliasField) Visible() bool     { return f.visible }
func (f *itemAliasField) SetVisible(v bool) { f.visible = v }
func (f *itemAliasField) Focusable() bool   { return f.showAlias && len(f.focusables) > 0 }
func (f *itemAliasField) AtBoundary(direction int) bool {
	if direction < 0 {
		return f.focusPos == 0
	}
	return f.focusPos == len(f.focusables)-1
}
