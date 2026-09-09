package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

var (
	styleFormLabel     lipgloss.Style
	styleFormLabelFoc  lipgloss.Style
	styleFormSection   lipgloss.Style
	styleFormError     lipgloss.Style
	styleFormButton    lipgloss.Style
	styleFormButtonFoc lipgloss.Style
	styleFormHint      lipgloss.Style
	styleFormHelp      lipgloss.Style
)

func initFormStyles() {
	if noColor {
		styleFormLabel = lipgloss.NewStyle().Bold(true)
		styleFormLabelFoc = lipgloss.NewStyle().Bold(true).Reverse(true)
		styleFormSection = lipgloss.NewStyle().Bold(true)
		styleFormError = lipgloss.NewStyle().Bold(true)
		styleFormButton = lipgloss.NewStyle()
		styleFormButtonFoc = lipgloss.NewStyle().Reverse(true)
		styleFormHint = lipgloss.NewStyle().Faint(true)
		styleFormHelp = lipgloss.NewStyle().Faint(true).Italic(true)
	} else {
		styleFormLabel = lipgloss.NewStyle().Bold(true).Foreground(colorLightGrey)
		styleFormLabelFoc = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
		styleFormSection = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
		styleFormError = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
		styleFormButton = lipgloss.NewStyle().Foreground(colorLightGrey)
		styleFormButtonFoc = lipgloss.NewStyle().Bold(true).Foreground(colorAccent)
		styleFormHint = lipgloss.NewStyle().Faint(true).Foreground(colorDimGrey)
		styleFormHelp = lipgloss.NewStyle().Faint(true).Italic(true).Foreground(colorDimGrey)
	}
}

type formSection struct {
	title  string
	fields []int
}

type visibilityRule struct {
	targetIdx int
	dependsOn int
	showWhen  func(string) bool
}

type valueRule struct {
	targetIdx int
	dependsOn int
	valueFn   func(string) string
	lastDep   string
}

type fieldCallback struct {
	dependsOn int
	fn        func(depValue string)
}

type formModel struct {
	title       string
	sections    []formSection
	fields      []FormField
	fieldNames  []string
	focusIdx    int
	scrollOff   int
	dirty       bool
	errors      map[int]string
	width       int
	height      int
	visRules    []visibilityRule
	valRules    []valueRule
	callbacks   []fieldCallback
	submitted   bool
	metadata        map[string]string
	helpShown       map[int]bool
	bundleItems     []certlib.CertItem // selected items to bundle (bundle form only)
	opensslEligible bool               // form maps to an openssl equivalent ('o' shortcut)
}

func newFormModel(title string) *formModel {
	initFormStyles()
	return &formModel{
		title:     title,
		errors:    make(map[int]string),
		metadata:  make(map[string]string),
		helpShown: make(map[int]bool),
	}
}

func (f *formModel) setMeta(key, value string) { f.metadata[key] = value }
func (f *formModel) getMeta(key string) string { return f.metadata[key] }

func (f *formModel) addField(name string, field FormField) int {
	idx := len(f.fields)
	f.fields = append(f.fields, field)
	f.fieldNames = append(f.fieldNames, name)
	return idx
}

func (f *formModel) addSection(title string, fieldIndices []int) {
	f.sections = append(f.sections, formSection{title: title, fields: fieldIndices})
}

func (f *formModel) addVisibilityRule(targetIdx, dependsOn int, showWhen func(string) bool) {
	f.visRules = append(f.visRules, visibilityRule{
		targetIdx: targetIdx,
		dependsOn: dependsOn,
		showWhen:  showWhen,
	})
}

func (f *formModel) addValueRule(targetIdx, dependsOn int, valueFn func(string) string) {
	lastDep := ""
	if dependsOn >= 0 && dependsOn < len(f.fields) {
		lastDep = f.fields[dependsOn].Value()
	}
	f.valRules = append(f.valRules, valueRule{
		targetIdx: targetIdx,
		dependsOn: dependsOn,
		valueFn:   valueFn,
		lastDep:   lastDep,
	})
}

func (f *formModel) syncValueRuleDeps() {
	for i := range f.valRules {
		rule := &f.valRules[i]
		if rule.dependsOn < 0 || rule.dependsOn >= len(f.fields) {
			continue
		}
		rule.lastDep = f.fields[rule.dependsOn].Value()
	}
}

func (f *formModel) addFieldCallback(dependsOn int, fn func(string)) {
	f.callbacks = append(f.callbacks, fieldCallback{dependsOn: dependsOn, fn: fn})
}

// focusedFieldIsTextInput reports whether the focused field consumes free-text
// keystrokes, so callers can tell whether a plain letter like 'o' is being
// typed into a field or is free to act as a shortcut.
func (f *formModel) focusedFieldIsTextInput() bool {
	if f.focusIdx < 0 || f.focusIdx >= len(f.fields) {
		return false
	}
	switch f.fields[f.focusIdx].(type) {
	case *textInputField, *dynamicListField, *itemAliasField:
		return true
	}
	return false
}

func (f *formModel) fieldByName(name string) FormField {
	for i, n := range f.fieldNames {
		if n == name {
			return f.fields[i]
		}
	}
	return nil
}

func (f *formModel) fieldValue(name string) string {
	field := f.fieldByName(name)
	if field != nil {
		return field.Value()
	}
	return ""
}

func (f *formModel) effectiveValue(name string) string {
	idx := f.fieldIndex(name)
	if idx < 0 || !f.fields[idx].Visible() {
		return ""
	}
	return f.fields[idx].Value()
}

func (f *formModel) fieldIndex(name string) int {
	for i, n := range f.fieldNames {
		if n == name {
			return i
		}
	}
	return -1
}

// --- Focus cycling ---

func (f *formModel) nextFocusable() int {
	if len(f.fields) == 0 {
		return -1
	}
	start := f.focusIdx + 1
	for i := 0; i < len(f.fields); i++ {
		idx := (start + i) % len(f.fields)
		if f.fields[idx].Visible() && f.fields[idx].Focusable() {
			return idx
		}
	}
	return f.focusIdx
}

func (f *formModel) prevFocusable() int {
	if len(f.fields) == 0 {
		return -1
	}
	start := f.focusIdx - 1
	for i := 0; i < len(f.fields); i++ {
		idx := (start - i + len(f.fields)) % len(f.fields)
		if f.fields[idx].Visible() && f.fields[idx].Focusable() {
			return idx
		}
	}
	return f.focusIdx
}

func (f *formModel) setFocus(idx int) {
	if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
		f.fields[f.focusIdx].Blur()
		f.validateField(f.focusIdx)
	}
	f.focusIdx = idx
	if idx >= 0 && idx < len(f.fields) {
		f.fields[idx].Focus()
	}
	f.evaluateVisibility()
	f.ensureFieldVisible(idx)
}

func (f *formModel) initFocus() {
	for i, field := range f.fields {
		if field.Visible() && field.Focusable() {
			f.focusIdx = i
			field.Focus()
			return
		}
	}
}

// --- Visibility ---

func (f *formModel) evaluateVisibility() {
	seen := make(map[int]bool)
	for _, rule := range f.visRules {
		if rule.dependsOn < 0 || rule.dependsOn >= len(f.fields) {
			continue
		}
		depVal := f.fields[rule.dependsOn].Value()
		shouldShow := rule.showWhen(depVal) && f.fields[rule.dependsOn].Visible()
		if seen[rule.targetIdx] {
			shouldShow = shouldShow || f.fields[rule.targetIdx].Visible()
		}
		seen[rule.targetIdx] = true
		f.fields[rule.targetIdx].SetVisible(shouldShow)
	}

	for i := range f.valRules {
		rule := &f.valRules[i]
		if rule.dependsOn < 0 || rule.dependsOn >= len(f.fields) {
			continue
		}
		depVal := f.fields[rule.dependsOn].Value()
		if depVal != rule.lastDep {
			rule.lastDep = depVal
			f.fields[rule.targetIdx].SetValue(rule.valueFn(depVal))
		}
	}

	for _, cb := range f.callbacks {
		if cb.dependsOn < 0 || cb.dependsOn >= len(f.fields) {
			continue
		}
		cb.fn(f.fields[cb.dependsOn].Value())
	}

	// If focused field became hidden, advance
	if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
		if !f.fields[f.focusIdx].Visible() || !f.fields[f.focusIdx].Focusable() {
			next := f.nextFocusable()
			if next != f.focusIdx {
				f.fields[f.focusIdx].Blur()
				f.focusIdx = next
				f.fields[f.focusIdx].Focus()
			}
		}
	}
}

// --- Validation ---

func (f *formModel) validateField(idx int) {
	if idx < 0 || idx >= len(f.fields) {
		return
	}
	field := f.fields[idx]
	if !field.Visible() {
		delete(f.errors, idx)
		return
	}
	err := field.Validate()
	if err != nil {
		f.errors[idx] = err.Error()
	} else {
		delete(f.errors, idx)
	}
}

func (f *formModel) validateAll() bool {
	f.errors = make(map[int]string)
	for i, field := range f.fields {
		if !field.Visible() {
			continue
		}
		err := field.Validate()
		if err != nil {
			f.errors[i] = err.Error()
		}
	}
	if len(f.errors) > 0 {
		// Focus first error
		for i := range f.fields {
			if _, ok := f.errors[i]; ok {
				f.setFocus(i)
				break
			}
		}
		return false
	}
	return true
}

// --- Dirty tracking ---

func (f *formModel) isDirty() bool {
	for _, field := range f.fields {
		if field.Visible() && field.IsDirty() {
			return true
		}
	}
	return false
}

func (f *formModel) resetDirty() {
	for _, field := range f.fields {
		field.SetValue(field.Value())
	}
}

// --- Scrolling ---

func (f *formModel) contentHeight() int {
	h := 0
	sectionFields := f.sectionFieldSet()

	for si, sec := range f.sections {
		hasVisible := false
		for _, fi := range sec.fields {
			if f.fields[fi].Visible() {
				hasVisible = true
				break
			}
		}
		if !hasVisible {
			continue
		}
		if si > 0 {
			h++ // blank line before section
		}
		h++ // section title
		for _, fi := range sec.fields {
			if f.fields[fi].Visible() {
				h += f.fields[fi].Height()
				if errMsg, ok := f.errors[fi]; ok && errMsg != "" {
					h++
				}
				h += len(f.inlineHelpLines(fi))
			}
		}
	}

	// Fields not in any section
	for i, field := range f.fields {
		if !field.Visible() || sectionFields[i] {
			continue
		}
		h += field.Height()
		if errMsg, ok := f.errors[i]; ok && errMsg != "" {
			h++
		}
		h += len(f.inlineHelpLines(i))
	}

	return h
}

func (f *formModel) sectionFieldSet() map[int]bool {
	set := make(map[int]bool)
	for _, sec := range f.sections {
		for _, fi := range sec.fields {
			set[fi] = true
		}
	}
	return set
}

func (f *formModel) footerHeight() int {
	_, h := f.footerHints()
	return h
}

func (f *formModel) visibleLines() int {
	lines := f.height - 2 - f.footerHeight() // title + blank + footer
	if lines < 1 {
		lines = 1
	}
	return lines
}

func (f *formModel) fieldYPositions() []int {
	positions := make([]int, len(f.fields))
	y := 0
	sectionFields := f.sectionFieldSet()

	for si, sec := range f.sections {
		hasVisible := false
		for _, fi := range sec.fields {
			if f.fields[fi].Visible() {
				hasVisible = true
				break
			}
		}
		if !hasVisible {
			continue
		}
		if si > 0 {
			y++
		}
		y++ // section title
		for _, fi := range sec.fields {
			positions[fi] = y
			if f.fields[fi].Visible() {
				y += f.fields[fi].Height()
				if errMsg, ok := f.errors[fi]; ok && errMsg != "" {
					y++
				}
				y += len(f.inlineHelpLines(fi))
			}
		}
	}

	for i, field := range f.fields {
		if sectionFields[i] {
			continue
		}
		positions[i] = y
		if field.Visible() {
			y += field.Height()
			if errMsg, ok := f.errors[i]; ok && errMsg != "" {
				y++
			}
			y += len(f.inlineHelpLines(i))
		}
	}

	return positions
}

func (f *formModel) ensureFieldVisible(idx int) {
	if idx < 0 || idx >= len(f.fields) {
		return
	}
	positions := f.fieldYPositions()
	fieldY := positions[idx]
	fieldH := f.fields[idx].Height()
	visLines := f.visibleLines()

	if fieldY < f.scrollOff {
		f.scrollOff = fieldY
	}
	if fieldY+fieldH > f.scrollOff+visLines {
		f.scrollOff = fieldY + fieldH - visLines
	}
	if f.scrollOff < 0 {
		f.scrollOff = 0
	}
}

// --- Update ---

func (f *formModel) update(msg tea.KeyMsg) (bool, tea.Cmd) {
	switch {
	case isKeyFastSubmit(msg):
		// Submitting from any field. validateAll focuses the first offending
		// field, so a refused submit says where to look rather than just
		// refusing.
		if f.validateAll() {
			f.submitted = true
			return true, nil
		}
		return false, nil
	case msg.String() == "f1":
		name := f.fieldNames[f.focusIdx]
		if _, ok := fieldHelpMap[name]; ok {
			f.helpShown[f.focusIdx] = !f.helpShown[f.focusIdx]
			f.ensureFieldVisible(f.focusIdx)
		}
		return false, nil
	case msg.String() == "tab":
		next := f.nextFocusable()
		f.setFocus(next)
		return false, nil
	case msg.String() == "shift+tab":
		prev := f.prevFocusable()
		f.setFocus(prev)
		return false, nil
	case isKeyUp(msg):
		if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
			if f.fields[f.focusIdx].AtBoundary(-1) {
				f.setFocus(f.prevFocusable())
				return false, nil
			}
		}
	case isKeyDown(msg):
		if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
			if f.fields[f.focusIdx].AtBoundary(1) {
				f.setFocus(f.nextFocusable())
				return false, nil
			}
		}
	case isKeyEnter(msg):
		if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
			if _, ok := f.fields[f.focusIdx].(*submitButtonField); ok {
				if f.validateAll() {
					f.submitted = true
					return true, nil
				}
				return false, nil
			}
		}
	}

	if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
		var cmd tea.Cmd
		f.fields[f.focusIdx], cmd = f.fields[f.focusIdx].Update(msg)
		f.evaluateVisibility()
		return false, cmd
	}
	return false, nil
}

// --- View ---

func (f *formModel) view() string {
	var sb strings.Builder

	sb.WriteString(styleFormSection.Render(f.title))
	sb.WriteString("\n\n")

	lines := f.renderContent()

	visLines := f.visibleLines()
	end := f.scrollOff + visLines
	if end > len(lines) {
		end = len(lines)
	}
	start := f.scrollOff
	if start > end {
		start = end
	}

	for i := start; i < end; i++ {
		sb.WriteString(lines[i])
		sb.WriteString("\n")
	}

	// Pad remaining
	for i := end - start; i < visLines; i++ {
		sb.WriteString("\n")
	}

	// Footer
	footer, _ := f.footerHints()
	sb.WriteString(footer)

	return sb.String()
}

func (f *formModel) renderContent() []string {
	var lines []string
	sectionFields := f.sectionFieldSet()

	for si, sec := range f.sections {
		hasVisible := false
		for _, fi := range sec.fields {
			if f.fields[fi].Visible() {
				hasVisible = true
				break
			}
		}
		if !hasVisible {
			continue
		}
		if si > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, styleFormSection.Render(sec.title))
		for _, fi := range sec.fields {
			if !f.fields[fi].Visible() {
				continue
			}
			fieldView := f.fields[fi].View(fi == f.focusIdx, f.width)
			fieldLines := strings.Split(fieldView, "\n")
			lines = append(lines, fieldLines...)
			if errMsg, ok := f.errors[fi]; ok && errMsg != "" {
				lines = append(lines, "  "+styleFormError.Render(errMsg))
			}
			lines = append(lines, f.inlineHelpLines(fi)...)
		}
	}

	for i, field := range f.fields {
		if !field.Visible() || sectionFields[i] {
			continue
		}
		fieldView := field.View(i == f.focusIdx, f.width)
		fieldLines := strings.Split(fieldView, "\n")
		lines = append(lines, fieldLines...)
		if errMsg, ok := f.errors[i]; ok && errMsg != "" {
			lines = append(lines, "  "+styleFormError.Render(errMsg))
		}
		lines = append(lines, f.inlineHelpLines(i)...)
	}

	return lines
}

func (f *formModel) inlineHelpLines(idx int) []string {
	if !f.helpShown[idx] {
		return nil
	}
	name := f.fieldNames[idx]
	help, ok := fieldHelpMap[name]
	if !ok {
		return nil
	}
	wrapWidth := f.width - 4
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	var result []string
	for _, paragraph := range strings.Split(help.Body, "\n") {
		for _, line := range wrapText(paragraph, wrapWidth) {
			result = append(result, "  "+styleFormHelp.Render(line))
		}
	}
	return result
}

func (f *formModel) footerHints() (string, int) {
	hints := []Hint{{"Tab/Down", "Next"}, {"Shift+Tab/Up", "Prev"}}
	if f.focusIdx >= 0 && f.focusIdx < len(f.fields) {
		switch f.fields[f.focusIdx].(type) {
		case *submitButtonField:
			hints = append(hints, Hint{"Enter", "Submit"})
		case *multiCheckField:
			hints = append(hints, Hint{"Space", "Toggle"})
		}
	}
	if f.focusIdx >= 0 && f.focusIdx < len(f.fieldNames) {
		if _, ok := fieldHelpMap[f.fieldNames[f.focusIdx]]; ok {
			hints = append(hints, Hint{"F1", "Help"})
		}
	}
	if f.opensslEligible && !f.focusedFieldIsTextInput() {
		hints = append(hints, Hint{"o", "OpenSSL"})
	}
	hints = append(hints, Hint{"F2/Alt+Enter", "Submit"}, Hint{"Esc", "Cancel"})

	var status []StatusHint
	errCount := len(f.errors)
	if errCount > 0 {
		status = append(status, StatusHint{fmt.Sprintf("%d error(s)", errCount)})
	}

	return RenderHintBar(f.width, hints, status...)
}
