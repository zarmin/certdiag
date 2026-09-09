package tui

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func makeKeyMsg(key string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

func makeSpecialKeyMsg(t tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: t}
}

func makeTestForm() *formModel {
	f := newFormModel("Test Form")
	f.width = 80
	f.height = 40

	f.addField("name", newTextInputField("Name", "enter name", true, nil))
	f.addField("algo", newRadioGroupField("Algorithm", []string{"RSA", "ECDSA", "Ed25519"}, 0))
	f.addField("ca", newCheckboxField("Is CA", false))
	f.addField("sans", newDynamicListField("SANs", "e.g. example.com"))
	f.addField("output", newFilePickerField("output", "Output", filepicker.TypeSaveFile, "/tmp", ".crt", nil))
	f.addField("submit", newSubmitButtonField("Create"))

	f.initFocus()
	return f
}

func makeAlgoForm() *formModel {
	f := newFormModel("Key Generation")
	f.width = 80
	f.height = 40

	algoIdx := f.addField("algo", newRadioGroupField("Algorithm", []string{"RSA", "ECDSA", "Ed25519"}, 0))
	sizeIdx := f.addField("size", newRadioGroupField("Key Size", []string{"2048", "4096"}, 0))
	curveIdx := f.addField("curve", newRadioGroupField("Curve", []string{"P-256", "P-384"}, 0))
	f.addField("submit", newSubmitButtonField("Generate"))

	f.addVisibilityRule(sizeIdx, algoIdx, func(v string) bool { return v == "RSA" })
	f.addVisibilityRule(curveIdx, algoIdx, func(v string) bool { return v == "ECDSA" })

	f.evaluateVisibility()
	f.initFocus()
	return f
}

func makePasswordForm() *formModel {
	f := newFormModel("Convert")
	f.width = 80
	f.height = 40

	fmtIdx := f.addField("format", newRadioGroupField("Format", []string{"PEM", "DER", "P12"}, 0))
	pwIdx := f.addField("password", newPasswordInputField("Password", "enter password", false, nil))
	f.addField("submit", newSubmitButtonField("Convert"))

	f.addVisibilityRule(pwIdx, fmtIdx, func(v string) bool { return v == "P12" })

	f.evaluateVisibility()
	f.initFocus()
	return f
}

// =============================================================================
// Section 1.1 -- Field Types
// =============================================================================

func TestTextInput_ValueReadWrite(t *testing.T) {
	f := newTextInputField("Name", "", false, nil)
	f.SetValue("test-value")
	if f.Value() != "test-value" {
		t.Errorf("expected 'test-value', got '%s'", f.Value())
	}
	f.SetValue("other")
	if f.Value() != "other" {
		t.Errorf("expected 'other', got '%s'", f.Value())
	}
}

func TestTextInput_Validation(t *testing.T) {
	f := newTextInputField("Name", "", true, nil)
	err := f.Validate()
	if err == nil {
		t.Error("expected error for empty required field")
	}
	f.input.SetValue("hello")
	err = f.Validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRadioGroup_Selection(t *testing.T) {
	f := newRadioGroupField("Algo", []string{"RSA", "ECDSA", "Ed25519"}, 0)
	if f.Value() != "RSA" {
		t.Errorf("expected 'RSA', got '%s'", f.Value())
	}
	f.Update(makeSpecialKeyMsg(tea.KeyRight))
	if f.Value() != "ECDSA" {
		t.Errorf("expected 'ECDSA' after right, got '%s'", f.Value())
	}
}

func TestRadioGroup_CycleWrap(t *testing.T) {
	f := newRadioGroupField("Algo", []string{"RSA", "ECDSA", "Ed25519"}, 2)
	if f.Value() != "Ed25519" {
		t.Errorf("expected 'Ed25519', got '%s'", f.Value())
	}
	f.Update(makeSpecialKeyMsg(tea.KeyRight))
	if f.Value() != "RSA" {
		t.Errorf("expected 'RSA' after wrap right, got '%s'", f.Value())
	}
	f.Update(makeSpecialKeyMsg(tea.KeyLeft))
	if f.Value() != "Ed25519" {
		t.Errorf("expected 'Ed25519' after wrap left, got '%s'", f.Value())
	}
}

func TestCheckbox_Toggle(t *testing.T) {
	f := newCheckboxField("CA", false)
	if f.Value() != "false" {
		t.Errorf("expected 'false', got '%s'", f.Value())
	}
	f.Update(makeKeyMsg(" "))
	if f.Value() != "true" {
		t.Errorf("expected 'true' after toggle, got '%s'", f.Value())
	}
	f.Update(makeKeyMsg(" "))
	if f.Value() != "false" {
		t.Errorf("expected 'false' after second toggle, got '%s'", f.Value())
	}
}

func TestDynamicList_AddRemove(t *testing.T) {
	f := newDynamicListField("SANs", "domain")
	f.Focus()
	f.inputs[0].SetValue("example.com")

	// Add row via Enter
	f.Update(makeSpecialKeyMsg(tea.KeyEnter))
	if len(f.inputs) != 2 {
		t.Fatalf("expected 2 inputs after add, got %d", len(f.inputs))
	}
	if f.focusIdx != 1 {
		t.Errorf("expected focus on new row (1), got %d", f.focusIdx)
	}

	// Remove empty row via Backspace
	f.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if len(f.inputs) != 1 {
		t.Fatalf("expected 1 input after remove, got %d", len(f.inputs))
	}
}

func TestDynamicList_EmptyIgnored(t *testing.T) {
	f := newDynamicListField("SANs", "domain")
	f.Focus()
	f.inputs[0].SetValue("example.com")

	// Add empty row
	f.Update(makeSpecialKeyMsg(tea.KeyEnter))
	// Leave it empty

	val := f.Value()
	if val != "example.com" {
		t.Errorf("expected 'example.com' (empty rows filtered), got '%s'", val)
	}
}

func TestMultiCheck_DefaultValue(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "digitalSignature,keyEncipherment")
	val := f.Value()
	if val != "digitalSignature,keyEncipherment" {
		t.Errorf("expected 'digitalSignature,keyEncipherment', got '%s'", val)
	}
}

func TestMultiCheck_EmptyDefault(t *testing.T) {
	f := newMultiCheckField("EKU", ekuOptions, "")
	if f.Value() != "" {
		t.Errorf("expected empty value, got '%s'", f.Value())
	}
}

func TestMultiCheck_SpaceToggles(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "")
	// Cursor starts at 0 (digitalSignature), toggle it on
	f.Update(makeKeyMsg(" "))
	if f.Value() != "digitalSignature" {
		t.Errorf("expected 'digitalSignature' after toggle, got '%s'", f.Value())
	}
	// Toggle it off
	f.Update(makeKeyMsg(" "))
	if f.Value() != "" {
		t.Errorf("expected empty after second toggle, got '%s'", f.Value())
	}
}

func TestMultiCheck_Navigation(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "")
	// Move right then toggle
	f.Update(makeSpecialKeyMsg(tea.KeyRight))
	f.Update(makeKeyMsg(" "))
	if f.Value() != "contentCommitment" {
		t.Errorf("expected 'contentCommitment', got '%s'", f.Value())
	}
	// Move left back to first, toggle
	f.Update(makeSpecialKeyMsg(tea.KeyLeft))
	f.Update(makeKeyMsg(" "))
	if f.Value() != "digitalSignature,contentCommitment" {
		t.Errorf("expected 'digitalSignature,contentCommitment', got '%s'", f.Value())
	}
}

func TestMultiCheck_CycleWrap(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "")
	// Move left from 0 should wrap to last
	f.Update(makeSpecialKeyMsg(tea.KeyLeft))
	f.Update(makeKeyMsg(" "))
	if f.Value() != "decipherOnly" {
		t.Errorf("expected 'decipherOnly' after wrap left, got '%s'", f.Value())
	}
}

func TestMultiCheck_SetValue(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "digitalSignature")
	f.SetValue("certSign,crlSign")
	if f.Value() != "certSign,crlSign" {
		t.Errorf("expected 'certSign,crlSign', got '%s'", f.Value())
	}
}

func TestMultiCheck_SetValueEmpty(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "digitalSignature")
	f.SetValue("")
	if f.Value() != "" {
		t.Errorf("expected empty after SetValue(''), got '%s'", f.Value())
	}
}

func TestMultiCheck_MultipleSelections(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "digitalSignature,keyEncipherment,certSign")
	val := f.Value()
	if val != "digitalSignature,keyEncipherment,certSign" {
		t.Errorf("expected 3 values, got '%s'", val)
	}
}

func TestMultiCheck_DirtyTracking(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "digitalSignature")
	if f.IsDirty() {
		t.Error("new field should not be dirty")
	}
	f.Update(makeKeyMsg(" ")) // toggle off digitalSignature
	if !f.IsDirty() {
		t.Error("field should be dirty after toggle")
	}
}

func TestMultiCheck_AtBoundary(t *testing.T) {
	f := newMultiCheckField("KU", kuOptions, "")
	if !f.AtBoundary(-1) {
		t.Error("multiCheckField should always be at boundary (top)")
	}
	if !f.AtBoundary(1) {
		t.Error("multiCheckField should always be at boundary (bottom)")
	}
}

func TestMultiCheck_View(t *testing.T) {
	initTestStyles()
	f := newMultiCheckField("KU", kuOptions, "digitalSignature")
	view := f.View(false, 80)
	if view == "" {
		t.Error("expected non-empty view")
	}
}

// =============================================================================
// Section 1.2 -- Focus Management
// =============================================================================

func TestForm_TabCycleForward(t *testing.T) {
	f := makeTestForm()
	initial := f.focusIdx

	// Tab through all fields
	visited := []int{initial}
	for i := 0; i < len(f.fields)-1; i++ {
		f.update(tea.KeyMsg{Type: tea.KeyTab})
		visited = append(visited, f.focusIdx)
	}

	// Should have visited all fields
	if len(visited) != len(f.fields) {
		t.Errorf("expected to visit %d fields, visited %d", len(f.fields), len(visited))
	}

	// All visited should be unique (before wrap)
	seen := map[int]bool{}
	for _, v := range visited {
		if seen[v] {
			t.Errorf("visited field %d twice", v)
		}
		seen[v] = true
	}
}

func TestForm_ShiftTabCycleBackward(t *testing.T) {
	f := makeTestForm()
	// Move to last field
	for i := 0; i < len(f.fields)-1; i++ {
		f.update(tea.KeyMsg{Type: tea.KeyTab})
	}
	lastIdx := f.focusIdx

	// Shift+Tab back
	f.update(tea.KeyMsg{Type: tea.KeyShiftTab})
	if f.focusIdx >= lastIdx {
		t.Errorf("expected focus to move backward from %d, got %d", lastIdx, f.focusIdx)
	}
}

func TestForm_SubmitIsLast(t *testing.T) {
	f := makeTestForm()
	// Tab to the end
	for i := 0; i < len(f.fields); i++ {
		f.update(tea.KeyMsg{Type: tea.KeyTab})
	}
	// After full cycle, should be back at start; so go to last
	for i := 0; i < len(f.fields)-1; i++ {
		f.update(tea.KeyMsg{Type: tea.KeyTab})
	}

	_, isSubmit := f.fields[f.focusIdx].(*submitButtonField)
	if !isSubmit {
		t.Errorf("expected submit button as last focusable, got field at idx %d", f.focusIdx)
	}
}

func TestForm_SkipHiddenFields(t *testing.T) {
	f := makeTestForm()
	// Hide the radio group (idx 1)
	f.fields[1].SetVisible(false)

	f.setFocus(0)
	f.update(tea.KeyMsg{Type: tea.KeyTab})

	if f.focusIdx == 1 {
		t.Error("focus should skip hidden field at idx 1")
	}
}

func TestForm_InitialFocus(t *testing.T) {
	f := makeTestForm()
	if f.focusIdx != 0 {
		t.Errorf("expected initial focus at 0, got %d", f.focusIdx)
	}
}

// =============================================================================
// Section 1.3 -- Visibility
// =============================================================================

func TestForm_DynamicVisibility(t *testing.T) {
	f := makeAlgoForm()
	sizeField := f.fieldByName("size")
	curveField := f.fieldByName("curve")

	// Default is RSA: size visible, curve hidden
	if !sizeField.Visible() {
		t.Error("size should be visible for RSA")
	}
	if curveField.Visible() {
		t.Error("curve should be hidden for RSA")
	}
}

func TestForm_RSAShowsSize(t *testing.T) {
	f := makeAlgoForm()
	f.fieldByName("algo").SetValue("RSA")
	f.evaluateVisibility()

	if !f.fieldByName("size").Visible() {
		t.Error("size should be visible for RSA")
	}
	if f.fieldByName("curve").Visible() {
		t.Error("curve should be hidden for RSA")
	}
}

func TestForm_ECDSAShowsCurve(t *testing.T) {
	f := makeAlgoForm()
	algoField := f.fieldByName("algo").(*radioGroupField)
	algoField.selected = 1 // ECDSA
	f.evaluateVisibility()

	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden for ECDSA")
	}
	if !f.fieldByName("curve").Visible() {
		t.Error("curve should be visible for ECDSA")
	}
}

func TestForm_Ed25519HidesBoth(t *testing.T) {
	f := makeAlgoForm()
	algoField := f.fieldByName("algo").(*radioGroupField)
	algoField.selected = 2 // Ed25519
	f.evaluateVisibility()

	if f.fieldByName("size").Visible() {
		t.Error("size should be hidden for Ed25519")
	}
	if f.fieldByName("curve").Visible() {
		t.Error("curve should be hidden for Ed25519")
	}
}

func TestForm_PasswordFieldVisibility(t *testing.T) {
	f := makePasswordForm()

	// Default is PEM: password hidden
	if f.fieldByName("password").Visible() {
		t.Error("password should be hidden for PEM format")
	}

	// Switch to P12: password visible
	fmtField := f.fieldByName("format").(*radioGroupField)
	fmtField.selected = 2 // P12
	f.evaluateVisibility()

	if !f.fieldByName("password").Visible() {
		t.Error("password should be visible for P12 format")
	}
}

// =============================================================================
// Section 1.4 -- Validation
// =============================================================================

func TestForm_RequiredFieldsBlock(t *testing.T) {
	f := makeTestForm()
	// Name field is required, leave it empty
	ok := f.validateAll()
	if ok {
		t.Error("validateAll should fail with empty required field")
	}
	if _, hasErr := f.errors[0]; !hasErr {
		t.Error("expected error on field 0 (Name)")
	}
}

func TestForm_ValidationErrors(t *testing.T) {
	validator := func(v string) error {
		if len(v) < 3 {
			return fmt.Errorf("must be at least 3 characters")
		}
		return nil
	}
	f := newFormModel("Test")
	f.width = 80
	f.height = 40
	f.addField("short", newTextInputField("Short", "", false, validator))
	f.addField("submit", newSubmitButtonField("Go"))
	f.initFocus()

	f.fields[0].(*textInputField).input.SetValue("ab")
	f.validateField(0)

	if _, hasErr := f.errors[0]; !hasErr {
		t.Error("expected validation error for short input")
	}
}

func TestForm_ValidSubmit(t *testing.T) {
	f := makeTestForm()
	f.fields[0].(*textInputField).input.SetValue("my-cert")
	f.fieldByName("output").SetValue("/tmp/my-cert.crt")
	ok := f.validateAll()
	if !ok {
		t.Errorf("validateAll should pass, got errors: %v", f.errors)
	}
}

func TestForm_PasswordMismatch(t *testing.T) {
	f := newFormModel("Test")
	f.width = 80
	f.height = 40

	f.addField("password", newPasswordInputField("Password", "", true, nil))

	confirmValidator := func(v string) error {
		pw := f.fieldValue("password")
		if v != pw {
			return fmt.Errorf("passwords do not match")
		}
		return nil
	}
	f.addField("confirm", newPasswordInputField("Confirm", "", true, confirmValidator))
	f.addField("submit", newSubmitButtonField("Go"))
	f.initFocus()

	f.fields[0].(*textInputField).input.SetValue("secret123")
	f.fields[1].(*textInputField).input.SetValue("different")

	ok := f.validateAll()
	if ok {
		t.Error("validateAll should fail on password mismatch")
	}
	if _, hasErr := f.errors[1]; !hasErr {
		t.Error("expected error on confirm field")
	}
}

func TestForm_ValidityRange(t *testing.T) {
	cases := []struct {
		name  string
		value string
		valid bool
	}{
		{"zero", "0", false},
		{"negative", "-5", false},
		{"positive", "365", true},
		{"large", "3650", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator := func(v string) error {
				if v == "" {
					return nil
				}
				var n int
				_, err := fmt.Sscanf(v, "%d", &n)
				if err != nil || n <= 0 {
					return fmt.Errorf("must be a positive number")
				}
				return nil
			}
			field := newTextInputField("Days", "", false, validator)
			field.input.SetValue(tc.value)
			err := field.Validate()
			if tc.valid && err != nil {
				t.Errorf("expected valid for %s, got error: %v", tc.value, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected error for %s, got nil", tc.value)
			}
		})
	}
}

// =============================================================================
// Section 1.5 -- Dirty Tracking
// =============================================================================

func TestForm_CleanInitially(t *testing.T) {
	f := makeTestForm()
	if f.isDirty() {
		t.Error("new form should not be dirty")
	}
}

func TestForm_DirtyAfterEdit(t *testing.T) {
	f := makeTestForm()
	f.fields[0].(*textInputField).input.SetValue("changed")
	if !f.isDirty() {
		t.Error("form should be dirty after edit")
	}
}

func TestForm_CleanAfterReset(t *testing.T) {
	f := makeTestForm()
	f.fields[0].(*textInputField).input.SetValue("changed")
	if !f.isDirty() {
		t.Fatal("precondition: form should be dirty")
	}
	f.resetDirty()
	if f.isDirty() {
		t.Error("form should be clean after resetDirty")
	}
}
