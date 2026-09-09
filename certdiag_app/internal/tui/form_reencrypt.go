package tui

import (
	"fmt"
	"path/filepath"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func isEntryPasswordMode(node *TreeNode) bool {
	return node.IsChild && node.Item != nil && node.Item.Alias != "" &&
		node.Container != nil &&
		node.Container.Format == certlib.FormatJKS
}

func buildReencryptForm(scanPath string, node *TreeNode) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	entryMode := isEntryPasswordMode(node)

	title := fmt.Sprintf("Change Password -- %s", node.Filename)
	submitLabel := "Change Password"
	if entryMode {
		title = fmt.Sprintf("Change Entry Password -- %s #%d", node.Item.Alias, node.ItemIdx)
		submitLabel = "Change Entry Password"
	}

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}
	if entryMode {
		f.setMeta("entry_alias", node.Item.Alias)
		f.setMeta("entry_index", strconv.Itoa(node.ItemIdx))
		f.setMeta("store_password", string(node.Container.Password))
	}

	// Password section
	removeIdx := f.addField(fieldKeyRemovePassword, newCheckboxField(labelRemovePassword, false))
	pwIdx := f.addField(fieldKeyNewPassword, newPasswordInputField("New Password", "enter new password", true, nil))
	confirmValidator := func(v string) error {
		if v != f.fieldValue(fieldKeyNewPassword) {
			return fmt.Errorf("passwords do not match")
		}
		return nil
	}
	confirmIdx := f.addField(fieldKeyConfirmPassword, newPasswordInputField("Confirm Password", "confirm password", true, confirmValidator))

	// Output section
	modeIdx := f.addField(fieldKeyOutputMode, newRadioGroupField("Output", []string{labelOverwriteOriginal, labelNewFile}, 0))

	ext := filepath.Ext(node.Container.FilePath)
	exts := extsForFileFormat(node.Container.Format)
	outputIdx := f.addField(fieldKeyOutput, newFilePickerField("output", "Output File", filepicker.TypeSaveFile, scanPath, ext, exts))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField(submitLabel))

	// Sections
	f.addSection("Password", []int{removeIdx, pwIdx, confirmIdx})
	f.addSection("Output", []int{modeIdx, outputIdx, submitIdx})

	// Visibility rules: hide password fields when "Remove Password" is checked
	f.addVisibilityRule(pwIdx, removeIdx, func(v string) bool { return v != "true" })
	f.addVisibilityRule(confirmIdx, removeIdx, func(v string) bool { return v != "true" })
	f.addVisibilityRule(outputIdx, modeIdx, func(v string) bool { return v == labelNewFile })

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildReencryptOptions(form *formModel, cachedPasswords []certlib.TaggedPassword) (certops.ReencryptOptions, error) {
	removePassword := form.fieldValue(fieldKeyRemovePassword) == "true"
	newPassword := form.fieldValue(fieldKeyNewPassword)
	outputMode := form.fieldValue(fieldKeyOutputMode)
	output := form.fieldValue(fieldKeyOutput)
	inputPath := form.getMeta("input_path")

	var newPw []byte
	if removePassword {
		newPw = nil
	} else {
		newPw = []byte(newPassword)
	}

	opts := certops.ReencryptOptions{
		InputPath:    inputPath,
		OldPasswords: append(inputPasswordsFromMeta(form), cachedPasswords...),
		NewPassword:  newPw,
	}

	// Entry-level password change for JKS
	if alias := form.getMeta("entry_alias"); alias != "" {
		opts.EntryAlias = alias
		if sp := form.getMeta("store_password"); sp != "" {
			opts.StorePassword = []byte(sp)
		}
	}

	if outputMode == labelOverwriteOriginal {
		opts.OutputPath = inputPath
		opts.Overwrite = true
	} else {
		opts.OutputPath = output
	}

	return opts, nil
}

func submitReencrypt(form *formModel, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildReencryptOptions(form, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		if overwrite {
			opts.Overwrite = true
		}

		result, err := certops.Reencrypt(opts)
		if err != nil {
			return formResult(err, "")
		}

		var msg string
		if opts.EntryAlias != "" {
			msg = fmt.Sprintf("Changed entry password for '%s' in %s", opts.EntryAlias, filepath.Base(result.OutputPath))
		} else {
			msg = fmt.Sprintf("Changed password on %s (%d items)", filepath.Base(result.OutputPath), result.ItemCount)
		}
		return formResultWithPasswords(nil, msg, opts.NewPassword)
	}
}

func buildRemovePassphraseForm(scanPath string, node *TreeNode) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	title := fmt.Sprintf("Remove Passphrase -- %s", node.Filename)

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}

	// Output section
	modeIdx := f.addField(fieldKeyOutputMode, newRadioGroupField("Output", []string{labelOverwriteOriginal, labelNewFile}, 0))

	ext := filepath.Ext(node.Container.FilePath)
	exts := extsForFileFormat(node.Container.Format)
	outputIdx := f.addField(fieldKeyOutput, newFilePickerField("output", "Output File", filepicker.TypeSaveFile, scanPath, ext, exts))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Remove Passphrase"))

	f.addSection("Output", []int{modeIdx, outputIdx, submitIdx})

	f.addVisibilityRule(outputIdx, modeIdx, func(v string) bool { return v == labelNewFile })

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildRemovePassphraseOptions(form *formModel, cachedPasswords []certlib.TaggedPassword) certops.ReencryptOptions {
	outputMode := form.fieldValue(fieldKeyOutputMode)
	output := form.fieldValue(fieldKeyOutput)
	inputPath := form.getMeta("input_path")

	opts := certops.ReencryptOptions{
		InputPath:    inputPath,
		OldPasswords: append(inputPasswordsFromMeta(form), cachedPasswords...),
		NewPassword:  nil,
	}

	if outputMode == labelOverwriteOriginal {
		opts.OutputPath = inputPath
		opts.Overwrite = true
	} else {
		opts.OutputPath = output
	}

	return opts
}

func submitRemovePassphrase(form *formModel, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts := buildRemovePassphraseOptions(form, cachedPasswords)
		if overwrite {
			opts.Overwrite = true
		}

		result, err := certops.Reencrypt(opts)
		if err != nil {
			return formResult(err, "")
		}
		return formResult(nil, fmt.Sprintf("Removed passphrase from %s (%d items)", filepath.Base(result.OutputPath), result.ItemCount))
	}
}
