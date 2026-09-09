package tui

import (
	"fmt"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildConvertForm(scanPath string, node *TreeNode) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	title := fmt.Sprintf("Convert -- %s", node.Filename)

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	f.setMeta("input_format", string(node.Container.Format))
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER, labelPKCS12, labelPKCS7, labelJKS}, 0))
	f.addField(fieldKeyInclude, newRadioGroupField("Include", []string{"All", labelCertsOnly, labelKeysOnly}, 0))
	pwIdx := f.addField(fieldKeyPassword, newPasswordInputField("Password", "output password", false, nil))
	aliasIdx := f.addField(fieldKeyAlias, newTextInputField("Alias", "entry alias", false, nil))
	legacyIdx := f.addField(fieldKeyLegacy, newCheckboxField("Legacy PKCS#12", false))
	outputField := newFilePickerField("output", "Output", filepicker.TypeSaveFile, scanPath, ".pem", extsPEM)
	outputIdx := f.addField(fieldKeyOutput, outputField)
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Convert"))

	// Callback: update output extensions when format changes
	f.addFieldCallback(formatIdx, func(v string) {
		outputField.SetSaveExtensions(extsForFormat(v))
		outputField.SetAutoExt(autoExtForFormat(v))
	})

	// Sections
	f.addSection("Output", []int{formatIdx, f.fieldIndex(fieldKeyInclude), pwIdx, aliasIdx, legacyIdx, outputIdx, submitIdx})

	// Visibility: password shown for PKCS#12, JKS
	f.addVisibilityRule(pwIdx, formatIdx, func(v string) bool {
		return v == labelPKCS12 || v == labelJKS
	})
	// Visibility: alias shown for JKS
	f.addVisibilityRule(aliasIdx, formatIdx, func(v string) bool {
		return v == labelJKS
	})
	// Visibility: legacy shown for PKCS#12 only
	f.addVisibilityRule(legacyIdx, formatIdx, func(v string) bool {
		return v == labelPKCS12
	})

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func mapOutputFormat(label string) certlib.FileFormat {
	switch label {
	case labelDER:
		return certlib.FormatDER
	case labelPKCS12:
		return certlib.FormatPKCS12
	case labelPKCS7:
		return certlib.FormatPKCS7
	case labelJKS:
		return certlib.FormatJKS
	default:
		return certlib.FormatPEM
	}
}

func buildConvertOptions(form *formModel, cachedPasswords []certlib.TaggedPassword) (certops.ConvertOptions, error) {
	format := form.fieldValue(fieldKeyFormat)
	include := form.fieldValue(fieldKeyInclude)
	password := form.fieldValue(fieldKeyPassword)
	alias := form.fieldValue(fieldKeyAlias)
	legacy := form.fieldValue(fieldKeyLegacy) == "true"
	output := form.fieldValue(fieldKeyOutput)

	var includeFilter string
	switch include {
	case labelCertsOnly:
		includeFilter = "certs"
	case labelKeysOnly:
		includeFilter = "keys"
	default:
		includeFilter = "all"
	}

	return certops.ConvertOptions{
		InputPath:      form.getMeta("input_path"),
		InputPasswords: append(inputPasswordsFromMeta(form), cachedPasswords...),
		OutputPath:     output,
		OutputFormat:   mapOutputFormat(format),
		Include:        includeFilter,
		OutputPassword: nilIfEmpty(password),
		Alias:          alias,
		LegacyPKCS12:   legacy,
	}, nil
}

func submitConvert(form *formModel, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildConvertOptions(form, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.Convert(opts)
		if err != nil {
			return formResult(err, "")
		}
		return formResultWithPasswords(nil, fmt.Sprintf("Converted %d items to %s at %s", result.ItemCount, result.OutputFormat, filepath.Base(result.OutputPath)), opts.OutputPassword)
	}
}
