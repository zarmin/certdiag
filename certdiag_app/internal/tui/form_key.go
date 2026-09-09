package tui

import (
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildCreateKeyForm(scanPath string, keyDefaults certlib.KeyGenOptions) *formModel {
	f := newFormModel("Create Key")

	// Key Parameters section
	sizes := keySizeOptions
	algoIdx := f.addField(fieldKeyAlgo, newRadioGroupField("Algorithm", algoOptions, radioIndex(algoOptions, keyDefaults.Algorithm)))
	sizeIdx := f.addField(fieldKeySize, newRadioGroupField("Key Size", sizes, sizeRadioIndex(sizes, keyDefaults.KeySize)))
	curveIdx := f.addField(fieldKeyCurve, newRadioGroupField("Curve", curveOptions, curveRadioIndex(curveOptions, keyDefaults.Curve)))

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	encryptIdx := f.addField(fieldKeyEncrypt, newCheckboxField("Encrypt", false))
	passwordIdx := f.addField(fieldKeyPassword, newPasswordInputField("Password", "enter password", true, nil))
	f.addField(fieldKeyOutput, newFilePickerField("output", "Output", filepicker.TypeSaveFile, scanPath, ".key", extsKeyOutput))
	f.addField(fieldKeySubmit, newSubmitButtonField("Generate"))

	// Sections
	f.addSection("Key Parameters", []int{algoIdx, sizeIdx, curveIdx})
	f.addSection("Output", []int{formatIdx, encryptIdx, passwordIdx, f.fieldIndex(fieldKeyOutput), f.fieldIndex(fieldKeySubmit)})

	// Visibility: size visible only when RSA
	f.addVisibilityRule(sizeIdx, algoIdx, func(v string) bool { return v == labelRSA })
	// Visibility: curve visible only when ECDSA
	f.addVisibilityRule(curveIdx, algoIdx, func(v string) bool { return v == labelECDSA })
	// Visibility: encrypt visible only when PEM
	f.addVisibilityRule(encryptIdx, formatIdx, func(v string) bool { return v == labelPEM })
	// Visibility: password visible only when encrypt is checked
	f.addVisibilityRule(passwordIdx, encryptIdx, func(v string) bool { return v == "true" })

	// Initial visibility
	f.evaluateVisibility()
	f.initFocus()

	return f
}

// buildKeyGenOptions maps form algo/size/curve values to certlib.KeyGenOptions.
// Shared by key, cert, and CSR forms.
func buildKeyGenOptions(algo, size, curve string) certlib.KeyGenOptions {
	opts := certlib.KeyGenOptions{
		Algorithm: algoInternal(algo),
	}
	switch algo {
	case labelRSA:
		keySize, err := strconv.Atoi(size)
		if err != nil {
			keySize = 2048
		}
		opts.KeySize = keySize
	case labelECDSA:
		opts.Curve = curveInternal(curve)
	}
	return opts
}

func buildCreateKeyOptions(form *formModel) (certops.GenerateKeyOptions, error) {
	algo := form.fieldValue(fieldKeyAlgo)
	size := form.fieldValue(fieldKeySize)
	curve := form.fieldValue(fieldKeyCurve)
	format := form.fieldValue(fieldKeyFormat)
	encrypt := form.effectiveValue(fieldKeyEncrypt) == "true"
	password := form.effectiveValue(fieldKeyPassword)
	output := form.fieldValue(fieldKeyOutput)

	opts := certops.GenerateKeyOptions{
		Algorithm:  algoInternal(algo),
		OutputPath: output,
	}

	switch algo {
	case labelRSA:
		keySize, err := strconv.Atoi(size)
		if err != nil {
			keySize = 2048
		}
		opts.KeySize = keySize
	case labelECDSA:
		opts.Curve = curveInternal(curve)
	}

	switch format {
	case labelDER:
		opts.Format = certlib.FormatDER
	default:
		opts.Format = certlib.FormatPEM
	}

	if encrypt {
		opts.Encrypt = true
		opts.Password = []byte(password)
	}

	return opts, nil
}

func submitCreateKey(form *formModel, overwrite bool) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildCreateKeyOptions(form)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.GenerateKey(opts)
		if err != nil {
			return formResult(err, "")
		}
		return formResultWithPasswords(nil,
			fmt.Sprintf("Generated %s key at %s", result.KeyType, result.OutputPath),
			opts.Password)
	}
}
