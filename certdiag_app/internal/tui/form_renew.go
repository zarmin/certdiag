package tui

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildRenewForm(scanPath string, node *TreeNode, keyDefaults certlib.KeyGenOptions, defaultDays int) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	title := "Renew"
	if node.Subject != "" {
		title = fmt.Sprintf("Renew -- %s", node.Subject)
	}

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}

	// Renewal section
	daysValidator := func(v string) error {
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return fmt.Errorf("must be a positive number")
		}
		return nil
	}
	if defaultDays <= 0 {
		defaultDays = 365
	}
	daysStr := strconv.Itoa(defaultDays)
	f.addField(fieldKeyDays, newTextInputField("Validity (days)", daysStr, false, daysValidator))
	f.fieldByName(fieldKeyDays).SetValue(daysStr)

	keySourceIdx := f.addField(fieldKeyKeySource, newRadioGroupField("Key Source", []string{keySourceReuse, keySourceGenerate}, 0))
	keyPathIdx := f.addField(fieldKeyKeyPath, newFilePickerField("key_path", "Key File Path", filepicker.TypeOpenFile, scanPath, "", nil))
	sizes := keySizeOptions
	algoIdx := f.addField(fieldKeyAlgo, newRadioGroupField("Algorithm", algoOptions, radioIndex(algoOptions, keyDefaults.Algorithm)))
	sizeIdx := f.addField(fieldKeySize, newRadioGroupField("Key Size", sizes, sizeRadioIndex(sizes, keyDefaults.KeySize)))
	curveIdx := f.addField(fieldKeyCurve, newRadioGroupField("Curve", curveOptions, curveRadioIndex(curveOptions, keyDefaults.Curve)))

	// Signing section
	signingIdx := f.addField(fieldKeySigning, newRadioGroupField("Signing", []string{"Self-signed", labelSignWithCA, labelAutosign}, 0))
	caCertIdx := f.addField(fieldKeyCaCert, newFilePickerField("ca_cert", "CA Cert Path", filepicker.TypeOpenFile, scanPath, "", nil))
	caKeyIdx := f.addField(fieldKeyCaKey, newFilePickerField("ca_key", "CA Key Path", filepicker.TypeOpenFile, scanPath, "", nil))

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	certOutIdx := f.addField(fieldKeyCertOut, newFilePickerField("cert_out", "Cert Output", filepicker.TypeSaveFile, scanPath, ".crt", extsCertOutput))
	keyOutIdx := f.addField(fieldKeyKeyOut, newFilePickerField("key_out", "Key Output", filepicker.TypeSaveFile, scanPath, ".key", extsKeyOutput))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Renew"))

	// Sections
	f.addSection("Renewal", []int{f.fieldIndex(fieldKeyDays), keySourceIdx, keyPathIdx, algoIdx, sizeIdx, curveIdx})
	f.addSection("Signing", []int{signingIdx, caCertIdx, caKeyIdx})
	f.addSection("Output", []int{formatIdx, certOutIdx, keyOutIdx, submitIdx})

	// Visibility: key_path visible when "Reuse existing"
	f.addVisibilityRule(keyPathIdx, keySourceIdx, func(v string) bool { return v == keySourceReuse })

	// Visibility: algo visible when "Generate new"
	f.addVisibilityRule(algoIdx, keySourceIdx, func(v string) bool { return v == keySourceGenerate })

	// Compound visibility: size visible when key_source="Generate new" AND algo="RSA"
	// Two rules targeting the same field, each checking the full compound condition.
	f.addVisibilityRule(sizeIdx, algoIdx, func(v string) bool {
		return v == labelRSA && f.fieldValue(fieldKeyKeySource) == keySourceGenerate
	})
	f.addVisibilityRule(sizeIdx, keySourceIdx, func(v string) bool {
		return v == keySourceGenerate && f.fieldValue(fieldKeyAlgo) == labelRSA
	})

	// Compound visibility: curve visible when key_source="Generate new" AND algo="ECDSA"
	f.addVisibilityRule(curveIdx, algoIdx, func(v string) bool {
		return v == labelECDSA && f.fieldValue(fieldKeyKeySource) == keySourceGenerate
	})
	f.addVisibilityRule(curveIdx, keySourceIdx, func(v string) bool {
		return v == keySourceGenerate && f.fieldValue(fieldKeyAlgo) == labelECDSA
	})

	// Signing visibility
	f.addVisibilityRule(caCertIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })
	f.addVisibilityRule(caKeyIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })

	// Compound visibility: key_out visible when "Generate new"
	f.addVisibilityRule(keyOutIdx, keySourceIdx, func(v string) bool { return v == keySourceGenerate })

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildRenewOptions(form *formModel, scanPath string, cachedPasswords []certlib.TaggedPassword) (certops.RenewOptions, error) {
	daysStr := form.fieldValue(fieldKeyDays)
	keySource := form.fieldValue(fieldKeyKeySource)
	keyPath := strings.TrimSpace(form.fieldValue(fieldKeyKeyPath))
	algo := form.fieldValue(fieldKeyAlgo)
	size := form.fieldValue(fieldKeySize)
	curve := form.fieldValue(fieldKeyCurve)
	signing := form.fieldValue(fieldKeySigning)
	caCert := strings.TrimSpace(form.fieldValue(fieldKeyCaCert))
	caKey := strings.TrimSpace(form.fieldValue(fieldKeyCaKey))
	format := form.fieldValue(fieldKeyFormat)
	certOut := form.fieldValue(fieldKeyCertOut)
	keyOut := form.fieldValue(fieldKeyKeyOut)

	days := 365
	if daysStr != "" {
		if n, err := strconv.Atoi(daysStr); err == nil && n > 0 {
			days = n
		}
	}

	var outputFormat certlib.FileFormat
	switch format {
	case labelDER:
		outputFormat = certlib.FormatDER
	default:
		outputFormat = certlib.FormatPEM
	}

	opts := certops.RenewOptions{
		CertPath:       form.getMeta("input_path"),
		CertPasswords:  inputPasswordsFromMeta(form),
		Days:           days,
		CertOutputPath: certOut,
		OutputFormat:   outputFormat,
	}

	if keySource == keySourceReuse {
		opts.KeyFilePath = keyPath
	} else {
		opts.NewKey = true
		opts.KeyOptions = buildKeyGenOptions(algo, size, curve)
		opts.KeyOutputPath = keyOut
	}

	// Wire the session password cache so an encrypted reused key or CA key can
	// be decrypted with a known password.
	opts.KeyFilePasswords = cachedPasswords
	opts.SignerKeyPasswords = cachedPasswords

	switch signing {
	case labelSignWithCA:
		opts.SignerCertPath = caCert
		opts.SignerKeyPath = caKey
	case labelAutosign:
		searchDirs := certops.AutosignSearchDirs(certOut)
		if inputDir := filepath.Dir(form.getMeta("input_path")); inputDir != "" {
			searchDirs = append(searchDirs, inputDir)
		}
		searchDirs = append(searchDirs, scanPath)
		opts.AutosignDirs = searchDirs
		opts.AutosignPasswords = cachedPasswords
	}

	return opts, nil
}

func submitRenew(form *formModel, scanPath string, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildRenewOptions(form, scanPath, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.Renew(opts)
		if err != nil {
			return formResult(err, "")
		}

		msg := fmt.Sprintf("Renewed certificate at %s", result.CertPath)
		if result.KeyWritten {
			msg += fmt.Sprintf(" (new key: %s)", filepath.Base(result.KeyPath))
		}
		return formResult(nil, msg)
	}
}
