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

func buildSignCSRForm(scanPath string, node *TreeNode, defaultDays, defaultCADays int) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	title := "Sign CSR"
	if node.Subject != "" {
		title = fmt.Sprintf("Sign CSR -- %s", node.Subject)
	}

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}

	// Signing section
	signingIdx := f.addField(fieldKeySigning, newRadioGroupField("Signing", []string{labelSignWithCA, labelAutosign}, 0))
	caCertIdx := f.addField(fieldKeyCaCert, newFilePickerField("ca_cert", "CA Cert Path", filepicker.TypeOpenFile, scanPath, "", nil))
	caKeyIdx := f.addField(fieldKeyCaKey, newFilePickerField("ca_key", "CA Key Path", filepicker.TypeOpenFile, scanPath, "", nil))

	// Certificate section
	cs := addCertSection(f, defaultDays, defaultCADays)

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	outputIdx := f.addField(fieldKeyOutput, newFilePickerField("output", "Output", filepicker.TypeSaveFile, scanPath, ".crt", extsCertOutput))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Sign"))

	// Sections
	f.addSection("Signing", []int{signingIdx, caCertIdx, caKeyIdx})
	f.addSection("Certificate", []int{cs.certTypeIdx, cs.daysIdx, cs.pathLenIdx, cs.kuIdx, cs.ekuIdx})
	f.addSection("Output", []int{formatIdx, outputIdx, submitIdx})

	// Visibility rules
	f.addVisibilityRule(caCertIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })
	f.addVisibilityRule(caKeyIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })

	outputField := f.fieldByName(fieldKeyOutput).(*filePickerField)
	outputField.placeholder = func() string {
		csrPath := f.getMeta("input_path")
		if csrPath == "" {
			return ""
		}
		base := filepath.Base(csrPath)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		if name == "" {
			return ""
		}
		targetExt := ".crt"
		if f.fieldValue(fieldKeyFormat) == labelDER {
			targetExt = ".der"
		}
		return name + targetExt
	}

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildSignCSROptions(form *formModel, scanPath string, cachedPasswords []certlib.TaggedPassword) (certops.SignCSROptions, error) {
	signing := form.fieldValue(fieldKeySigning)
	caCert := strings.TrimSpace(form.fieldValue(fieldKeyCaCert))
	caKey := strings.TrimSpace(form.fieldValue(fieldKeyCaKey))
	certType := form.fieldValue(fieldKeyCertType)
	daysStr := form.fieldValue(fieldKeyDays)
	pathLenStr := form.fieldValue(fieldKeyPathLen)
	format := form.fieldValue(fieldKeyFormat)
	output := resolvedFilePath(form, "output")

	days := 365
	if daysStr != "" {
		if n, err := strconv.Atoi(daysStr); err == nil && n > 0 {
			days = n
		}
	}

	isCA := certType == labelCA
	pathLength := 0
	if isCA && pathLenStr != "" {
		if n, err := strconv.Atoi(pathLenStr); err == nil && n >= 0 {
			pathLength = n
		}
	}

	var outputFormat certlib.FileFormat
	switch format {
	case labelDER:
		outputFormat = certlib.FormatDER
	default:
		outputFormat = certlib.FormatPEM
	}

	ku, eku, err := parseFormKeyUsage(form)
	if err != nil {
		return certops.SignCSROptions{}, err
	}

	opts := certops.SignCSROptions{
		CSRPath:        form.getMeta("input_path"),
		CAKeyPasswords: append(inputPasswordsFromMeta(form), cachedPasswords...),
		Days:           days,
		IsCA:           isCA,
		PathLength:     pathLength,
		KeyUsage:       ku,
		ExtKeyUsage:    eku,
		CertOutputPath: output,
		OutputFormat:   outputFormat,
	}

	switch signing {
	case labelSignWithCA:
		opts.CACertPath = caCert
		opts.CAKeyPath = caKey
	case labelAutosign:
		searchDirs := certops.AutosignSearchDirs(output)
		if inputDir := filepath.Dir(form.getMeta("input_path")); inputDir != "" {
			searchDirs = append(searchDirs, inputDir)
		}
		searchDirs = append(searchDirs, scanPath)
		caResult, err := certops.FindCA(certops.FindCAOptions{SearchDirs: searchDirs, Passwords: cachedPasswords})
		if err != nil {
			return certops.SignCSROptions{}, fmt.Errorf("autosign: %w", err)
		}
		opts.CACertPath = caResult.CACertPath
		opts.CAKeyPath = caResult.CAKeyPath
	}

	return opts, nil
}

func submitSignCSR(form *formModel, scanPath string, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildSignCSROptions(form, scanPath, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.SignCSR(opts)
		if err != nil {
			return formResult(err, "")
		}
		msg := fmt.Sprintf("Signed CSR -> %s (issuer: %s)", result.CertPath, result.Issuer)
		if len(result.Notes) > 0 {
			msg += "; note: " + strings.Join(result.Notes, "; ")
		}
		return formResult(nil, msg)
	}
}
