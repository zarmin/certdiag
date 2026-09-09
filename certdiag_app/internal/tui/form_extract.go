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

func buildExtractForm(_ string, node *TreeNode) *formModel {
	if node == nil || node.Container == nil {
		return nil
	}

	if node.IsChild && node.Item != nil {
		return buildExtractSingleForm(node)
	}

	itemCount := len(node.Container.Items)
	title := fmt.Sprintf("Extract -- %s (%d items)", node.Filename, itemCount)

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}

	// Filter section
	filterIdx := f.addField(fieldKeyTypeFilter, newRadioGroupField("Type Filter", []string{"All", labelCertsOnly, labelKeysOnly}, 0))

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	parentDir := filepath.Dir(node.Container.FilePath)
	outDirPicker := newFilePickerField("output_dir", "Output Dir", filepicker.TypeOpenDir, parentDir, "", nil)
	outDirPicker.SetValue(parentDir)
	outDirIdx := f.addField(fieldKeyOutputDir, outDirPicker)
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Extract"))

	// Sections
	f.addSection("Filter", []int{filterIdx})
	f.addSection("Output", []int{formatIdx, outDirIdx, submitIdx})

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildExtractSingleForm(node *TreeNode) *formModel {
	bundleName := filepath.Base(node.Container.FilePath)
	title := fmt.Sprintf("Extract -- %s from %s", node.Subject, bundleName)

	f := newFormModel(title)
	f.setMeta("input_path", node.Container.FilePath)
	if len(node.Container.Password) > 0 {
		f.setMeta("input_password", string(node.Container.Password))
	}
	f.setMeta("item_index", strconv.Itoa(node.ItemIdx+1))

	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))

	parentDir := filepath.Dir(node.Container.FilePath)
	defaultName := extractDefaultFilename(node, "pem")
	defaultPath := filepath.Join(parentDir, defaultName)
	contentType := node.Item.Type
	initialExts := extsForExtract(contentType, labelPEM)
	outFilePicker := newFilePickerField("output_file", "Output File", filepicker.TypeSaveFile, parentDir, ".pem", initialExts)
	outFilePicker.SetValue(defaultPath)
	outFileIdx := f.addField(fieldKeyOutputFile, outFilePicker)
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Extract"))

	// Callback: update output extensions when format changes
	f.addFieldCallback(formatIdx, func(v string) {
		outFilePicker.SetSaveExtensions(extsForExtract(contentType, v))
		outFilePicker.SetAutoExt(autoExtForFormat(v))
		outFilePicker.SetValue(rewriteOutputExt(outFilePicker.Value(), v))
	})

	f.addSection("Output", []int{formatIdx, outFileIdx, submitIdx})

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func rewriteOutputExt(path, format string) string {
	if path == "" {
		return path
	}
	ext := filepath.Ext(path)
	if _, ok := certlib.FormatFromExtension(ext); !ok {
		return path
	}
	newExt := autoExtForFormat(format)
	if newExt == "" {
		return path
	}
	return strings.TrimSuffix(path, ext) + newExt
}

func extractDefaultFilename(node *TreeNode, ext string) string {
	base := filepath.Base(node.Container.FilePath)
	baseName := strings.TrimSuffix(base, filepath.Ext(base))
	index := node.ItemIdx + 1
	typeName := extractItemTypeName(node.Item.Type)
	return fmt.Sprintf("%s-%d-%s.%s", baseName, index, typeName, ext)
}

func extractItemTypeName(t certlib.ContentType) string {
	switch t {
	case certlib.ContentCertificate:
		return "cert"
	case certlib.ContentPrivateKey:
		return "key"
	case certlib.ContentPublicKey:
		return "pubkey"
	case certlib.ContentCSR:
		return "csr"
	default:
		return "unknown"
	}
}

func buildExtractOptions(form *formModel) (certops.ExtractOptions, error) {
	if itemIdxStr := form.getMeta("item_index"); itemIdxStr != "" {
		return buildExtractSingleOptions(form, itemIdxStr)
	}

	typeFilter := form.fieldValue(fieldKeyTypeFilter)
	format := form.fieldValue(fieldKeyFormat)
	outputDir := strings.TrimSpace(form.fieldValue(fieldKeyOutputDir))

	var outputFormat certlib.FileFormat
	switch format {
	case labelDER:
		outputFormat = certlib.FormatDER
	default:
		outputFormat = certlib.FormatPEM
	}

	var filter string
	switch typeFilter {
	case labelCertsOnly:
		filter = "certs"
	case labelKeysOnly:
		filter = "keys"
	default:
		filter = "all"
	}

	return certops.ExtractOptions{
		InputPath:      form.getMeta("input_path"),
		InputPasswords: inputPasswordsFromMeta(form),
		OutputDir:      outputDir,
		OutputFormat:   outputFormat,
		TypeFilter:     filter,
	}, nil
}

func buildExtractSingleOptions(form *formModel, itemIdxStr string) (certops.ExtractOptions, error) {
	format := form.fieldValue(fieldKeyFormat)
	outputFile := strings.TrimSpace(form.fieldValue(fieldKeyOutputFile))

	idx, err := strconv.Atoi(itemIdxStr)
	if err != nil {
		return certops.ExtractOptions{}, fmt.Errorf("invalid item index: %s", itemIdxStr)
	}

	var outputFormat certlib.FileFormat
	switch format {
	case labelDER:
		outputFormat = certlib.FormatDER
	default:
		outputFormat = certlib.FormatPEM
	}

	return certops.ExtractOptions{
		InputPath:      form.getMeta("input_path"),
		InputPasswords: inputPasswordsFromMeta(form),
		OutputFile:     outputFile,
		OutputFormat:   outputFormat,
		Index:          idx,
	}, nil
}

func submitExtract(form *formModel, overwrite bool) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildExtractOptions(form)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.Extract(opts)
		if err != nil {
			return formResult(err, "")
		}

		var msg string
		if form.getMeta("item_index") != "" && len(result.ExtractedFiles) == 1 {
			ef := result.ExtractedFiles[0]
			msg = fmt.Sprintf("Extracted %s to %s", ef.Subject, filepath.Base(ef.Path))
		} else {
			msg = fmt.Sprintf("Extracted %d items from %s", len(result.ExtractedFiles), filepath.Base(form.getMeta("input_path")))
		}
		return formResult(nil, msg)
	}
}
