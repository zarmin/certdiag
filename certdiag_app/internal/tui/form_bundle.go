package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildBundleForm(scanPath string, selectedNodes []TreeNode, filePaths []string) *formModel {
	title := fmt.Sprintf("Bundle -- %d items selected", len(selectedNodes))

	f := newFormModel(title)
	f.setMeta("input_paths", strings.Join(filePaths, ","))
	f.setMeta("item_count", fmt.Sprintf("%d", len(selectedNodes)))

	// Carry exactly the selected items so only they are bundled (not whole files)
	// and aliases stay aligned to the selection order.
	for _, n := range selectedNodes {
		if n.Item != nil {
			f.bundleItems = append(f.bundleItems, *n.Item)
		}
	}

	// Format section (first, drives visibility of other fields)
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelPKCS12, labelPKCS7, labelJKS}, 0))

	// Items section: composite field with inline alias inputs
	var itemDescs []string
	var baseAliases []string
	var aliasable []bool
	for i, n := range selectedNodes {
		itemDescs = append(itemDescs, buildItemLabel(i, n))
		baseAliases = append(baseAliases, prefillAlias(n))
		isCert := n.Item != nil && n.Item.Type == certlib.ContentCertificate
		aliasable = append(aliasable, isCert)
	}
	deduplicatedAliases := deduplicateAliases(baseAliases)

	aliasField := newItemAliasField(itemDescs, deduplicatedAliases, aliasable)
	aliasIdx := f.addField(fieldKeyItemAliases, aliasField)

	tipIdx := f.addField(fieldKeyTip, newReadOnlyTextField("Tip", "root CA is typically omitted for TLS server bundles"))

	// PKCS#12 alias notice
	pkcs12NoticeIdx := f.addField(fieldKeyPkcs12Notice, newReadOnlyTextField("Note", "PKCS#12 alias (friendlyName) is not yet supported"))

	// Options section
	pwIdx := f.addField(fieldKeyPassword, newPasswordInputField("Password", "output password", false, nil))
	legacyIdx := f.addField(fieldKeyLegacy, newCheckboxField("Legacy PKCS#12", false))

	// Output section
	outputField := newFilePickerField("output", "Output", filepicker.TypeSaveFile, scanPath, ".pem", extsPEM)
	outputIdx := f.addField(fieldKeyOutput, outputField)
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Create Bundle"))

	// Sections
	f.addSection("Format", []int{formatIdx})
	f.addSection("Items", []int{aliasIdx, tipIdx, pkcs12NoticeIdx})
	f.addSection("Options", []int{pwIdx, legacyIdx})
	f.addSection("Output", []int{outputIdx, submitIdx})

	// Callback: toggle showAlias on alias field when format is JKS
	f.addFieldCallback(formatIdx, func(v string) {
		aliasField.showAlias = v == labelJKS
	})

	// Callback: update output extensions when format changes
	f.addFieldCallback(formatIdx, func(v string) {
		outputField.SetSaveExtensions(extsForFormat(v))
		outputField.SetAutoExt(autoExtForFormat(v))
	})

	// Visibility rules
	f.addVisibilityRule(pkcs12NoticeIdx, formatIdx, func(v string) bool {
		return v == labelPKCS12
	})
	f.addVisibilityRule(pwIdx, formatIdx, func(v string) bool {
		return v == labelPKCS12 || v == labelJKS
	})
	f.addVisibilityRule(legacyIdx, formatIdx, func(v string) bool {
		return v == labelPKCS12
	})

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func deduplicateAliases(aliases []string) []string {
	used := make(map[string]int)
	result := make([]string, len(aliases))
	for i, base := range aliases {
		lower := strings.ToLower(base)
		if count, exists := used[lower]; exists {
			result[i] = fmt.Sprintf("%s-%d", base, count+1)
			used[lower] = count + 1
		} else {
			result[i] = base
			used[lower] = 1
		}
	}
	return result
}

func buildItemLabel(i int, n TreeNode) string {
	filename := filepath.Base(n.Container.FilePath)
	if n.Item != nil && n.Item.Alias != "" {
		filename = n.Item.Alias
	}
	return fmt.Sprintf("%d. %s (%s)", i+1, filename, n.ContentType)
}

func prefillAlias(n TreeNode) string {
	if n.Item != nil {
		switch n.Item.Type {
		case certlib.ContentCertificate:
			if n.Item.Certificate != nil && n.Item.Certificate.Subject.CommonName != "" {
				return stringutil.SanitizeAlias(n.Item.Certificate.Subject.CommonName)
			}
		case certlib.ContentPrivateKey:
			if n.Subject != "" && n.Subject != "---" {
				return "key-" + stringutil.SanitizeAlias(n.Subject)
			}
			return fmt.Sprintf("key-%d", 1)
		}
	}
	return "entry"
}

func buildBundleOptions(form *formModel) (certops.BundleOptions, error) {
	format := form.fieldValue(fieldKeyFormat)
	password := form.fieldValue(fieldKeyPassword)
	legacy := form.fieldValue(fieldKeyLegacy) == "true"
	output := form.fieldValue(fieldKeyOutput)

	inputPaths := strings.Split(form.getMeta("input_paths"), ",")
	var cleanPaths []string
	for _, p := range inputPaths {
		p = strings.TrimSpace(p)
		if p != "" {
			cleanPaths = append(cleanPaths, p)
		}
	}

	opts := certops.BundleOptions{
		InputPaths:     cleanPaths,
		InputItems:     form.bundleItems,
		AutoChain:      true,
		IncludeRoot:    true,
		OutputPath:     output,
		OutputFormat:   mapOutputFormat(format),
		OutputPassword: nilIfEmpty(password),
		LegacyPKCS12:   legacy,
	}

	// Collect per-item aliases for JKS
	if format == labelJKS {
		aliasStr := form.fieldValue(fieldKeyItemAliases)
		if aliasStr != "" {
			parts := strings.Split(aliasStr, "\n")
			aliases := make(map[int]string)
			for i, v := range parts {
				v = strings.TrimSpace(v)
				if v != "" {
					aliases[i] = v
				}
			}
			if len(aliases) > 0 {
				opts.Aliases = aliases
			}
		}
	}

	return opts, nil
}

func submitBundle(form *formModel, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildBundleOptions(form)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		// Try the session password cache first (encrypted inputs were already
		// unlocked to be selectable), then an empty-password fallback.
		opts.InputPasswords = append([]certlib.TaggedPassword{}, cachedPasswords...)
		opts.InputPasswords = append(opts.InputPasswords,
			certlib.TaggedPassword{Password: []byte(""), Source: certlib.PasswordSourceNone})

		result, err := certops.Bundle(opts)
		if err != nil {
			return formResult(err, "")
		}
		return formResultWithPasswords(nil,
			fmt.Sprintf("Bundled %d items to %s", result.ItemCount, filepath.Base(result.OutputPath)),
			opts.OutputPassword)
	}
}
