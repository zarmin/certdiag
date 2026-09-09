package tui

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildCreateCSRForm(scanPath string, node *TreeNode, subjectOrg, subjectCountry string, keyDefaults certlib.KeyGenOptions) *formModel {
	f := newFormModel("Create CSR")

	// Subject section
	cnIdx := f.addField(fieldKeyCn, newTextInputField("Common Name (CN)", "e.g. example.com", true, nil))
	orgIdx := f.addField(fieldKeyOrg, newTextInputField("Organization (O)", "e.g. My Corp", false, nil))
	if subjectOrg != "" {
		f.fieldByName(fieldKeyOrg).SetValue(subjectOrg)
	}
	countryIdx := f.addField(fieldKeyCountry, newTextInputField("Country (C)", "e.g. US", false, nil))
	if subjectCountry != "" {
		f.fieldByName(fieldKeyCountry).SetValue(subjectCountry)
	}
	extraDNValidator := func(v string) error {
		if v == "" {
			return nil
		}
		_, err := certlib.ParseDN(v)
		return err
	}
	extraDNIdx := f.addField(fieldKeyExtraDn, newTextInputField("Extra DN", "OU=Eng,L=NYC,ST=NY", false, extraDNValidator))
	sansIdx := f.addField(fieldKeySans, newDynamicListField("SANs", "dns:example.com"))

	// Key section
	keySourceIdx := f.addField(fieldKeyKeySource, newRadioGroupField("Key Source", []string{keySourceGenerate, keySourceExisting}, 0))
	keyPathIdx := f.addField(fieldKeyKeyPath, newFilePickerField("key_path", "Key File Path", filepicker.TypeOpenFile, scanPath, "", nil))
	sizes := keySizeOptions
	algoIdx := f.addField(fieldKeyAlgo, newRadioGroupField("Algorithm", algoOptions, radioIndex(algoOptions, keyDefaults.Algorithm)))
	sizeIdx := f.addField(fieldKeySize, newRadioGroupField("Key Size", sizes, sizeRadioIndex(sizes, keyDefaults.KeySize)))
	curveIdx := f.addField(fieldKeyCurve, newRadioGroupField("Curve", curveOptions, curveRadioIndex(curveOptions, keyDefaults.Curve)))

	// Output section
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	csrOutIdx := f.addField(fieldKeyCsrOut, newFilePickerField("csr_out", "CSR Output", filepicker.TypeSaveFile, scanPath, ".csr", extsCSR))
	keyOutIdx := f.addField(fieldKeyKeyOut, newFilePickerField("key_out", "Key Output", filepicker.TypeSaveFile, scanPath, ".key", extsKeyOutput))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Create"))

	// Sections
	f.addSection("Subject", []int{cnIdx, orgIdx, countryIdx, extraDNIdx, sansIdx})
	f.addSection("Key", []int{keySourceIdx, keyPathIdx, algoIdx, sizeIdx, curveIdx})
	f.addSection("Output", []int{formatIdx, csrOutIdx, keyOutIdx, submitIdx})

	// Visibility rules: key source
	f.addVisibilityRule(keyPathIdx, keySourceIdx, func(v string) bool { return v == keySourceExisting })
	f.addVisibilityRule(algoIdx, keySourceIdx, func(v string) bool { return v == keySourceGenerate })

	// Compound visibility: size visible when key_source="Generate new" AND algo="RSA"
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

	// key_out visible only when generating new key
	f.addVisibilityRule(keyOutIdx, keySourceIdx, func(v string) bool { return v == keySourceGenerate })

	csrOutField := f.fieldByName(fieldKeyCsrOut).(*filePickerField)
	csrOutField.placeholder = func() string {
		base := stringutil.NormalizeName(strings.TrimSpace(f.fieldValue(fieldKeyCn)))
		if base == "" {
			return ""
		}
		return base + ".csr"
	}

	keyOutField := f.fieldByName(fieldKeyKeyOut).(*filePickerField)
	keyOutField.placeholder = func() string {
		base := stringutil.NormalizeName(strings.TrimSpace(f.fieldValue(fieldKeyCn)))
		if base == "" {
			return ""
		}
		return base + ".key"
	}

	// Pre-fill when opened from a key node
	if node != nil && node.Container != nil && strings.Contains(node.ContentType, "/key") {
		f.fieldByName(fieldKeyKeySource).SetValue(keySourceExisting)
		f.fieldByName(fieldKeyKeyPath).SetValue(node.Container.FilePath)
	}

	// Pre-fill from cert or CSR node
	if node != nil && node.Item != nil {
		var data prefillData
		if node.Item.Certificate != nil {
			data = prefillFromCert(node.Item.Certificate)
		} else if node.Item.CSR != nil {
			data = prefillFromCSR(node.Item.CSR)
		}
		applyPrefill(f, data, false)
	}

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildCreateCSROptions(form *formModel, cachedPasswords []certlib.TaggedPassword) (certops.CreateCSROptions, error) {
	cn := strings.TrimSpace(form.fieldValue(fieldKeyCn))
	org := strings.TrimSpace(form.fieldValue(fieldKeyOrg))
	country := strings.TrimSpace(form.fieldValue(fieldKeyCountry))
	sansRaw := form.fieldValue(fieldKeySans)
	keySource := form.fieldValue(fieldKeyKeySource)
	keyPath := strings.TrimSpace(form.fieldValue(fieldKeyKeyPath))
	algo := form.fieldValue(fieldKeyAlgo)
	size := form.fieldValue(fieldKeySize)
	curve := form.fieldValue(fieldKeyCurve)
	format := form.fieldValue(fieldKeyFormat)
	csrOut := resolvedFilePath(form, "csr_out")
	keyOut := resolvedFilePath(form, "key_out")

	subject := pkix.Name{CommonName: cn}
	if org != "" {
		subject.Organization = []string{org}
	}
	if country != "" {
		subject.Country = []string{country}
	}

	extraDN := strings.TrimSpace(form.fieldValue(fieldKeyExtraDn))
	if extraDN != "" {
		extra, err := certlib.ParseDN(extraDN)
		if err != nil {
			return certops.CreateCSROptions{}, fmt.Errorf("invalid extra DN: %w", err)
		}
		subject = certlib.MergeSubject(subject, extra)
		subject.ExtraNames = append(subject.ExtraNames, extra.ExtraNames...)
	}

	var sans certlib.SANList
	if sansRaw != "" {
		var err error
		sans, err = certlib.ParseSANString(sansRaw)
		if err != nil {
			return certops.CreateCSROptions{}, fmt.Errorf("invalid SANs: %w", err)
		}
	}

	var outputFormat certlib.FileFormat
	switch format {
	case labelDER:
		outputFormat = certlib.FormatDER
	default:
		outputFormat = certlib.FormatPEM
	}

	opts := certops.CreateCSROptions{
		Subject:       subject,
		SANs:          sans,
		CSROutputPath: csrOut,
		OutputFormat:  outputFormat,
	}

	if keySource == keySourceExisting {
		opts.KeyFilePath = keyPath
		opts.KeyFilePasswords = cachedPasswords
	} else {
		opts.WithKey = true
		opts.KeyOptions = buildKeyGenOptions(algo, size, curve)
		opts.KeyOutputPath = keyOut
	}

	return opts, nil
}

func submitCreateCSR(form *formModel, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, err := buildCreateCSROptions(form, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.CreateCSR(opts)
		if err != nil {
			return formResult(err, "")
		}
		if result.KeyWritten {
			return formResult(nil, fmt.Sprintf("Created CSR at %s (key: %s)", result.CSRPath, result.KeyPath))
		}
		return formResult(nil, fmt.Sprintf("Created CSR at %s", result.CSRPath))
	}
}
