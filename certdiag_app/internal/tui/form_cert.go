package tui

import (
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certops"
	"github.com/zarmin/certdiag/certdiag_app/internal/stringutil"
	"github.com/zarmin/certdiag/certdiag_app/pkg/filepicker"
)

func buildCreateCertForm(scanPath string, node *TreeNode, subjectOrg, subjectCountry string, keyDefaults certlib.KeyGenOptions, defaultDays, defaultCADays int) *formModel {
	f := newFormModel("Create Certificate")

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

	// Signing section
	signingIdx := f.addField(fieldKeySigning, newRadioGroupField("Signing", []string{"Self-signed", labelSignWithCA, labelAutosign}, 0))
	caCertIdx := f.addField(fieldKeyCaCert, newFilePickerField("ca_cert", "CA Cert Path", filepicker.TypeOpenFile, scanPath, "", nil))
	caKeyIdx := f.addField(fieldKeyCaKey, newFilePickerField("ca_key", "CA Key Path", filepicker.TypeOpenFile, scanPath, "", nil))

	// Certificate section
	cs := addCertSection(f, defaultDays, defaultCADays)

	// Output section
	outputModeIdx := f.addField(fieldKeyOutputMode, newRadioGroupField("Output", []string{labelIndividualFiles, labelBundlePEM}, 0))
	formatIdx := f.addField(fieldKeyFormat, newRadioGroupField("Format", []string{labelPEM, labelDER}, 0))
	encryptIdx := f.addField(fieldKeyEncryptKey, newCheckboxField("Encrypt Key", false))
	encryptPwIdx := f.addField(fieldKeyEncryptPassword, newPasswordInputField("Key Password", "enter password", true, nil))
	certOutIdx := f.addField(fieldKeyCertOut, newFilePickerField("cert_out", "Cert Output", filepicker.TypeSaveFile, scanPath, ".crt", extsCertOutput))
	keyOutIdx := f.addField(fieldKeyKeyOut, newFilePickerField("key_out", "Key Output", filepicker.TypeSaveFile, scanPath, ".key", extsKeyOutput))
	bundleOutIdx := f.addField(fieldKeyBundleOut, newFilePickerField("bundle_out", "Bundle Output", filepicker.TypeSaveFile, scanPath, ".pem", extsBundleOutput))
	submitIdx := f.addField(fieldKeySubmit, newSubmitButtonField("Create"))

	// Sections
	f.addSection("Subject", []int{cnIdx, orgIdx, countryIdx, extraDNIdx, sansIdx})
	f.addSection("Key", []int{keySourceIdx, keyPathIdx, algoIdx, sizeIdx, curveIdx})
	f.addSection("Signing", []int{signingIdx, caCertIdx, caKeyIdx})
	f.addSection("Certificate", []int{cs.certTypeIdx, cs.daysIdx, cs.pathLenIdx, cs.kuIdx, cs.ekuIdx})
	f.addSection("Output", []int{outputModeIdx, formatIdx, encryptIdx, encryptPwIdx, certOutIdx, keyOutIdx, bundleOutIdx, submitIdx})

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

	// Signing visibility
	f.addVisibilityRule(caCertIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })
	f.addVisibilityRule(caKeyIdx, signingIdx, func(v string) bool { return v == labelSignWithCA })

	// Output visibility
	f.addVisibilityRule(formatIdx, outputModeIdx, func(v string) bool { return v == labelIndividualFiles })
	f.addVisibilityRule(certOutIdx, outputModeIdx, func(v string) bool { return v == labelIndividualFiles })

	// Compound visibility: key_out visible when key_source="Generate new" AND output_mode="Individual files"
	f.addVisibilityRule(keyOutIdx, outputModeIdx, func(v string) bool {
		return v == labelIndividualFiles && f.fieldValue(fieldKeyKeySource) == keySourceGenerate
	})
	f.addVisibilityRule(keyOutIdx, keySourceIdx, func(v string) bool {
		return v == keySourceGenerate && f.fieldValue(fieldKeyOutputMode) == labelIndividualFiles
	})

	f.addVisibilityRule(bundleOutIdx, outputModeIdx, func(v string) bool { return v == labelBundlePEM })

	// Encrypt key: visible when generating new key AND output is PEM (individual PEM or bundle)
	f.addVisibilityRule(encryptIdx, keySourceIdx, func(v string) bool {
		return v == keySourceGenerate && (f.fieldValue(fieldKeyOutputMode) == labelBundlePEM || f.fieldValue(fieldKeyFormat) == labelPEM)
	})
	f.addVisibilityRule(encryptIdx, outputModeIdx, func(v string) bool {
		return f.fieldValue(fieldKeyKeySource) == keySourceGenerate && (v == labelBundlePEM || f.fieldValue(fieldKeyFormat) == labelPEM)
	})
	f.addVisibilityRule(encryptIdx, formatIdx, func(v string) bool {
		return f.fieldValue(fieldKeyKeySource) == keySourceGenerate && (f.fieldValue(fieldKeyOutputMode) == labelBundlePEM || v == labelPEM)
	})
	f.addVisibilityRule(encryptPwIdx, encryptIdx, func(v string) bool { return v == "true" })

	certOutField := f.fieldByName(fieldKeyCertOut).(*filePickerField)
	certOutField.placeholder = func() string {
		base := stringutil.NormalizeName(strings.TrimSpace(f.fieldValue(fieldKeyCn)))
		if base == "" {
			return ""
		}
		return base + ".crt"
	}

	keyOutField := f.fieldByName(fieldKeyKeyOut).(*filePickerField)
	keyOutField.placeholder = func() string {
		base := stringutil.NormalizeName(strings.TrimSpace(f.fieldValue(fieldKeyCn)))
		if base == "" {
			return ""
		}
		return base + ".key"
	}

	bundleOutField := f.fieldByName(fieldKeyBundleOut).(*filePickerField)
	bundleOutField.placeholder = func() string {
		base := stringutil.NormalizeName(strings.TrimSpace(f.fieldValue(fieldKeyCn)))
		if base == "" {
			return ""
		}
		return base + ".pem"
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
		applyPrefill(f, data, true)
	}

	f.evaluateVisibility()
	f.initFocus()

	return f
}

func buildCreateCertOptions(form *formModel, scanPath string, cachedPasswords []certlib.TaggedPassword) (certops.CreateCertOptions, string, error) {
	cn := strings.TrimSpace(form.fieldValue(fieldKeyCn))
	org := strings.TrimSpace(form.fieldValue(fieldKeyOrg))
	country := strings.TrimSpace(form.fieldValue(fieldKeyCountry))
	sansRaw := form.fieldValue(fieldKeySans)
	keySource := form.fieldValue(fieldKeyKeySource)
	keyPath := strings.TrimSpace(form.fieldValue(fieldKeyKeyPath))
	algo := form.fieldValue(fieldKeyAlgo)
	size := form.fieldValue(fieldKeySize)
	curve := form.fieldValue(fieldKeyCurve)
	signing := form.fieldValue(fieldKeySigning)
	caCert := strings.TrimSpace(form.fieldValue(fieldKeyCaCert))
	caKey := strings.TrimSpace(form.fieldValue(fieldKeyCaKey))
	certType := form.fieldValue(fieldKeyCertType)
	daysStr := form.fieldValue(fieldKeyDays)

	pathLenStr := form.fieldValue(fieldKeyPathLen)
	outputMode := form.fieldValue(fieldKeyOutputMode)
	format := form.fieldValue(fieldKeyFormat)
	certOut := strings.TrimSpace(form.fieldValue(fieldKeyCertOut))
	keyOut := strings.TrimSpace(form.fieldValue(fieldKeyKeyOut))
	bundleOut := strings.TrimSpace(form.fieldValue(fieldKeyBundleOut))

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
			return certops.CreateCertOptions{}, "", fmt.Errorf("invalid extra DN: %w", err)
		}
		subject = certlib.MergeSubject(subject, extra)
		subject.ExtraNames = append(subject.ExtraNames, extra.ExtraNames...)
	}

	var sans certlib.SANList
	if sansRaw != "" {
		var err error
		sans, err = certlib.ParseSANString(sansRaw)
		if err != nil {
			return certops.CreateCertOptions{}, "", fmt.Errorf("invalid SANs: %w", err)
		}
	}

	days := 365
	if daysStr != "" {
		if n, err := strconv.Atoi(daysStr); err == nil && n > 0 {
			days = n
		}
	}

	isCA := certType == labelCA

	var nameConstraints certlib.NameConstraints
	if isCA {
		permitted, err := certlib.ParseNameConstraints(form.fieldValue(fieldKeyPermittedNames))
		if err != nil {
			return certops.CreateCertOptions{}, "", fmt.Errorf("invalid permitted names: %w", err)
		}
		excluded, err := certlib.ParseNameConstraints(form.fieldValue(fieldKeyExcludedNames))
		if err != nil {
			return certops.CreateCertOptions{}, "", fmt.Errorf("invalid excluded names: %w", err)
		}
		nameConstraints = permitted.Merge(excluded.Excluded())
		nameConstraints.Critical = true
	}
	pathLength := 0
	if isCA && pathLenStr != "" {
		if n, err := strconv.Atoi(pathLenStr); err == nil && n >= 0 {
			pathLength = n
		}
	}

	baseName := stringutil.NormalizeName(cn)
	if baseName == "" {
		baseName = "cert"
	}

	dir := scanDir(scanPath)

	var outputFormat certlib.FileFormat
	if outputMode == labelBundlePEM {
		outputFormat = certlib.FormatPEM
		certOut = ""
		keyOut = ""
		if bundleOut == "" {
			bundleOut = filepath.Join(dir, baseName+".pem")
		}
	} else {
		outputFormat = certlib.FormatPEM
		switch format {
		case labelDER:
			outputFormat = certlib.FormatDER
		}
		if certOut == "" {
			certOut = filepath.Join(dir, baseName+".crt")
		}
		if keyOut == "" {
			keyOut = filepath.Join(dir, baseName+".key")
		}
		bundleOut = ""
	}

	ku, eku, err := parseFormKeyUsage(form)
	if err != nil {
		return certops.CreateCertOptions{}, "", err
	}

	opts := certops.CreateCertOptions{
		Subject:         subject,
		SANs:            sans,
		Days:            days,
		IsCA:            isCA,
		PathLength:      pathLength,
		NameConstraints: nameConstraints,
		KeyUsage:        ku,
		ExtKeyUsage:     eku,
		CertOutputPath:  certOut,
		OutputFormat:    outputFormat,
	}

	if keySource == keySourceExisting {
		opts.KeyFilePath = keyPath
	} else {
		opts.WithKey = true
		opts.KeyOptions = buildKeyGenOptions(algo, size, curve)
		opts.KeyOutputPath = keyOut
		if form.effectiveValue(fieldKeyEncryptKey) == "true" {
			opts.EncryptKey = true
			opts.KeyPassword = []byte(form.effectiveValue(fieldKeyEncryptPassword))
		}
	}

	// Wire the session password cache so an encrypted existing key or CA key can
	// be decrypted with a known password.
	opts.KeyFilePasswords = cachedPasswords
	opts.SignerKeyPasswords = cachedPasswords

	switch signing {
	case labelSignWithCA:
		opts.SignerCertPath = caCert
		opts.SignerKeyPath = caKey
	case labelAutosign:
		searchDirs := certops.AutosignSearchDirs(certOut)
		searchDirs = append(searchDirs, scanPath)
		caResult, err := certops.FindCA(certops.FindCAOptions{SearchDirs: searchDirs, Passwords: cachedPasswords})
		if err != nil {
			return certops.CreateCertOptions{}, "", fmt.Errorf("autosign: %w", err)
		}
		opts.SignerCertPath = caResult.CACertPath
		opts.SignerKeyPath = caResult.CAKeyPath
	}

	return opts, bundleOut, nil
}

func submitCreateCert(form *formModel, scanPath string, overwrite bool, cachedPasswords []certlib.TaggedPassword) tea.Cmd {
	return func() tea.Msg {
		opts, bundleOut, err := buildCreateCertOptions(form, scanPath, cachedPasswords)
		if err != nil {
			return FormResultMsg{Err: err}
		}
		opts.Overwrite = overwrite

		result, err := certops.CreateCert(opts)
		if err != nil {
			return formResult(err, "")
		}

		if bundleOut != "" {
			bundleData := append(result.CertBytes, result.KeyBytes...)
			err := certlib.WriteToFile(bundleOut, bundleData, overwrite)
			return formResultWithPasswords(err, fmt.Sprintf("Created bundle at %s", bundleOut), opts.KeyPassword)
		}

		msg := fmt.Sprintf("Created %s certificate at %s", result.KeyType, result.CertPath)
		if result.IsSelfSigned {
			msg = fmt.Sprintf("Created self-signed %s certificate at %s", result.KeyType, result.CertPath)
		}
		return formResultWithPasswords(nil, msg, opts.KeyPassword)
	}
}
