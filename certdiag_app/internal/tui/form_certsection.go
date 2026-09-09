package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type certSectionResult struct {
	certTypeIdx int
	daysIdx     int
	pathLenIdx  int
	kuIdx       int
	ekuIdx      int
}

func addCertSection(f *formModel, defaultDays, defaultCADays int) certSectionResult {
	if defaultDays <= 0 {
		defaultDays = 365
	}
	if defaultCADays <= 0 {
		defaultCADays = 3650
	}

	certTypeIdx := f.addField(fieldKeyCertType, newRadioGroupField("Type", []string{"Leaf", labelCA}, 0))

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
	daysStr := strconv.Itoa(defaultDays)
	daysIdx := f.addField(fieldKeyDays, newTextInputField("Validity (days)", daysStr, false, daysValidator))
	f.fieldByName(fieldKeyDays).SetValue(daysStr)

	pathLenValidator := func(v string) error {
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("must be a non-negative number")
		}
		return nil
	}
	pathLenIdx := f.addField(fieldKeyPathLen, newTextInputField("Path Length", "0", false, pathLenValidator))

	// A CA that says what it may issue for cannot be misused as a CA for
	// everything else, which is the whole reason to offer this here.
	ncValidator := func(v string) error {
		if strings.TrimSpace(v) == "" {
			return nil
		}
		_, err := certlib.ParseNameConstraints(v)
		return err
	}
	permittedIdx := f.addField(fieldKeyPermittedNames,
		newTextInputField("Permitted Names", "DNS:example.com,IP:10.0.0.0/8", false, ncValidator))
	excludedIdx := f.addField(fieldKeyExcludedNames,
		newTextInputField("Excluded Names", "DNS:secret.example.com", false, ncValidator))

	kuIdx := f.addField(fieldKeyKeyUsage, newMultiCheckField("Key Usage", kuOptions, kuDefaultLeaf))
	ekuIdx := f.addField(fieldKeyExtKeyUsage, newMultiCheckField("Ext Key Usage", ekuOptions, ekuDefaultLeaf))

	// Visibility: path_len and the name constraints only when CA
	f.addVisibilityRule(pathLenIdx, certTypeIdx, func(v string) bool { return v == labelCA })
	f.addVisibilityRule(permittedIdx, certTypeIdx, func(v string) bool { return v == labelCA })
	f.addVisibilityRule(excludedIdx, certTypeIdx, func(v string) bool { return v == labelCA })

	// Value rules: switch defaults on cert_type change
	f.addValueRule(daysIdx, certTypeIdx, func(v string) string {
		if v == labelCA {
			return strconv.Itoa(defaultCADays)
		}
		return strconv.Itoa(defaultDays)
	})
	f.addValueRule(kuIdx, certTypeIdx, func(v string) string {
		if v == labelCA {
			return kuDefaultCA
		}
		return kuDefaultLeaf
	})
	f.addValueRule(ekuIdx, certTypeIdx, func(v string) string {
		if v == labelCA {
			return ""
		}
		return ekuDefaultLeaf
	})

	return certSectionResult{
		certTypeIdx: certTypeIdx,
		daysIdx:     daysIdx,
		pathLenIdx:  pathLenIdx,
		kuIdx:       kuIdx,
		ekuIdx:      ekuIdx,
	}
}
