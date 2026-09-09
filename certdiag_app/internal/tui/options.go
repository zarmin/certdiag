package tui

import (
	"fmt"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
)

type optionKind int

const (
	optBool optionKind = iota
	optInt
	optChoice
)

type optionDef struct {
	key         string
	label       string
	description string
	kind        optionKind
	cliFlag     string
	choices     []string
	category    string
	storeOnly   bool // trust store view only
	scanOnly    bool // hidden in the trust store view (nothing is scanned there)
}

var allOptionDefs = []optionDef{
	{key: "recursive", label: "Recursive", description: "Scan subdirectories", kind: optBool, cliFlag: "--recursive", category: "SCAN", scanOnly: true},
	{key: "max_depth", label: "Max depth", description: "Recursion depth limit (0 = unlimited)", kind: optInt, cliFlag: "--depth", scanOnly: true},
	{key: "signature_scan", label: "Signature scan", description: "Detect certs by file content, not extension", kind: optBool, cliFlag: "--file-signature-scan", scanOnly: true},
	{key: "auto_discover", label: "Auto-discover", description: "Auto-discover related files in same dir", kind: optBool, cliFlag: "--discover", scanOnly: true},
	{key: "store_grouping", label: "Grouping", description: "Group trust stores by instance or by kind", kind: optChoice, choices: []string{"instance", "kind"}, category: "STORE", storeOnly: true},
	{key: "path_display", label: "Path display", description: "How file paths are shown in the tree", kind: optChoice, choices: []string{"filename", "relative", "absolute"}, category: "DISPLAY"},
	{key: "fingerprint_format", label: "Fingerprint format", description: "How fingerprints are rendered (JSON/YAML stay hex)", kind: optChoice, choices: fingerprintFormatChoices(), cliFlag: "--fingerprint-format"},
}

// fingerprintFormatChoices lists the display formats in their declared order.
func fingerprintFormatChoices() []string {
	out := make([]string, 0, len(certlib.FingerprintFormats))
	for _, f := range certlib.FingerprintFormats {
		out = append(out, string(f))
	}
	return out
}

// visibleOptionDefs returns the options offered in a given view. Scan options
// are meaningless in the trust store view and the grouping option is
// meaningless outside it.
func visibleOptionDefs(storeView bool) []optionDef {
	var out []optionDef
	for _, d := range allOptionDefs {
		if d.storeOnly && !storeView {
			continue
		}
		if d.scanOnly && storeView {
			continue
		}
		out = append(out, d)
	}
	return out
}

type optionsModel struct {
	cursor         int
	bools          map[string]bool
	ints           map[string]int
	strs           map[string]string
	locked         map[string]bool
	defs           []optionDef
	changed        bool
	displayChanged bool
	storeChanged   bool
}

func newOptionsModel(scanOpts scanOptionSnapshot, locked map[string]bool) optionsModel {
	if locked == nil {
		locked = make(map[string]bool)
	}
	bools := map[string]bool{
		"recursive":      scanOpts.Recursive,
		"signature_scan": scanOpts.FileSignatureScan,
		"auto_discover":  scanOpts.AutoDiscover,
	}
	ints := map[string]int{
		"max_depth": scanOpts.MaxDepth,
	}
	strs := map[string]string{
		"path_display": scanOpts.PathDisplay,
	}
	strs["store_grouping"] = scanOpts.StoreGrouping
	strs["fingerprint_format"] = scanOpts.FingerprintFormat
	return optionsModel{
		bools:  bools,
		ints:   ints,
		strs:   strs,
		locked: locked,
		defs:   visibleOptionDefs(scanOpts.StoreView),
	}
}

type scanOptionSnapshot struct {
	Recursive         bool
	MaxDepth          int
	FileSignatureScan bool
	AutoDiscover      bool
	PathDisplay       string
	StoreGrouping     string
	StoreView         bool
	FingerprintFormat string
}

func (o *optionsModel) toggleBool(key string) {
	if o.locked[key] {
		return
	}
	o.bools[key] = !o.bools[key]
	o.changed = true
}

func (o *optionsModel) cycleChoice(key string, delta int) {
	if o.locked[key] {
		return
	}
	var def optionDef
	for _, d := range o.defs {
		if d.key == key {
			def = d
			break
		}
	}
	if len(def.choices) == 0 {
		return
	}
	cur := o.strs[key]
	idx := 0
	for i, c := range def.choices {
		if c == cur {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(def.choices)) % len(def.choices)
	o.strs[key] = def.choices[idx]
	if key == "store_grouping" {
		o.storeChanged = true
		return
	}
	o.displayChanged = true
}

func (o *optionsModel) adjustInt(key string, delta int) {
	if o.locked[key] {
		return
	}
	v := o.ints[key] + delta
	if v < 0 {
		v = 0
	}
	if v > 10 {
		v = 10
	}
	o.ints[key] = v
	o.changed = true
}

func (o *optionsModel) currentDef() optionDef {
	if o.cursor >= len(o.defs) {
		return optionDef{}
	}
	return o.defs[o.cursor]
}

func (o *optionsModel) categoryCount() int {
	seen := map[string]bool{}
	for _, def := range o.defs {
		cat := def.category
		if cat == "" {
			continue
		}
		seen[cat] = true
	}
	return len(seen)
}

func (o *optionsModel) snapshot() scanOptionSnapshot {
	return scanOptionSnapshot{
		Recursive:         o.bools["recursive"],
		MaxDepth:          o.ints["max_depth"],
		FileSignatureScan: o.bools["signature_scan"],
		AutoDiscover:      o.bools["auto_discover"],
		PathDisplay:       o.strs["path_display"],
		StoreGrouping:     o.strs["store_grouping"],
		FingerprintFormat: o.strs["fingerprint_format"],
	}
}

func (o *optionsModel) view(width int) string {
	var sb strings.Builder

	sb.WriteString(styleModalTitle.Render(" Options"))
	sb.WriteString("\n")

	sepW := max(width-2, 4)
	sb.WriteString(styleSeparator.Render(" " + strings.Repeat("\u2500", sepW)))
	sb.WriteString("\n")

	lastCategory := ""
	for i, def := range o.defs {
		cat := def.category
		if cat != "" && cat != lastCategory {
			sb.WriteString(styleLabel.Render("  " + cat))
			sb.WriteString("\n")
			lastCategory = cat
		} else if i == 0 && cat == "" {
			sb.WriteString(styleLabel.Render("  SCAN"))
			sb.WriteString("\n")
			lastCategory = "SCAN"
		}

		isLocked := o.locked[def.key]

		var valStr string
		switch def.kind {
		case optBool:
			if o.bools[def.key] {
				valStr = "[x]"
			} else {
				valStr = "[ ]"
			}
			valStr = fmt.Sprintf("  %s %-16s %s", valStr, def.label, def.description)
		case optInt:
			v := o.ints[def.key]
			valStr = fmt.Sprintf("  [%d] %-14s %s", v, def.label, def.description)
		case optChoice:
			v := o.strs[def.key]
			valStr = fmt.Sprintf("  [%s] %-*s %s", v, 14-len(v)+len(def.label), def.label, def.description)
		}

		if isLocked {
			valStr += fmt.Sprintf("  (%s)", def.cliFlag)
		}

		if i == o.cursor {
			if isLocked {
				sb.WriteString(styleDimRow.Render(padRight(valStr, width)))
			} else {
				sb.WriteString(styleCursorRow.Render(padRight(valStr, width)))
			}
		} else {
			if isLocked {
				sb.WriteString(styleDimRow.Render(valStr))
			} else {
				sb.WriteString(styleNormalRow.Render(valStr))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
