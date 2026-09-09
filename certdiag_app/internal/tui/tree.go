package tui

import (
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib/truststore"
)

type displayMode int

const (
	displayTruncate displayMode = iota // columns clipped with "..."
	displayWrap                        // columns word-wrapped, rows grow taller
	displayHScroll                     // optional columns at natural width, horizontal scrolling
)

const (
	headerFilename = "FILENAME"
	headerStore    = "STORE"
	headerRemote   = "REMOTE"
)

// Column ids that need trust data loaded before they can render.
const (
	colIDTrust  = "trust"
	colIDStores = "stores"
)

type treeModel struct {
	cursor         int
	offset         int
	viewportHeight int
	width          int
	activeCols     []string   // active optional column IDs from config/editor
	cachedVisible  []TreeNode // kept in sync with RootModel.visible for height-aware clamping
	displayMode    displayMode
	hScrollOffset  int
	firstColHeader string // "FILENAME" (default) or "STORE" in trust store view
}

func newTreeModel() treeModel {
	return treeModel{}
}

// colSpec defines visual properties of a configurable optional column.
type colSpec struct {
	id         string
	header     string
	proportion int  // relative width weight; 0 = use fixedWidth
	fixedWidth int  // used when proportion == 0
	multiLine  bool // whether values can span multiple display lines
	storeOnly  bool // only offered in the trust store view
}

// allColSpecs is the canonical ordered list of optional columns.
var allColSpecs = []colSpec{
	{id: "subject", header: "SUBJECT", proportion: 22},
	{id: "issuer", header: "ISSUER", proportion: 18},
	{id: "expiry", header: "EXPIRY", fixedWidth: 12},
	{id: "algo", header: "ALGO", proportion: 12},
	{id: "valid_from", header: "VALID FROM", fixedWidth: 12},
	{id: "sans", header: "SANs", proportion: 22, multiLine: true},
	{id: "usage", header: "USAGE", proportion: 18},
	{id: "relations", header: "RELATIONS", proportion: 22, multiLine: true},
	{id: "warnings", header: "WARNINGS", proportion: 22, multiLine: true},
	{id: colIDTrust, header: "TRUST", fixedWidth: 9},
	{id: colIDStores, header: "STORES", proportion: 14},
	{id: "fp_md5", header: "FP MD5", proportion: 20},
	{id: "fp_sha1", header: "FP SHA-1", proportion: 20},
	{id: "fp_sha256", header: "FP SHA-256", proportion: 20},
	{id: "fp_sha384", header: "FP SHA-384", proportion: 20},
	{id: "fp_sha512", header: "FP SHA-512", proportion: 20},
}

// fingerprintColumns maps a column id to the digest it displays.
var fingerprintColumns = map[string]certlib.FingerprintAlgo{
	"fp_md5":    certlib.FingerprintMD5,
	"fp_sha1":   certlib.FingerprintSHA1,
	"fp_sha256": certlib.FingerprintSHA256,
	"fp_sha384": certlib.FingerprintSHA384,
	"fp_sha512": certlib.FingerprintSHA512,
}

func colSpecByID(id string) *colSpec {
	for i := range allColSpecs {
		if allColSpecs[i].id == id {
			return &allColSpecs[i]
		}
	}
	return nil
}

// visibleColSpecs returns the columns offered in a given view. Store-only
// columns are meaningless in the Cert Lister and are hidden there.
//
// TRUST and STORES are no longer store-only: they answer "does this machine
// trust this certificate", which is the question the Cert Lister exists for.
func visibleColSpecs(storeView bool) []colSpec {
	var out []colSpec
	for _, spec := range allColSpecs {
		if spec.storeOnly && !storeView {
			continue
		}
		out = append(out, spec)
	}
	return out
}

// colWidths holds computed display widths for all columns in a render pass.
type colWidths struct {
	filename int
	ctype    int
	opt      map[string]int // width per optional column ID
	active   []string       // ordered active optional column IDs
}

// --- Viewport management ---

func computeVisible(allNodes []TreeNode, searchFilter string) []TreeNode {
	filter := strings.ToLower(searchFilter)
	var result []TreeNode

	i := 0
	for i < len(allNodes) {
		node := allNodes[i]

		if node.IsBundle {
			childStart := i + 1
			childEnd := childStart
			for childEnd < len(allNodes) && allNodes[childEnd].IsChild && allNodes[childEnd].ContainerIdx == node.ContainerIdx {
				childEnd++
			}

			if filter == "" {
				result = append(result, node)
				if node.Expanded {
					result = append(result, allNodes[childStart:childEnd]...)
				}
			} else {
				headerMatches := strings.Contains(node.Searchable, filter)
				var matchingChildren []TreeNode
				for _, child := range allNodes[childStart:childEnd] {
					if strings.Contains(child.Searchable, filter) {
						matchingChildren = append(matchingChildren, child)
					}
				}
				if headerMatches || len(matchingChildren) > 0 {
					result = append(result, node)
					// A filter shows what matched even inside a folded group:
					// a search that hides its hits is no search (M31 E7).
					if len(matchingChildren) > 0 {
						result = append(result, matchingChildren...)
					} else if headerMatches && node.Expanded {
						result = append(result, allNodes[childStart:childEnd]...)
					}
				}
			}
			i = childEnd
		} else {
			if filter == "" || strings.Contains(node.Searchable, filter) {
				result = append(result, node)
			}
			i++
		}
	}

	return result
}

func (t *treeModel) clampCursor(visibleCount int) {
	if visibleCount == 0 {
		t.cursor = 0
		t.offset = 0
		return
	}
	if t.cursor >= visibleCount {
		t.cursor = visibleCount - 1
	}
	if t.cursor < 0 {
		t.cursor = 0
	}
	t.clampOffset(visibleCount)
}

func (t *treeModel) clampOffset(visibleCount int) {
	if visibleCount == 0 {
		t.offset = 0
		return
	}
	if t.cursor < t.offset {
		t.offset = t.cursor
	}

	visible := t.cachedVisible
	if len(visible) > 0 && t.viewportHeight > 0 {
		cols := calcColWidths(t.activeCols, t.width)
		// Walk from offset to cursor summing display heights; advance offset if cursor is not visible.
		lines := 0
		for i := t.offset; i < len(visible) && i <= t.cursor; i++ {
			if i < t.cursor {
				lines += nodeDisplayHeight(visible[i], cols, t.displayMode)
			} else {
				lines++ // count at least the first line of the cursor row
			}
		}
		for lines > t.viewportHeight && t.offset < t.cursor {
			if t.offset < len(visible) {
				lines -= nodeDisplayHeight(visible[t.offset], cols, t.displayMode)
			}
			t.offset++
		}
	} else {
		// Fallback when cache is not yet populated
		if t.cursor >= t.offset+t.viewportHeight {
			t.offset = t.cursor - t.viewportHeight + 1
		}
	}

	maxOffset := visibleCount - 1
	if t.offset > maxOffset {
		t.offset = maxOffset
	}
	if t.offset < 0 {
		t.offset = 0
	}
}

// nodeDisplayHeight returns how many terminal lines a node occupies given active columns.
func nodeDisplayHeight(node TreeNode, cols colWidths, mode displayMode) int {
	if mode == displayHScroll {
		return 1
	}
	h := 1
	if mode == displayWrap && cols.filename > 0 {
		fnDisplay := "  " + node.Filename
		if node.IsChild {
			fnDisplay = "  '- " + node.Filename
		} else if node.IsBundle {
			fnDisplay = "> " + node.Filename
		}
		fnH := len(wrapText(fnDisplay, cols.filename))
		if fnH > h {
			h = fnH
		}
	}
	for _, col := range cols.active {
		w := cols.opt[col]
		if w == 0 {
			continue
		}
		var colH int
		switch col {
		case "sans":
			if mode == displayWrap {
				colH = wrappedMultiLineHeight(node.SANs, w)
			} else {
				colH = len(node.SANs)
			}
		case "relations":
			if mode == displayWrap {
				colH = wrappedMultiLineHeight(node.Relations, w)
			} else {
				colH = len(node.Relations)
			}
		case "warnings":
			if mode == displayWrap {
				colH = wrappedMultiLineHeight(node.Warnings, w)
			} else {
				colH = len(node.Warnings)
			}
		default:
			if mode == displayWrap {
				val := singleColValue(node, col)
				if val != "" {
					colH = len(wrapText(val, w))
				}
			}
		}
		if colH > h {
			h = colH
		}
	}
	return h
}

// --- Width calculation ---

func calcColWidths(activeCols []string, width int) colWidths {
	avail := width - 2
	if avail < 20 {
		avail = 20
	}

	cw := colWidths{
		opt:    make(map[string]int),
		active: activeCols,
	}

	// Fixed columns: filename gets 20%, type gets 12% of avail
	cw.filename = avail * 20 / 100
	if cw.filename < 6 {
		cw.filename = 6
	}
	cw.ctype = avail * 12 / 100
	if cw.ctype < 4 {
		cw.ctype = 4
	}
	remaining := avail - cw.filename - cw.ctype

	activeSet := make(map[string]bool, len(activeCols))
	for _, col := range activeCols {
		activeSet[col] = true
	}

	// Assign fixed-width optional columns first
	for _, spec := range allColSpecs {
		if !activeSet[spec.id] || spec.proportion != 0 {
			continue
		}
		cw.opt[spec.id] = spec.fixedWidth
		remaining -= spec.fixedWidth + 1 // +1 for leading space
	}

	// Collect proportional optional columns and their total weight
	totalProp := 0
	var propSpecs []colSpec
	for _, spec := range allColSpecs {
		if activeSet[spec.id] && spec.proportion != 0 {
			totalProp += spec.proportion
			propSpecs = append(propSpecs, spec)
		}
	}

	if totalProp > 0 && remaining > 0 {
		// Subtract one leading-space per proportional column
		remaining -= len(propSpecs)
		if remaining < len(propSpecs)*3 {
			remaining = len(propSpecs) * 3
		}

		assigned := 0
		for i, spec := range propSpecs {
			var w int
			if i == len(propSpecs)-1 {
				w = remaining - assigned
			} else {
				w = remaining * spec.proportion / totalProp
			}
			if w < 3 {
				w = 3
			}
			cw.opt[spec.id] = w
			assigned += w
		}
	}

	return cw
}

// --- Rendering ---

func renderTree(visible []TreeNode, t treeModel, dimmed bool, selected ...map[nodeKey]bool) string {
	var sel map[nodeKey]bool
	if len(selected) > 0 {
		sel = selected[0]
	}

	effectiveWidth := t.width
	if sel != nil {
		effectiveWidth -= 4
	}

	var cols colWidths
	if t.displayMode == displayHScroll {
		cols = calcColWidthsHScroll(t.activeCols, effectiveWidth, visible)
	} else {
		cols = calcColWidths(t.activeCols, effectiveWidth)
	}

	var sb strings.Builder

	header := buildHeader(cols, t.displayMode, t.hScrollOffset, t.firstColHeader)
	if sel != nil {
		header = "    " + header
	}
	if dimmed {
		sb.WriteString(styleDimRow.Render(header))
	} else {
		sb.WriteString(styleHeader.Render(header))
	}
	sb.WriteString("\n")

	if len(visible) == 0 {
		sb.WriteString("  (no items)")
		return sb.String()
	}

	linesUsed := 0
	for i := t.offset; i < len(visible) && linesUsed < t.viewportHeight; i++ {
		node := visible[i]
		isCursor := (i == t.cursor)
		height := nodeDisplayHeight(node, cols, t.displayMode)
		prefix := buildNodePrefix(node, visible, i)

		for lineIdx := 0; lineIdx < height; lineIdx++ {
			if linesUsed >= t.viewportHeight {
				break
			}
			if node.Locked && lineIdx > 0 {
				break
			}

			var line string
			if node.Locked {
				line = formatLockedLine(cols, "  "+node.Filename, node.ContentType, t.displayMode, t.hScrollOffset)
			} else {
				line = formatNodeLine(cols, node, prefix, lineIdx, t.displayMode, t.hScrollOffset, isCursor)
				if lineIdx == 0 && !isCursor && !noColor && t.displayMode != displayHScroll {
					line = colorizeRowColumns(line, cols, node)
				}
			}

			if sel != nil {
				key := nodeKey{containerIdx: node.ContainerIdx, itemIdx: node.ItemIdx}
				if lineIdx == 0 {
					if sel[key] {
						line = "[x] " + line
					} else {
						line = "[ ] " + line
					}
				} else {
					line = "    " + line
				}
			}

			if dimmed {
				sb.WriteString(styleDimRow.Render(line))
			} else if isCursor {
				sb.WriteString(styleCursorRow.Render(padRight(line, t.width)))
			} else if node.Locked {
				sb.WriteString(styleLockedRow.Render(line))
			} else if node.IsBundle {
				sb.WriteString(styleBundleRow.Render(line))
			} else {
				sb.WriteString(styleNormalRow.Render(line))
			}
			sb.WriteString("\n")
			linesUsed++
		}
	}

	return sb.String()
}

func buildHeader(cols colWidths, mode displayMode, hScrollOffset int, firstCol string) string {
	if firstCol == "" {
		firstCol = headerFilename
	}
	var sb strings.Builder
	sb.WriteString(" " + padOrTrunc(firstCol, cols.filename))

	if mode == displayHScroll {
		sb.WriteString(hscrollSliceWithType(cols, "TYPE", func(col string, w int) string {
			return padOrTrunc(colHeader(col), w)
		}, hScrollOffset))
	} else {
		sb.WriteString(" " + padOrTrunc("TYPE", cols.ctype))
		for _, col := range cols.active {
			w := cols.opt[col]
			if w == 0 {
				continue
			}
			sb.WriteString(" " + padOrTrunc(colHeader(col), w))
		}
	}
	return sb.String()
}

func colHeader(col string) string {
	for _, spec := range allColSpecs {
		if spec.id == col {
			return spec.header
		}
	}
	return strings.ToUpper(col)
}

func buildNodePrefix(node TreeNode, visible []TreeNode, idx int) string {
	if node.IsBundle {
		if node.Expanded {
			return "v "
		}
		return "> "
	}
	if node.IsChild {
		isLast := true
		if idx+1 < len(visible) {
			next := visible[idx+1]
			if next.IsChild && next.ContainerIdx == node.ContainerIdx {
				isLast = false
			}
		}
		if isLast {
			return "  '- "
		}
		return "  |- "
	}
	return "  "
}

func formatLockedLine(cols colWidths, display, format string, mode displayMode, hScrollOffset int) string {
	var sb strings.Builder
	sb.WriteString(" " + padOrTrunc(display, cols.filename))
	if mode == displayHScroll {
		sb.WriteString(hscrollSliceWithType(cols, format, func(_ string, w int) string {
			return padOrTrunc("[locked] password required", w)
		}, hScrollOffset))
	} else {
		sb.WriteString(" " + padOrTrunc(format, cols.ctype))
		sb.WriteString(" [locked] password required")
	}
	return sb.String()
}

func formatNodeLine(cols colWidths, node TreeNode, prefix string, lineIdx int, mode displayMode, hScrollOffset int, isCursor bool) string {
	var sb strings.Builder

	if mode == displayWrap {
		fnFull := prefix + node.Filename
		fnLines := wrapText(fnFull, cols.filename)
		if lineIdx < len(fnLines) {
			sb.WriteString(" " + padOrTrunc(fnLines[lineIdx], cols.filename))
		} else {
			sb.WriteString(" " + strings.Repeat(" ", cols.filename))
		}
	} else if lineIdx == 0 {
		sb.WriteString(" " + padOrTrunc(prefix+node.Filename, cols.filename))
	} else {
		sb.WriteString(" " + strings.Repeat(" ", cols.filename))
	}

	if mode == displayHScroll {
		typeVal := ""
		if lineIdx == 0 {
			typeVal = node.ContentType
		}
		colorExpiry := lineIdx == 0 && !isCursor && !noColor && !node.ExpiryTime.IsZero()
		sb.WriteString(hscrollSliceWithType(cols, typeVal, func(col string, w int) string {
			val := padOrTrunc(nodeColLine(node, col, lineIdx, w, mode), w)
			if colorExpiry && col == "expiry" {
				trimmed := strings.TrimRight(val, " ")
				if trimmed != "" && trimmed != "---" {
					styled := expiryStyle(node.ExpiryTime).Render(trimmed)
					return styled + strings.Repeat(" ", w-runeWidth(trimmed))
				}
			}
			return val
		}, hScrollOffset))
	} else {
		if lineIdx == 0 {
			sb.WriteString(" " + padOrTrunc(node.ContentType, cols.ctype))
		} else {
			sb.WriteString(" " + strings.Repeat(" ", cols.ctype))
		}
		for _, col := range cols.active {
			w := cols.opt[col]
			if w == 0 {
				continue
			}
			val := nodeColLine(node, col, lineIdx, w, mode)
			sb.WriteString(" " + padOrTrunc(val, w))
		}
	}

	return sb.String()
}

func nodeColLine(node TreeNode, col string, lineIdx int, colWidth int, mode displayMode) string {
	if mode == displayHScroll {
		if lineIdx != 0 {
			return ""
		}
		switch col {
		case "sans":
			if len(node.SANs) > 0 {
				return node.SANs[0]
			}
			return ""
		case "relations":
			if len(node.Relations) > 0 {
				return node.Relations[0]
			}
			return ""
		case "warnings":
			if len(node.Warnings) > 0 {
				return node.Warnings[0]
			}
			return ""
		}
		return singleColValue(node, col)
	}

	if mode == displayTruncate {
		switch col {
		case "sans":
			if lineIdx < len(node.SANs) {
				return node.SANs[lineIdx]
			}
			return ""
		case "relations":
			if lineIdx < len(node.Relations) {
				return node.Relations[lineIdx]
			}
			return ""
		case "warnings":
			if lineIdx < len(node.Warnings) {
				return node.Warnings[lineIdx]
			}
			return ""
		}
		if lineIdx != 0 {
			return ""
		}
		return singleColValue(node, col)
	}

	// Word wrap enabled
	switch col {
	case "sans":
		return wrappedMultiLinePick(node.SANs, colWidth, lineIdx)
	case "relations":
		return wrappedMultiLinePick(node.Relations, colWidth, lineIdx)
	case "warnings":
		return wrappedMultiLinePick(node.Warnings, colWidth, lineIdx)
	}
	val := singleColValue(node, col)
	lines := wrapText(val, colWidth)
	if lineIdx < len(lines) {
		return lines[lineIdx]
	}
	return ""
}

// colorizeColumnInRow applies a style to one column within an already-formatted
// row. The row is plain text at this point; the column offset is computed from
// the width data. style is called with the trimmed cell text and may return the
// text unchanged to skip coloring.
func colorizeColumnInRow(row string, cols colWidths, col string, style func(string) string) string {
	if noColor {
		return row
	}
	colW, active := cols.opt[col]
	if !active || colW == 0 {
		return row
	}

	start := 1 + cols.filename + 1 + cols.ctype
	for _, c := range cols.active {
		if c == col {
			break
		}
		w := cols.opt[c]
		if w == 0 {
			continue
		}
		start += 1 + w
	}
	start += 1 // the column's own leading space

	runes := []rune(row)
	if start >= len(runes) {
		return row
	}
	end := start + colW
	if end > len(runes) {
		end = len(runes)
	}

	field := string(runes[start:end])
	trimmed := strings.TrimRight(field, " ")
	if trimmed == "" || trimmed == "---" {
		return row
	}

	styled := style(trimmed)
	pad := colW - runeWidth(trimmed)
	if pad < 0 {
		pad = 0
	}
	return string(runes[:start]) + styled + strings.Repeat(" ", pad) + string(runes[end:])
}

// colorizeExpiryInRow applies expiry color to the expiry column.
func colorizeExpiryInRow(row string, cols colWidths, node TreeNode) string {
	if node.ExpiryTime.IsZero() {
		return row
	}
	return colorizeColumnInRow(row, cols, "expiry", func(s string) string {
		return expiryStyle(node.ExpiryTime).Render(s)
	})
}

// trustColumnStyle colors a trust verdict: an explicit denial is the finding
// worth seeing, an untrusted or expired chain is a warning.
func trustColumnStyle(s string) string {
	switch truststore.ParseTrustVerdict(s) {
	case truststore.VerdictAnchor, truststore.VerdictTrusted:
		return lipgloss.NewStyle().Foreground(colorGreen).Render(s)
	case truststore.VerdictDenied:
		return lipgloss.NewStyle().Foreground(colorRed).Render(s)
	case truststore.VerdictUntrusted, truststore.VerdictExpired:
		return lipgloss.NewStyle().Foreground(colorYellow).Render(s)
	}
	return styleDimRow.Render(s)
}

// colorizeRowColumns applies per-column color to a rendered row.
//
// Columns must be styled right to left. colorizeColumnInRow locates a column by
// rune offset in the raw row, so styling one inserts escape sequences that shift
// every offset after it; a left-to-right pass slices the next column mid-escape
// and leaks raw ANSI into the output. Going right to left leaves the offsets the
// remaining columns need untouched.
func colorizeRowColumns(row string, cols colWidths, node TreeNode) string {
	type columnStyle struct {
		id    string
		style func(string) string
	}

	var styles []columnStyle
	if !node.ExpiryTime.IsZero() {
		styles = append(styles, columnStyle{"expiry", func(s string) string {
			return expiryStyle(node.ExpiryTime).Render(s)
		}})
	}
	if node.Trust != "" {
		styles = append(styles, columnStyle{colIDTrust, trustColumnStyle})
	}
	if len(node.Stores) > 0 {
		styles = append(styles, columnStyle{colIDStores, func(s string) string {
			// A certificate in every loaded store is the uninteresting case.
			if node.StoresInAll {
				return styleDimRow.Render(s)
			}
			return lipgloss.NewStyle().Foreground(colorAccent).Render(s)
		}})
	}
	if len(styles) == 0 {
		return row
	}

	position := make(map[string]int, len(cols.active))
	for i, c := range cols.active {
		position[c] = i
	}
	sort.SliceStable(styles, func(i, j int) bool {
		return position[styles[i].id] > position[styles[j].id]
	})

	for _, s := range styles {
		row = colorizeColumnInRow(row, cols, s.id, s.style)
	}
	return row
}

// --- Word wrap helpers ---

func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	runes := []rune(s)
	if len(runes) <= width {
		return []string{s}
	}
	var lines []string
	for i := 0; i < len(runes); i += width {
		end := i + width
		if end > len(runes) {
			end = len(runes)
		}
		lines = append(lines, string(runes[i:end]))
	}
	return lines
}

func singleColValue(node TreeNode, col string) string {
	switch col {
	case "subject":
		return node.Subject
	case "issuer":
		return node.Issuer
	case "expiry":
		return node.Expiry
	case "algo":
		return node.Algo
	case "valid_from":
		return node.ValidFrom
	case "usage":
		return node.Usage
	case "stores":
		return strings.Join(node.Stores, " ")
	case "trust":
		return node.Trust
	}
	if algo, ok := fingerprintColumns[col]; ok {
		return node.Fingerprints[algo]
	}
	return ""
}

func wrappedMultiLineHeight(entries []string, width int) int {
	total := 0
	for _, entry := range entries {
		total += len(wrapText(entry, width))
	}
	return total
}

func wrappedMultiLinePick(entries []string, width int, lineIdx int) string {
	idx := 0
	for _, entry := range entries {
		lines := wrapText(entry, width)
		if lineIdx < idx+len(lines) {
			return lines[lineIdx-idx]
		}
		idx += len(lines)
	}
	return ""
}

// --- Horizontal scroll helpers ---

// calcColWidthsHScroll computes column widths for hscroll mode: fixed columns get
// their normal proportional sizes, optional columns get their natural (max content) width.
func calcColWidthsHScroll(activeCols []string, _ int, visible []TreeNode) colWidths {
	cw := colWidths{
		opt:    make(map[string]int),
		active: activeCols,
	}

	// Only filename is pinned; type scrolls with optional columns
	cw.filename = runeWidth("FILENAME")
	cw.ctype = runeWidth("TYPE") // natural width, rendered inside hscroll buffer
	for _, node := range visible {
		prefix := "  "
		if node.IsChild {
			prefix = "  '- "
		}
		if w := runeWidth(prefix + node.Filename); w > cw.filename {
			cw.filename = w
		}
		if w := runeWidth(node.ContentType); w > cw.ctype {
			cw.ctype = w
		}
	}

	natural := naturalColWidths(visible, activeCols)
	for _, col := range activeCols {
		w := natural[col]
		hdr := runeWidth(colHeader(col))
		if w < hdr {
			w = hdr
		}
		if w < 3 {
			w = 3
		}
		cw.opt[col] = w
	}
	return cw
}

// naturalColWidths computes the max content width per optional column across visible nodes.
func naturalColWidths(visible []TreeNode, activeCols []string) map[string]int {
	result := make(map[string]int, len(activeCols))
	for _, node := range visible {
		for _, col := range activeCols {
			var w int
			switch col {
			case "sans":
				for _, s := range node.SANs {
					if rw := runeWidth(s); rw > w {
						w = rw
					}
				}
			case "relations":
				for _, s := range node.Relations {
					if rw := runeWidth(s); rw > w {
						w = rw
					}
				}
			case "warnings":
				for _, s := range node.Warnings {
					if rw := runeWidth(s); rw > w {
						w = rw
					}
				}
			default:
				w = runeWidth(singleColValue(node, col))
			}
			if w > result[col] {
				result[col] = w
			}
		}
	}
	return result
}

// totalScrollableWidth returns the total width of the scrollable area (TYPE + optional columns)
// including leading spaces, for use in hscroll clamping.
func totalScrollableWidth(cols colWidths) int {
	total := 1 + cols.ctype // TYPE column with leading space
	for _, col := range cols.active {
		w := cols.opt[col]
		if w > 0 {
			total += 1 + w
		}
	}
	return total
}

// hscrollSliceWithType renders the TYPE column followed by optional columns into a
// wide buffer, then slices a horizontal window starting at hScrollOffset.
// typeVal is the pre-formatted type value (or header text for the header row).
func hscrollSliceWithType(cols colWidths, typeVal string, renderCol func(col string, w int) string, hScrollOffset int) string {
	var wide strings.Builder
	// TYPE is the first column in the scrollable area
	wide.WriteString(" ")
	wide.WriteString(padOrTrunc(typeVal, cols.ctype))
	for _, col := range cols.active {
		w := cols.opt[col]
		if w == 0 {
			continue
		}
		wide.WriteString(" ")
		wide.WriteString(renderCol(col, w))
	}

	return ansi.TruncateLeft(wide.String(), hScrollOffset, "")
}

// clampHScroll ensures hScrollOffset stays within valid bounds.
func (t *treeModel) clampHScroll() {
	if t.displayMode != displayHScroll {
		t.hScrollOffset = 0
		return
	}
	var cols colWidths
	if len(t.cachedVisible) > 0 {
		cols = calcColWidthsHScroll(t.activeCols, t.width, t.cachedVisible)
	} else {
		cols = calcColWidths(t.activeCols, t.width)
	}
	totalScroll := totalScrollableWidth(cols)
	fixedWidth := 1 + cols.filename
	visibleOpt := t.width - fixedWidth
	if visibleOpt < 0 {
		visibleOpt = 0
	}
	maxOffset := totalScroll - visibleOpt
	if maxOffset < 0 {
		maxOffset = 0
	}
	if t.hScrollOffset > maxOffset {
		t.hScrollOffset = maxOffset
	}
	if t.hScrollOffset < 0 {
		t.hScrollOffset = 0
	}
}

// --- Utility ---

func padOrTrunc(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if runeWidth(s) > width {
		// A wide character may not fit before the ellipsis, leaving the cut
		// a cell short; pad so the column stays aligned.
		s = truncate(s, width)
	}
	return s + strings.Repeat(" ", width-runeWidth(s))
}

// truncate cuts to a number of display cells, not runes: a CJK character is
// two cells wide and the columns must line up for it too (M31 E4).
func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return ansi.Truncate(s, maxLen, "")
	}
	return ansi.Truncate(s, maxLen, "...")
}

func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func runeWidth(s string) int {
	return lipgloss.Width(s)
}
