package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/internal/output"
)

type detailLine struct {
	text       string
	value      string // raw copyable value
	selectable bool   // cursor can land here (all non-blank lines)
	navigable  bool   // Enter navigates to targetRef
	targetRef  certlib.ItemRef
	style      *lipgloss.Style
}

type detailModel struct {
	fingerprintFormat certlib.FingerprintFormat

	node         TreeNode
	source       string // remote target (e.g. "example.com:443"), empty for local files
	scrollOffset int
	contentLines []detailLine
	cursorLine   int
	width        int
	height       int
}

func newDetailModel(node TreeNode, structured *output.StructuredOutput, store *certlib.CertStore, opts output.OutputOptions, width, height int) *detailModel {
	d := &detailModel{
		node:              node,
		width:             detailInnerWidth(width, height),
		height:            height,
		cursorLine:        -1,
		fingerprintFormat: opts.FingerprintFormat,
	}
	d.contentLines = d.buildContent(structured, store, opts)
	d.initCursor()
	return d
}

func (d *detailModel) initCursor() {
	for i, line := range d.contentLines {
		if line.selectable {
			d.cursorLine = i
			return
		}
	}
	d.cursorLine = -1
}

func (d *detailModel) hasSelectableLines() bool {
	for _, line := range d.contentLines {
		if line.selectable {
			return true
		}
	}
	return false
}

func (d *detailModel) moveCursorDown() {
	if d.cursorLine < 0 {
		return
	}
	for i := d.cursorLine + 1; i < len(d.contentLines); i++ {
		if d.contentLines[i].selectable {
			d.cursorLine = i
			return
		}
	}
}

func (d *detailModel) moveCursorUp() {
	if d.cursorLine < 0 {
		return
	}
	for i := d.cursorLine - 1; i >= 0; i-- {
		if d.contentLines[i].selectable {
			d.cursorLine = i
			return
		}
	}
}

// moveCursorFirst and moveCursorLast jump to the first and last selectable
// line (Home/End, g/G).
func (d *detailModel) moveCursorFirst() {
	for i := range d.contentLines {
		if d.contentLines[i].selectable {
			d.cursorLine = i
			return
		}
	}
}

func (d *detailModel) moveCursorLast() {
	for i := len(d.contentLines) - 1; i >= 0; i-- {
		if d.contentLines[i].selectable {
			d.cursorLine = i
			return
		}
	}
}

// scrollToEnd shows the last page of a pane without selectable lines.
func (d *detailModel) scrollToEnd(visLines int) {
	if max := len(d.contentLines) - visLines; max > 0 {
		d.scrollOffset = max
	}
}

func (d *detailModel) selectedLine() *detailLine {
	if d.cursorLine >= 0 && d.cursorLine < len(d.contentLines) {
		return &d.contentLines[d.cursorLine]
	}
	return nil
}

func (d *detailModel) ensureLineVisible(idx, visibleLines int) {
	if idx < d.scrollOffset {
		d.scrollOffset = idx
	}
	if idx >= d.scrollOffset+visibleLines {
		d.scrollOffset = idx - visibleLines + 1
	}
}

func (d *detailModel) buildContent(structured *output.StructuredOutput, store *certlib.CertStore, opts output.OutputOptions) []detailLine {
	var lines []detailLine
	node := d.node

	if node.Item == nil {
		if node.isReadOnlySource() {
			lines = append(lines, detailLine{text: "Store:  " + node.Filename, value: node.Filename, selectable: true})
			if node.Container.FilePath != "" {
				lines = append(lines, detailLine{text: "Path:   " + node.Container.FilePath, value: node.Container.FilePath, selectable: true})
			}
			lines = append(lines, detailLine{text: fmt.Sprintf("Certs:  %d", node.ChildCount), value: fmt.Sprintf("%d", node.ChildCount), selectable: true})
			if len(node.Container.ParseErrors) > 0 {
				lines = append(lines, detailLine{})
				lines = append(lines, detailLine{text: "Warnings:", selectable: true})
				for _, e := range node.Container.ParseErrors {
					lines = append(lines, detailLine{text: "  " + e, value: e, selectable: true})
				}
			}
			return lines
		}
		lines = append(lines, detailLine{text: "Bundle: " + node.Filename, value: node.Filename, selectable: true})
		lines = append(lines, d.fileMetadataLines()...)
		lines = append(lines, detailLine{text: "Format: " + node.ContentType, value: node.ContentType, selectable: true})
		lines = append(lines, detailLine{text: fmt.Sprintf("Items:  %d", node.ChildCount), value: fmt.Sprintf("%d", node.ChildCount), selectable: true})
		if len(node.Container.ParseErrors) > 0 {
			lines = append(lines, detailLine{})
			lines = append(lines, detailLine{text: "Errors:", selectable: true})
			for _, e := range node.Container.ParseErrors {
				lines = append(lines, detailLine{text: "  " + e, value: e, selectable: true})
			}
		}
		return lines
	}

	si := d.findStructuredItem(structured)

	switch {
	case node.Item.Type == certlib.ContentCertificate && si != nil && si.Certificate != nil:
		lines = d.buildCertLines(si)
	case node.Item.Type == certlib.ContentCertificate && si == nil && node.Item.Certificate != nil:
		lines = d.buildBareCertLines()
	case node.Item.Type == certlib.ContentPrivateKey && si != nil && si.PrivateKey != nil:
		lines = d.buildKeyLines(si)
	case node.Item.Type == certlib.ContentCSR && si != nil && si.CSR != nil:
		lines = d.buildCSRLines(si)
	default:
		lines = d.buildFallbackLines()
	}

	// Store provenance goes first: for a certificate that came from a trust
	// store, which store it lives in is the primary context.
	lines = append(d.storeProvenanceLines(), lines...)

	// Relations — grouped by type with selectable peer lines
	lines = d.appendRelations(lines, store, opts)

	if len(node.Container.ParseErrors) > 0 {
		lines = append(lines, detailLine{})
		lines = append(lines, detailLine{text: "Errors:", selectable: true})
		for _, e := range node.Container.ParseErrors {
			lines = append(lines, detailLine{text: "  " + e, value: e, selectable: true})
		}
	}

	if opts.CheckResult != nil {
		var warnings []detailLine
		for _, issue := range opts.CheckResult.Issues {
			if issue.ItemRef == d.node.Ref {
				sev := strings.ToUpper(string(issue.Severity))
				text := fmt.Sprintf("  %s: %s", sev, issue.Message)
				line := detailLine{text: text, value: issue.Message, selectable: true}
				switch issue.Severity {
				case certlib.SeverityCritical:
					line.style = &styleCriticalLine
				case certlib.SeverityWarning:
					line.style = &styleWarningLine
				}
				warnings = append(warnings, line)
			}
		}
		if len(warnings) > 0 {
			lines = append(lines, detailLine{})
			lines = append(lines, detailLine{text: "Warnings:", selectable: true})
			lines = append(lines, warnings...)
		}
	}

	return lines
}

// maxDetailChains caps how many chains a busy intermediate lists. A CA that
// issued hundreds of leaves belongs to hundreds of chains; the issuer_of group
// below already enumerates them.
const maxDetailChains = 5

func (d *detailModel) appendRelations(lines []detailLine, store *certlib.CertStore, opts output.OutputOptions) []detailLine {
	if store == nil || opts.RelationIndex == nil {
		return lines
	}

	ref := d.node.Ref

	// Collect chain info
	var chainLabel string
	var extraChains []string
	if chains, ok := opts.ChainsContaining[ref]; ok && len(chains) > 0 {
		bold := lipgloss.NewStyle().Bold(true)
		// The same chain through four copies of a certificate is one chain
		// to the reader: identical labels collapse into one line with a count.
		var labels []string
		counts := map[string]int{}
		for _, chain := range chains {
			label := certlib.FormatChainLabelFor(chain, ref, store, func(s string) string { return bold.Render(s) })
			if counts[label] == 0 {
				labels = append(labels, label)
			}
			counts[label]++
		}
		for i, label := range labels {
			if i >= maxDetailChains {
				extraChains = append(extraChains, fmt.Sprintf("%d+ chains (see issuer_of below)", maxDetailChains))
				break
			}
			if counts[label] > 1 {
				label = fmt.Sprintf("%s (x%d)", label, counts[label])
			}
			if i == 0 {
				chainLabel = label
				continue
			}
			extraChains = append(extraChains, label)
		}
	} else if chain, ok := opts.Chains[ref]; ok {
		bold := lipgloss.NewStyle().Bold(true)
		chainLabel = certlib.FormatChainLabel(chain, store, func(s string) string { return bold.Render(s) })
	}

	rels := opts.RelationIndex[ref]
	if len(rels) == 0 && chainLabel == "" {
		return lines
	}

	lines = append(lines, detailLine{})
	lines = append(lines, detailLine{text: "Relations:", selectable: true})

	if chainLabel != "" {
		lines = append(lines, detailLine{text: "  " + chainLabel, value: chainLabel, selectable: true})
	}
	for _, extra := range extraChains {
		lines = append(lines, detailLine{text: "  " + extra, value: extra, selectable: true})
	}

	for _, group := range certlib.GroupRelations(rels) {
		lines = append(lines, detailLine{text: "  " + group.Key + ":", selectable: true})
		for _, rel := range group.Relations {
			peerInfo := formatPeerInfo(rel.Peer, store)
			lines = append(lines, detailLine{
				text:       "    " + peerInfo,
				value:      strings.TrimSpace(peerInfo),
				selectable: true,
				navigable:  true,
				targetRef:  rel.Peer,
			})
		}
	}

	return lines
}

func formatPeerInfo(ref certlib.ItemRef, store *certlib.CertStore) string {
	if store == nil || ref.ContainerIdx < 0 || ref.ContainerIdx >= len(store.Containers) {
		return filepath.Base(ref.FilePath)
	}
	c := &store.Containers[ref.ContainerIdx]
	if ref.ItemIdx < 0 || ref.ItemIdx >= len(c.Items) {
		return filepath.Base(ref.FilePath)
	}
	item := &c.Items[ref.ItemIdx]
	filename := filepath.Base(c.FilePath)
	if ref.Alias != "" {
		filename = ref.Alias
	}

	var parts []string
	switch item.Type {
	case certlib.ContentCertificate:
		if item.Certificate != nil {
			subject := output.FormatSubject(item.Certificate)
			algo := output.FormatKeyAlgo(item.Certificate.PublicKey)
			expiry := item.Certificate.NotAfter.Format("2006-01-02")
			parts = append(parts, subject, algo, expiry)
		}
	case certlib.ContentPrivateKey:
		parts = append(parts, "[private key]")
		if item.PrivateKey != nil {
			parts = append(parts, output.FormatPrivateKeyAlgo(item.PrivateKey))
		} else if item.Encrypted {
			parts = append(parts, "(encrypted)")
		}
	case certlib.ContentCSR:
		if item.CSR != nil {
			subject := item.CSR.Subject.CommonName
			if subject == "" {
				subject = certlib.FormatDNName(item.CSR.Subject)
			}
			parts = append(parts, subject)
		}
	case certlib.ContentPublicKey:
		parts = append(parts, "[public key]")
		if item.PublicKey != nil {
			parts = append(parts, output.FormatKeyAlgo(item.PublicKey))
		}
	default:
		parts = append(parts, string(item.Type))
	}

	info := strings.Join(parts, "  ")
	return fmt.Sprintf("%-30s (%s)", info, filename)
}

func (d *detailModel) findStructuredItem(structured *output.StructuredOutput) *output.StructuredItem {
	if structured == nil {
		return nil
	}
	node := d.node
	for _, f := range structured.Files {
		if f.FilePath == node.Container.FilePath {
			idx := node.ItemIdx
			if idx >= 0 && idx < len(f.Items) {
				return &f.Items[idx]
			}
		}
	}
	return nil
}

func (d *detailModel) buildCertLines(si *output.StructuredItem) []detailLine {
	c := si.Certificate
	w := d.width
	var lines []detailLine
	lines = append(lines, dl("File", d.node.Filename))
	lines = append(lines, d.fileMetadataLines()...)
	lines = append(lines, dl("Type", d.node.ContentType))
	if si.Alias != "" {
		lines = append(lines, dl("Alias", si.Alias))
	}
	lines = append(lines, dl("Version", fmt.Sprintf("v%d", c.Version)))
	lines = append(lines, dlWrap("Subject", c.Subject, w)...)
	lines = append(lines, dlWrap("Subject DN", c.SubjectDN, w)...)
	lines = append(lines, dlWrap("Issuer", c.Issuer, w)...)
	lines = append(lines, dlWrap("Issuer DN", c.IssuerDN, w)...)
	if len(c.IssuerAltNames) > 0 {
		lines = append(lines, dlWrap("Issuer Alt Names", strings.Join(c.IssuerAltNames, ", "), w)...)
	}
	lines = append(lines, dl("Validity", c.NotBefore+" to "+c.NotAfter))
	lines = append(lines, dlWrap("Serial", c.Serial, w)...)
	lines = append(lines, dl("Algorithm", c.Algorithm))
	lines = append(lines, dl("Signature", c.SignatureAlgo))

	if len(c.SANs) > 0 {
		lines = append(lines, dlWrap("SANs", strings.Join(c.SANs, ", "), w)...)
	}

	if c.IsCA {
		lines = append(lines, dl("CA", "Yes"))
	} else {
		lines = append(lines, dl("CA", "No"))
	}

	if len(c.KeyUsage) > 0 {
		lines = append(lines, dlWrap("Key Usage", strings.Join(c.KeyUsage, ", "), w)...)
	}
	if len(c.ExtKeyUsage) > 0 {
		lines = append(lines, dlWrap("Ext Key Usage", strings.Join(c.ExtKeyUsage, ", "), w)...)
	}

	if len(c.CRLDistributionPoints) > 0 {
		lines = append(lines, dlWrap("CRL Dist Points", strings.Join(c.CRLDistributionPoints, ", "), w)...)
	}

	if len(c.OCSPServers) > 0 || len(c.IssuingCertificateURLs) > 0 {
		var aia []string
		for _, u := range c.OCSPServers {
			aia = append(aia, "OCSP:"+u)
		}
		for _, u := range c.IssuingCertificateURLs {
			aia = append(aia, "CA Issuers:"+u)
		}
		lines = append(lines, dlWrap("Auth Info Access", strings.Join(aia, ", "), w)...)
	}

	lines = append(lines, d.fingerprintLines(c)...)

	return lines
}

// fingerprintLines renders every digest the structured model carries. The
// model always stores canonical lowercase hex, so this re-formats for display
// rather than re-hashing.
func (d *detailModel) fingerprintLines(c *output.StructuredCertificate) []detailLine {
	canonical := map[certlib.FingerprintAlgo]string{
		certlib.FingerprintMD5:    c.MD5,
		certlib.FingerprintSHA1:   c.SHA1,
		certlib.FingerprintSHA256: c.SHA256,
		certlib.FingerprintSHA384: c.SHA384,
		certlib.FingerprintSHA512: c.SHA512,
	}
	var lines []detailLine
	for _, algo := range certlib.FingerprintAlgos {
		value := certlib.ReformatFingerprint(canonical[algo], d.fingerprintFormat)
		if value == "" {
			continue
		}
		lines = append(lines, dlWrap(algo.Label(), value, d.width)...)
	}
	return lines
}

// buildBareCertLines renders a certificate that has no structured item behind
// it. Remote results have one since M30a part IV; the packet analyzer, which
// recovers certificates from a capture, does not.
func (d *detailModel) buildBareCertLines() []detailLine {
	c := output.BuildStructuredCert(d.node.Item)
	w := d.width
	var lines []detailLine
	lines = append(lines, dl("File", d.node.Filename))
	if d.source != "" {
		lines = append(lines, dl("Source", d.source))
	}
	lines = append(lines, dl("Type", d.node.ContentType))
	lines = append(lines, dl("Version", fmt.Sprintf("v%d", c.Version)))
	lines = append(lines, dlWrap("Subject", c.Subject, w)...)
	lines = append(lines, dlWrap("Subject DN", c.SubjectDN, w)...)
	lines = append(lines, dlWrap("Issuer", c.Issuer, w)...)
	lines = append(lines, dlWrap("Issuer DN", c.IssuerDN, w)...)
	if len(c.IssuerAltNames) > 0 {
		lines = append(lines, dlWrap("Issuer Alt Names", strings.Join(c.IssuerAltNames, ", "), w)...)
	}
	lines = append(lines, dl("Validity", c.NotBefore+" to "+c.NotAfter))
	lines = append(lines, dlWrap("Serial", c.Serial, w)...)
	lines = append(lines, dl("Algorithm", c.Algorithm))
	lines = append(lines, dl("Signature", c.SignatureAlgo))
	if len(c.SANs) > 0 {
		lines = append(lines, dlWrap("SANs", strings.Join(c.SANs, ", "), w)...)
	}
	if c.IsCA {
		lines = append(lines, dl("CA", "Yes"))
	} else {
		lines = append(lines, dl("CA", "No"))
	}
	if len(c.KeyUsage) > 0 {
		lines = append(lines, dlWrap("Key Usage", strings.Join(c.KeyUsage, ", "), w)...)
	}
	if len(c.ExtKeyUsage) > 0 {
		lines = append(lines, dlWrap("Ext Key Usage", strings.Join(c.ExtKeyUsage, ", "), w)...)
	}
	if len(c.CRLDistributionPoints) > 0 {
		lines = append(lines, dlWrap("CRL Dist Points", strings.Join(c.CRLDistributionPoints, ", "), w)...)
	}
	if len(c.OCSPServers) > 0 || len(c.IssuingCertificateURLs) > 0 {
		var aia []string
		for _, u := range c.OCSPServers {
			aia = append(aia, "OCSP:"+u)
		}
		for _, u := range c.IssuingCertificateURLs {
			aia = append(aia, "CA Issuers:"+u)
		}
		lines = append(lines, dlWrap("Auth Info Access", strings.Join(aia, ", "), w)...)
	}
	lines = append(lines, d.fingerprintLines(c)...)
	return lines
}

func (d *detailModel) buildKeyLines(si *output.StructuredItem) []detailLine {
	k := si.PrivateKey
	var lines []detailLine
	lines = append(lines, dl("File", d.node.Filename))
	lines = append(lines, d.fileMetadataLines()...)
	lines = append(lines, dl("Type", d.node.ContentType))
	if si.Alias != "" {
		lines = append(lines, dl("Alias", si.Alias))
	}
	lines = append(lines, dl("Algorithm", k.Algorithm))
	if k.Encrypted {
		lines = append(lines, dl("Encrypted", "Yes"))
	}
	return lines
}

func (d *detailModel) buildCSRLines(si *output.StructuredItem) []detailLine {
	c := si.CSR
	w := d.width
	var lines []detailLine
	lines = append(lines, dl("File", d.node.Filename))
	lines = append(lines, d.fileMetadataLines()...)
	lines = append(lines, dl("Type", d.node.ContentType))
	lines = append(lines, dlWrap("Subject", c.Subject, w)...)
	lines = append(lines, dlWrap("Subject DN", c.SubjectDN, w)...)
	lines = append(lines, dl("Algorithm", c.Algorithm))
	lines = append(lines, dl("Signature", c.SignatureAlgo))
	if len(c.SANs) > 0 {
		lines = append(lines, dlWrap("SANs", strings.Join(c.SANs, ", "), w)...)
	}
	return lines
}

func (d *detailModel) buildFallbackLines() []detailLine {
	var lines []detailLine
	lines = append(lines, dl("File", d.node.Filename))
	lines = append(lines, d.fileMetadataLines()...)
	lines = append(lines, dl("Type", d.node.ContentType))
	if d.node.Subject != "" && d.node.Subject != "---" {
		lines = append(lines, dl("Subject", d.node.Subject))
	}
	if d.node.Algo != "" && d.node.Algo != "---" {
		lines = append(lines, dl("Algorithm", d.node.Algo))
	}
	return lines
}

func dl(label, value string) detailLine {
	return detailLine{
		text:       fmt.Sprintf("%-15s %s", label+":", value),
		value:      value,
		selectable: true,
	}
}

const dlLabelWidth = 16 // 15 chars label + colon + 1 space

func dlWrap(label, value string, width int) []detailLine {
	if width <= dlLabelWidth+10 {
		return []detailLine{dl(label, value)}
	}
	availW := width - dlLabelWidth
	text := fmt.Sprintf("%-15s %s", label+":", value)
	if lipgloss.Width(text) <= width {
		return []detailLine{dl(label, value)}
	}

	indent := strings.Repeat(" ", dlLabelWidth)
	chunks := wrapDetailValue(value, availW)
	var lines []detailLine
	for i, chunk := range chunks {
		if i == 0 {
			lines = append(lines, detailLine{
				text:       fmt.Sprintf("%-15s %s", label+":", chunk),
				value:      value,
				selectable: true,
			})
		} else {
			lines = append(lines, detailLine{
				text:       indent + chunk,
				value:      value,
				selectable: true,
			})
		}
	}
	return lines
}

func wrapDetailValue(s string, maxW int) []string {
	if maxW <= 0 || lipgloss.Width(s) <= maxW {
		return []string{s}
	}
	var result []string
	for len(s) > 0 {
		if lipgloss.Width(s) <= maxW {
			result = append(result, s)
			break
		}
		cut := len(s)
		width := 0
		for i, r := range s {
			rw := lipgloss.Width(string(r))
			if i > 0 && width+rw > maxW {
				cut = i
				break
			}
			width += rw
		}
		// Try to break at a separator (comma+space, space)
		best := -1
		for i := cut; i > 0; i-- {
			if i < len(s) && (s[i] == ' ' || s[i] == ',') {
				best = i
				break
			}
		}
		if best > 0 {
			result = append(result, strings.TrimRight(s[:best+1], " "))
			s = strings.TrimLeft(s[best+1:], " ")
		} else {
			result = append(result, s[:cut])
			s = s[cut:]
		}
	}
	return result
}

func (d *detailModel) fileMetadataLines() []detailLine {
	c := d.node.Container
	var lines []detailLine
	absPath, err := filepath.Abs(c.FilePath)
	if err == nil {
		lines = append(lines, dl("Path", absPath))
	}
	if !(d.node.IsChild && c.FileSize == 0) {
		lines = append(lines, dl("Size", output.FormatFileSize(c.FileSize)))
	}
	if !c.FileModTime.IsZero() {
		lines = append(lines, dl("Modified", c.FileModTime.Format(time.DateTime)))
	}
	if !c.FileAccessTime.IsZero() {
		lines = append(lines, dl("Accessed", c.FileAccessTime.Format(time.DateTime)))
	}
	if !c.FileCreateTime.IsZero() {
		lines = append(lines, dl("Created", c.FileCreateTime.Format(time.DateTime)))
	}
	return lines
}

func (d *detailModel) visibleLines(panelHeight int) int {
	// For split panel: panelHeight is the available content area
	// Subtract title (2 lines) and footer (1 line)
	lines := panelHeight - 3
	if lines < 1 {
		lines = 1
	}
	return lines
}

func (d *detailModel) scrollDown(visLines int) {
	maxScroll := len(d.contentLines) - visLines
	if maxScroll < 0 {
		maxScroll = 0
	}
	if d.scrollOffset < maxScroll {
		d.scrollOffset++
	}
}

func (d *detailModel) scrollUp() {
	if d.scrollOffset > 0 {
		d.scrollOffset--
	}
}

// detailInnerWidth returns the inner content width the detail is rendered
// into, matching renderDetailPanel (split) and renderDetailFullscreen.
func detailInnerWidth(width, height int) int {
	if height >= splitScreenMinHeight {
		innerW := width - 2
		if innerW < 10 {
			innerW = 10
		}
		return innerW
	}
	modalWidth := width - 4
	if modalWidth > 70 {
		modalWidth = 70
	}
	if modalWidth < 20 {
		modalWidth = 20
	}
	innerW := modalWidth - 4
	if innerW < 10 {
		innerW = 10
	}
	return innerW
}

// renderDetailPanel renders the detail view for split-screen mode.
func renderDetailPanel(d *detailModel, focused bool, panelHeight, panelWidth int) string {
	if d == nil || panelHeight < 3 {
		return ""
	}

	innerW := panelWidth - 2
	if innerW < 10 {
		innerW = 10
	}

	var sb strings.Builder

	// Title
	title := detailTitle(d)
	if !noColor {
		title = styleModalTitle.Render(title)
	}
	sb.WriteString(title)
	sb.WriteString("\n\n")

	visLines := d.visibleLines(panelHeight)

	// Ensure cursor is visible
	if d.cursorLine >= 0 {
		d.ensureLineVisible(d.cursorLine, visLines)
	}

	end := d.scrollOffset + visLines
	if end > len(d.contentLines) {
		end = len(d.contentLines)
	}
	start := d.scrollOffset
	if start > end {
		start = end
	}

	for i := start; i < end; i++ {
		line := d.contentLines[i]
		text := line.text
		if runeWidth(text) > innerW {
			text = truncate(text, innerW)
		}

		if i == d.cursorLine && focused {
			sb.WriteString(styleCursorRow.Render(padRight(text, innerW)))
		} else if line.style != nil {
			sb.WriteString(line.style.Render(text))
		} else if line.navigable {
			sb.WriteString(styleSelectableRow.Render(text))
		} else {
			sb.WriteString(text)
		}
		sb.WriteString("\n")
	}

	// Fill remaining lines
	for i := end - start; i < visLines; i++ {
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderDetailFullscreen renders the detail view for small terminals (fullscreen mode).
func renderDetailFullscreen(d *detailModel, width, height int) string {
	if d == nil {
		return ""
	}

	modalWidth := width - 4
	if modalWidth > 70 {
		modalWidth = 70
	}
	if modalWidth < 20 {
		modalWidth = 20
	}
	modalHeight := height - 4
	if modalHeight > 30 {
		modalHeight = 30
	}
	if modalHeight < 5 {
		modalHeight = 5
	}

	innerW := modalWidth - 4
	if innerW < 10 {
		innerW = 10
	}
	innerH := modalHeight - 4
	if innerH < 1 {
		innerH = 1
	}

	title := detailTitle(d)

	footer, footerHeight := detailFooter(d, false, innerW)

	var contentSB strings.Builder
	contentSB.WriteString(styleModalTitle.Render(title))
	contentSB.WriteString("\n\n")

	visLines := innerH - 2 - footerHeight // title + blank + footer
	if visLines < 1 {
		visLines = 1
	}

	if d.cursorLine >= 0 {
		d.ensureLineVisible(d.cursorLine, visLines)
	}

	end := d.scrollOffset + visLines
	if end > len(d.contentLines) {
		end = len(d.contentLines)
	}
	start := d.scrollOffset
	if start > end {
		start = end
	}

	for i := start; i < end; i++ {
		line := d.contentLines[i]
		text := line.text
		if runeWidth(text) > innerW {
			text = truncate(text, innerW)
		}

		if i == d.cursorLine {
			contentSB.WriteString(styleCursorRow.Render(padRight(text, innerW)))
		} else if line.style != nil {
			contentSB.WriteString(line.style.Render(text))
		} else if line.navigable {
			contentSB.WriteString(styleSelectableRow.Render(text))
		} else {
			contentSB.WriteString(text)
		}
		contentSB.WriteString("\n")
	}

	for i := end - start; i < visLines; i++ {
		contentSB.WriteString("\n")
	}

	contentSB.WriteString(footer)

	var border lipgloss.Border
	if noColor {
		border = lipgloss.NormalBorder()
	} else {
		border = lipgloss.RoundedBorder()
	}

	boxStyle := lipgloss.NewStyle().
		Border(border).
		BorderForeground(colorModal).
		Padding(0, 1).
		Width(modalWidth - 2)

	box := boxStyle.Render(contentSB.String())
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func detailTitle(d *detailModel) string {
	title := "Details"
	if d.node.Item != nil {
		switch d.node.Item.Type {
		case certlib.ContentCertificate:
			title = "Certificate Details"
		case certlib.ContentPrivateKey:
			title = "Private Key Details"
		case certlib.ContentCSR:
			title = "CSR Details"
		}
	}
	return title
}

func detailFooter(d *detailModel, splitMode bool, width int) (string, int) {
	return RenderHintBar(width, detailHints(d, splitMode))
}

// detailHints is the key list of the full-screen detail view; the split view
// has its own (splitHints).
func detailHints(d *detailModel, splitMode bool) []Hint {
	hints := []Hint{{"j/k", "Scroll"}}
	sel := d.selectedLine()
	if sel != nil && sel.navigable {
		hints = append(hints, Hint{"Enter", "Navigate"})
	}
	if splitMode {
		hints = append(hints, Hint{"Tab", "Tree"})
	}
	if d.source != "" || (d.node.Container != nil && d.node.Container.FilePath != "") {
		hints = append(hints, Hint{"o", "OpenSSL"})
	}
	return append(hints, Hint{"?", "Help"}, Hint{"Esc/q", "Close"})
}

// storeProvenanceLines builds the trust store context for a certificate that
// came from a store rather than a file.
func (d *detailModel) storeProvenanceLines() []detailLine {
	node := d.node
	if !node.isReadOnlySource() {
		return nil
	}

	var lines []detailLine
	lines = append(lines, detailLine{text: "Store:", selectable: true})
	lines = append(lines, detailLine{text: "  Name:         " + node.Container.Label, value: node.Container.Label, selectable: true})
	if node.Container.FilePath != "" {
		lines = append(lines, detailLine{text: "  Path:         " + node.Container.FilePath, value: node.Container.FilePath, selectable: true})
	}
	if node.StoreKind != "" {
		lines = append(lines, detailLine{text: "  Kind:         " + node.StoreKind, value: node.StoreKind, selectable: true})
	}
	if node.Item != nil && node.Item.Alias != "" {
		lines = append(lines, detailLine{text: "  Alias:        " + node.Item.Alias, value: node.Item.Alias, selectable: true})
	}
	if len(node.Stores) > 0 {
		joined := strings.Join(node.Stores, ", ")
		lines = append(lines, detailLine{text: "  Also present: " + joined, value: joined, selectable: true})
	}
	if node.Trust != "" {
		lines = append(lines, detailLine{text: "  Trust:        " + node.Trust, value: node.Trust, selectable: true})
		for _, p := range node.TrustPolicies {
			lines = append(lines, detailLine{text: "    " + p, value: p, selectable: true})
		}
	}
	lines = append(lines, detailLine{})
	return lines
}
