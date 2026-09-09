package output

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zarmin/certdiag/certdiag_app/internal/certlib"
	"github.com/zarmin/certdiag/certdiag_app/pkg/tableformat"
)

func newTable(hasRelations, hasChecks, hasTrust bool) *tableformat.Table {
	t := tableformat.New(
		tableformat.WithAutoDetect(),
		tableformat.WithRowSeparators(true),
	)
	headers := []string{"FILENAME", "TYPE", "SUBJECT", "ISSUER", "EXPIRY", "ALGO"}
	if hasTrust {
		headers = append(headers, "TRUST", "STORES")
	}
	if hasRelations {
		headers = append(headers, "RELATIONS")
	}
	if hasChecks {
		headers = append(headers, "WARNINGS")
	}
	t.SetHeaders(headers...)
	// Identity columns (FILENAME, SUBJECT, EXPIRY, TYPE, ISSUER, TRUST) are
	// never hidden and keep a readable minimum; the rest give way at narrow
	// widths in the order RELATIONS, WARNINGS, STORES, ALGO (M31 decision D3).
	t.AddColumn("FILENAME", tableformat.ColTruncateAfter(250), tableformat.ColMinWidth(12))
	t.AddColumn("TYPE", tableformat.ColNoWrap(), tableformat.ColMinWidth(7))
	t.AddColumn("SUBJECT", tableformat.ColTruncateAfter(250), tableformat.ColMinWidth(16))
	t.AddColumn("ISSUER", tableformat.ColTruncateAfter(250), tableformat.ColMinWidth(11)) // "Self-signed"
	t.AddColumn("EXPIRY", tableformat.ColNoWrap(), tableformat.ColFixWidth(10))
	t.AddColumn("ALGO", tableformat.ColMinWidth(6), tableformat.ColPriority(1))
	if hasTrust {
		t.AddColumn("TRUST", tableformat.ColNoWrap(), tableformat.ColMinWidth(9))
		t.AddColumn("STORES", tableformat.ColMaxWidth(18), tableformat.ColMinWidth(6), tableformat.ColPriority(2))
	}
	if hasRelations {
		t.AddColumn("RELATIONS", tableformat.ColMaxWidth(40), tableformat.ColMinWidth(10), tableformat.ColPriority(4))
	}
	if hasChecks {
		t.AddColumn("WARNINGS", tableformat.ColMaxWidth(40), tableformat.ColMinWidth(10), tableformat.ColPriority(3))
	}
	return t
}

func addRows(t *tableformat.Table, containers []*certlib.CertContainer, options OutputOptions, hasRelations bool) {
	containerIndices := resolveTableContainerIndices(containers, options)

	for ci, container := range containers {
		if container.RelationsOnly {
			continue
		}
		filename := filepath.Base(container.FilePath)
		storeIdx := containerIndices[ci]

		for ii, item := range container.Items {
			row := formatTableRow(filename, container.Format, &item, container)
			if options.TrustEnabled() {
				row = append(row, options.TrustVerdict(item.Certificate), formatStoreTags(item.Certificate, options))
			}
			if hasRelations {
				ref := certlib.ItemRef{
					ContainerIdx: storeIdx,
					ItemIdx:      ii,
					FilePath:     container.FilePath,
					Alias:        item.Alias,
				}
				relCell := formatTableRelations(ref, options)
				row = append(row, relCell)
			}
			if options.CheckResult != nil {
				ref := certlib.ItemRef{
					ContainerIdx: storeIdx,
					ItemIdx:      ii,
					FilePath:     container.FilePath,
					Alias:        item.Alias,
				}
				row = append(row, formatTableWarnings(ref, options))
			}
			irow := make([]any, len(row))
			for i, v := range row {
				irow[i] = v
			}
			t.AddRow(irow...)
		}
	}
}

func resolveTableContainerIndices(containers []*certlib.CertContainer, opts OutputOptions) map[int]int {
	result := make(map[int]int)
	if opts.Store == nil {
		for i := range containers {
			result[i] = i
		}
		return result
	}
	for i, c := range containers {
		idx := -1
		for si := range opts.Store.Containers {
			if &opts.Store.Containers[si] == c {
				idx = si
				break
			}
		}
		result[i] = idx
	}
	return result
}

func formatStoreTags(cert *x509.Certificate, options OutputOptions) string {
	if cert == nil || options.StoreTags == nil {
		return ""
	}
	return strings.Join(options.StoreTags(cert), " ")
}

func FormatTableView(containers []*certlib.CertContainer, options OutputOptions) string {
	hasRelations := options.RelationIndex != nil
	hasChecks := options.CheckResult != nil
	t := newTable(hasRelations, hasChecks, options.TrustEnabled())
	addRows(t, containers, options, hasRelations)
	s, err := t.String()
	if err != nil {
		return fmt.Sprintf("error rendering table: %v", err)
	}
	return s
}

func PrintTableView(containers []*certlib.CertContainer, options OutputOptions) {
	hasRelations := options.RelationIndex != nil
	hasChecks := options.CheckResult != nil
	t := newTable(hasRelations, hasChecks, options.TrustEnabled())
	addRows(t, containers, options, hasRelations)
	t.Display()
}

func formatTableRow(filename string, format certlib.FileFormat, item *certlib.CertItem, container *certlib.CertContainer) []string {
	hasKey := false
	hasCert := false
	hasCSR := false
	for _, containerItem := range container.Items {
		if containerItem.Type == certlib.ContentPrivateKey {
			hasKey = true
		}
		if containerItem.Type == certlib.ContentCertificate {
			hasCert = true
		}
		if containerItem.Type == certlib.ContentCSR {
			hasCSR = true
		}
	}

	coloredFilename := ColorizeFilename(filename, hasKey, hasCert, hasCSR)
	contentType := FormatContentType(item, format)
	subject := "-"
	issuer := "-"
	expiry := "-"
	algo := "-"

	switch item.Type {
	case certlib.ContentCertificate:
		if item.Certificate != nil {
			subject = FormatSubjectDN(item.Certificate, 0)
			issuer = ColorizeIssuer(FormatIssuer(item.Certificate), certlib.IsSelfSigned(item.Certificate))
			expiry = ColorizeExpiry(item.Certificate.NotAfter)
			algo = FormatKeyAlgo(item.Certificate.PublicKey)
		}
	case certlib.ContentPrivateKey:
		if item.PrivateKey != nil {
			algo = FormatPrivateKeyAlgo(item.PrivateKey)
		} else if item.Encrypted {
			algo = "(encrypted)"
		}
		if item.EntryPassword != nil && !bytes.Equal(item.EntryPassword, container.Password) {
			contentType += " [diff pw]"
		}
	case certlib.ContentPublicKey:
		if item.PublicKey != nil {
			algo = FormatKeyAlgo(item.PublicKey)
		}
	case certlib.ContentCSR:
		if item.CSR != nil {
			subject = item.CSR.Subject.CommonName
			if subject == "" {
				subject = certlib.FormatDNName(item.CSR.Subject)
			}
			algo = FormatKeyAlgo(item.CSR.PublicKey)
		}
	}

	return []string{coloredFilename, contentType, subject, issuer, expiry, algo}
}

func formatTableWarnings(ref certlib.ItemRef, opts OutputOptions) string {
	if opts.CheckResult == nil {
		return "-"
	}
	var parts []string
	for _, issue := range opts.CheckResult.Issues {
		if issue.ItemRef == ref {
			sev := strings.ToUpper(string(issue.Severity))
			parts = append(parts, fmt.Sprintf("%s: %s", sev, issue.Message))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "\n")
}

func formatTableRelations(ref certlib.ItemRef, opts OutputOptions) string {
	var lines []string

	_, hasChain := opts.Chains[ref]

	if hasChain {
		lines = append(lines, certlib.FormatChainTable(opts.Chains[ref], opts.Store))
	}

	var filtered []certlib.ResolvedRelation
	for _, rel := range opts.RelationIndex[ref] {
		if hasChain && rel.Type == certlib.RelationSignedBy && rel.Direction == certlib.DirectionOutgoing {
			continue
		}
		filtered = append(filtered, rel)
	}

	if grouped := certlib.FormatGroupedRelations(filtered, ref, opts.Store); grouped != "" {
		lines = append(lines, grouped)
	}

	return strings.Join(lines, "\n")
}
