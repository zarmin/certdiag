package tableformat

import (
	"fmt"
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
)

func render(orig *Table, w io.Writer) error {
	if len(orig.Columns) == 0 {
		return newTableError(ErrInvalidConfig, "No columns configured")
	}

	t, dropped, err := fitColumns(orig)
	if err != nil {
		return err
	}
	resolvedWidths, effectiveWidth, err := calculateWidths(t)
	if err != nil {
		return err
	}
	defer func() {
		if len(dropped) > 0 {
			fmt.Fprintf(w, "(columns hidden to fit %d cells: %s; widen the terminal or set COLUMNS)\n",
				effectiveWidth, strings.Join(dropped, ", "))
		}
	}()

	processedGrid := make([][][]string, 0)

	if t.Options.DisplayHeaders && len(t.Headers) > 0 {
		headerRow := make([][]string, len(t.Columns))
		for i, header := range t.Headers {
			if i >= len(t.Columns) {
				break
			}

			// Snip the header to the resolved column width first; otherwise an
			// overlong header stays wider than its column and misaligns every
			// border below it.
			snippedHeader := text.Snip(header, resolvedWidths[i], Ellipsis)
			styledHeader := text.Bold.Sprint(snippedHeader)
			aligned := text.AlignCenter.Apply(styledHeader, resolvedWidths[i])

			headerRow[i] = []string{aligned}
		}
		for i := len(t.Headers); i < len(t.Columns); i++ {
			headerRow[i] = []string{padLine(resolvedWidths[i])}
		}
		processedGrid = append(processedGrid, headerRow)
	}

	for rowIdx, row := range t.rows {
		processedRow := make([][]string, len(t.Columns))

		for colIdx := range t.Columns {
			col := &t.Columns[colIdx]
			width := resolvedWidths[colIdx]

			var cellContent string
			var cellStyle CellStyle

			if colIdx < len(row) {
				switch v := row[colIdx].(type) {
				case TableCell:
					cellContent = v.Content
					cellStyle = v.Style
				default:
					cellContent = fmt.Sprint(v)
					cellStyle = CellStyle{}
				}
			}

			lines := processCellContent(cellContent, col, width, &t.Options)

			align := t.Options.DefaultAlignment
			if col.HasAlignment {
				align = col.Alignment
			}
			if cellStyle.HasAlign {
				align = cellStyle.Alignment
			}

			styledLines := make([]string, len(lines))
			for i, line := range lines {
				styled := applyCellStyle(line, cellStyle)
				aligned := applyAlignment(styled, width, align)
				styledLines[i] = aligned
			}

			processedRow[colIdx] = styledLines
		}

		maxLines := 1
		for _, cellLines := range processedRow {
			if len(cellLines) > maxLines {
				maxLines = len(cellLines)
			}
		}

		for colIdx := range processedRow {
			for len(processedRow[colIdx]) < maxLines {
				processedRow[colIdx] = append(processedRow[colIdx], padLine(resolvedWidths[colIdx]))
			}
		}

		processedGrid = append(processedGrid, processedRow)

		_ = rowIdx
	}

	fmt.Fprint(w, buildTopBorder(resolvedWidths, t.Options.Compact))

	for gridIdx, processedRow := range processedGrid {
		maxLines := 0
		for _, cellLines := range processedRow {
			if len(cellLines) > maxLines {
				maxLines = len(cellLines)
			}
		}

		for lineIdx := 0; lineIdx < maxLines; lineIdx++ {
			lineCells := make([]string, len(processedRow))
			for colIdx, cellLines := range processedRow {
				if lineIdx < len(cellLines) {
					lineCells[colIdx] = cellLines[lineIdx]
				} else {
					lineCells[colIdx] = padLine(resolvedWidths[colIdx])
				}
			}
			fmt.Fprint(w, buildContentLine(lineCells, resolvedWidths, t.Options.Compact))
		}

		isHeaderRow := gridIdx == 0 && t.Options.DisplayHeaders && len(t.Headers) > 0
		isLastRow := gridIdx == len(processedGrid)-1

		if isHeaderRow {
			fmt.Fprint(w, buildHeaderSeparator(resolvedWidths, t.Options.Compact))
		} else if t.Options.RowSeparators && !isLastRow {
			fmt.Fprint(w, buildRowSeparator(resolvedWidths, t.Options.Compact))
		}
	}

	fmt.Fprint(w, buildBottomBorder(resolvedWidths, t.Options.Compact))

	_ = effectiveWidth

	return nil
}

func buildTopBorder(resolvedWidths []int, compact bool) string {
	box := DefaultBoxChars
	var parts []string

	for i, width := range resolvedWidths {
		padding := width
		if !compact {
			padding += 2
		}

		if i == 0 {
			parts = append(parts, box.TopLeft)
		} else {
			parts = append(parts, box.TopEdge)
		}
		parts = append(parts, strings.Repeat(box.Horizontal, padding))
	}
	parts = append(parts, box.TopRight, "\n")

	return strings.Join(parts, "")
}

func buildHeaderSeparator(resolvedWidths []int, compact bool) string {
	box := DefaultBoxChars
	var parts []string

	for i, width := range resolvedWidths {
		padding := width
		if !compact {
			padding += 2
		}

		if i == 0 {
			parts = append(parts, box.LeftEdge)
		} else {
			parts = append(parts, box.Cross)
		}
		parts = append(parts, strings.Repeat(box.Horizontal, padding))
	}
	parts = append(parts, box.RightEdge, "\n")

	return strings.Join(parts, "")
}

func buildRowSeparator(resolvedWidths []int, compact bool) string {
	return buildHeaderSeparator(resolvedWidths, compact)
}

func buildBottomBorder(resolvedWidths []int, compact bool) string {
	box := DefaultBoxChars
	var parts []string

	for i, width := range resolvedWidths {
		padding := width
		if !compact {
			padding += 2
		}

		if i == 0 {
			parts = append(parts, box.BottomLeft)
		} else {
			parts = append(parts, box.BottomEdge)
		}
		parts = append(parts, strings.Repeat(box.Horizontal, padding))
	}
	parts = append(parts, box.BottomRight, "\n")

	return strings.Join(parts, "")
}

func buildContentLine(cells []string, resolvedWidths []int, compact bool) string {
	box := DefaultBoxChars
	var parts []string

	for i, cell := range cells {
		parts = append(parts, box.Vertical)
		if compact {
			parts = append(parts, cell)
		} else {
			parts = append(parts, " ", cell, " ")
		}

		_ = resolvedWidths
		_ = i
	}
	parts = append(parts, box.Vertical, "\n")

	return strings.Join(parts, "")
}

// fitColumns hides droppable columns, highest Priority first, until every
// remaining column can be shown at its minimum width. A table without
// droppable columns renders as before, squeezed.
func fitColumns(t *Table) (*Table, []string, error) {
	cur := t
	var dropped []string
	for {
		widths, effectiveWidth, err := calculateWidths(cur)
		fits := err == nil
		if fits {
			total := calculateOverhead(len(cur.Columns), cur.Options.Compact)
			for i, col := range cur.Columns {
				min := col.MinWidth
				if min < 1 {
					min = 1
				}
				if widths[i] < min {
					fits = false
					break
				}
				total += widths[i]
			}
			// The allocator never squeezes a column below its minimum; the
			// table simply grows past the terminal. That is the case to catch.
			if effectiveWidth > 0 && total > effectiveWidth {
				fits = false
			}
		}
		if fits {
			return cur, dropped, nil
		}
		idx, best := -1, 0
		for i, col := range cur.Columns {
			if col.Priority > best {
				best, idx = col.Priority, i
			}
		}
		if idx < 0 {
			if err != nil {
				return nil, dropped, err
			}
			return cur, dropped, nil
		}
		dropped = append(dropped, cur.Columns[idx].Name)
		cur = cur.without(idx)
	}
}

// without returns a copy of the table with one column removed.
func (t *Table) without(idx int) *Table {
	out := &Table{Options: t.Options}
	for i, h := range t.Headers {
		if i != idx {
			out.Headers = append(out.Headers, h)
		}
	}
	for i, c := range t.Columns {
		if i != idx {
			out.Columns = append(out.Columns, c)
		}
	}
	for _, row := range t.rows {
		var r []interface{}
		for i, cell := range row {
			if i != idx {
				r = append(r, cell)
			}
		}
		out.rows = append(out.rows, r)
	}
	return out
}
