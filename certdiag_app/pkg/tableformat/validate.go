package tableformat

import "fmt"

func validate(t *Table) error {
	opts := &t.Options
	numCols := len(t.Columns)

	if opts.AutoDetect && opts.FixWidth != 0 {
		return newTableError(ErrAutoDetectWithFixWidth,
			"AutoDetect and FixWidth cannot both be set")
	}

	if opts.MaxWidth > 0 && opts.MinWidth > 0 && opts.MaxWidth < opts.MinWidth {
		return newTableError(ErrMaxLessThanMin,
			fmt.Sprintf("Table MaxWidth (%d) < MinWidth (%d)", opts.MaxWidth, opts.MinWidth))
	}

	overhead := calculateOverhead(numCols, opts.Compact)

	effectiveWidth := opts.FixWidth
	if opts.AutoDetect {
		effectiveWidth = detectTerminalWidth()
	}
	if opts.MinWidth > 0 && effectiveWidth < opts.MinWidth {
		effectiveWidth = opts.MinWidth
	}
	if opts.MaxWidth > 0 && effectiveWidth > opts.MaxWidth {
		effectiveWidth = opts.MaxWidth
	}

	for i, col := range t.Columns {
		if col.FixWidth > 0 && col.FixWidthPercent > 0 {
			return newTableErrorWithColumn(ErrBothFixWidthAndPercent,
				fmt.Sprintf("Column '%s' has both FixWidth (%d) and FixWidthPercent (%.1f%%)",
					col.Name, col.FixWidth, col.FixWidthPercent), i)
		}

		if col.FixWidth > 0 && (col.MinWidth > 0 || col.MaxWidth > 0) {
			return newTableErrorWithColumn(ErrBothFixWidthAndMinMax,
				fmt.Sprintf("Column '%s' has FixWidth and min/max constraints", col.Name), i)
		}

		effectiveMin := col.MinWidth
		effectiveMax := col.MaxWidth

		if col.FixWidthPercent > 0 {
			usable := usableFromPercent(col.FixWidthPercent, effectiveWidth, opts.Compact)
			if col.MinWidth > 0 {
				effectiveMin = maxInt(effectiveMin, usable)
			}
			if col.MaxWidth > 0 {
				effectiveMax = minInt(effectiveMax, usable)
			}
		}

		if effectiveMax > 0 && effectiveMin > 0 && effectiveMax < effectiveMin {
			return newTableErrorWithColumn(ErrEffectiveMaxLessThanMin,
				fmt.Sprintf("Column '%s' effective max (%d) < effective min (%d)",
					col.Name, effectiveMax, effectiveMin), i)
		}
	}

	fixedTotal := 0
	for _, col := range t.Columns {
		if col.FixWidth > 0 {
			fixedTotal += col.FixWidth
		} else if col.FixWidthPercent > 0 {
			fixedTotal += usableFromPercent(col.FixWidthPercent, effectiveWidth, opts.Compact)
		}
	}
	if fixedTotal > 0 && effectiveWidth > 0 && (fixedTotal+overhead) > effectiveWidth {
		return newTableError(ErrFixedWidthExceedsTable,
			fmt.Sprintf("Fixed columns (%d) + overhead (%d) = %d exceeds table width (%d)",
				fixedTotal, overhead, fixedTotal+overhead, effectiveWidth))
	}

	for i, col := range t.Columns {
		minRequired := 1
		if col.MinWidth > minRequired {
			minRequired = col.MinWidth
		}
		if col.FixWidth > 0 && col.FixWidth < minRequired {
			return newTableErrorWithColumn(ErrColumnWidthTooSmall,
				fmt.Sprintf("Column '%s' width (%d) < minimum required (%d)",
					col.Name, col.FixWidth, minRequired), i)
		}
	}

	return nil
}
