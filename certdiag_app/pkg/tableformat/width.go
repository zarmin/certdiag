package tableformat

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
)

const closingBorder = 1

func calculateOverhead(numCols int, compact bool) int {
	return perColOverhead(compact)*numCols + closingBorder
}

func perColOverhead(compact bool) int {
	if compact {
		return 1
	}
	return 3
}

func usableFromPercent(percent float64, tableWidth int, compact bool) int {
	if tableWidth == 0 {
		return 0
	}
	overhead := perColOverhead(compact)
	usable := int(float64(tableWidth-closingBorder)*percent/100.0) - overhead
	if usable < 1 {
		usable = 1
	}
	return usable
}

func clamp(val, min, max int) int {
	if min > 0 && val < min {
		return min
	}
	if max > 0 && val > max {
		return max
	}
	return val
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func calculateWidths(t *Table) ([]int, int, error) {
	opts := &t.Options
	numCols := len(t.Columns)

	if numCols == 0 {
		return []int{}, 0, newTableError(ErrInvalidConfig, "No columns configured")
	}

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

	if err := validate(t); err != nil {
		return nil, 0, err
	}

	overhead := calculateOverhead(numCols, opts.Compact)

	resolvedMins := make([]int, numCols)
	resolvedMaxs := make([]int, numCols)
	naturalWidths := make([]int, numCols)
	fixedWidths := make([]int, numCols)
	isFixed := make([]bool, numCols)

	for i, col := range t.Columns {
		if col.FixWidth > 0 {
			fixedWidths[i] = col.FixWidth
			isFixed[i] = true
		} else if col.FixWidthPercent > 0 {
			usable := usableFromPercent(col.FixWidthPercent, effectiveWidth, opts.Compact)
			fixedWidths[i] = usable
			isFixed[i] = true
		}

		resolvedMins[i] = col.MinWidth
		resolvedMaxs[i] = col.MaxWidth

		naturalWidth := 0
		if i < len(t.Headers) {
			naturalWidth = maxInt(naturalWidth, text.StringWidthWithoutEscSequences(t.Headers[i]))
		}
		for _, row := range t.rows {
			if i < len(row) {
				cellContent := fmt.Sprint(row[i])
				if col.TruncateAfter > 0 {
					cellContent = text.Snip(cellContent, col.TruncateAfter, Ellipsis)
				}
				for _, line := range strings.Split(cellContent, "\n") {
					naturalWidth = maxInt(naturalWidth, text.StringWidthWithoutEscSequences(line))
				}
			}
		}
		naturalWidths[i] = naturalWidth

		if col.NoWrap && !isFixed[i] {
			w := clamp(naturalWidths[i], resolvedMins[i], resolvedMaxs[i])
			if w < 1 {
				w = 1
			}
			fixedWidths[i] = w
			isFixed[i] = true
		}

		if resolvedMins[i] == 0 {
			resolvedMins[i] = 1
		}
	}

	if effectiveWidth == 0 {
		resolvedWidths := make([]int, numCols)
		for i := range numCols {
			if isFixed[i] {
				resolvedWidths[i] = fixedWidths[i]
			} else {
				w := naturalWidths[i]
				w = clamp(w, resolvedMins[i], resolvedMaxs[i])
				if w < 1 {
					w = 1
				}
				resolvedWidths[i] = w
			}
		}
		return resolvedWidths, 0, nil
	}

	usableWidth := effectiveWidth - overhead
	if usableWidth < numCols {
		return nil, 0, newTableError(ErrInvalidConfig,
			fmt.Sprintf("Effective width (%d) too small for %d columns", effectiveWidth, numCols))
	}

	resolvedWidths := make([]int, numCols)
	for i := range numCols {
		resolvedWidths[i] = 0
	}

	remainingUsable := usableWidth
	numFlexible := 0

	for i := range numCols {
		if isFixed[i] {
			resolvedWidths[i] = fixedWidths[i]
			remainingUsable -= fixedWidths[i]
		} else {
			numFlexible++
		}
	}

	if numFlexible == 0 {
		if remainingUsable < 0 {
			return nil, 0, newTableError(ErrNoWrapContentDoesNotFit,
				fmt.Sprintf("Fixed and NoWrap columns exceed usable width by %d", -remainingUsable))
		}
		return resolvedWidths, effectiveWidth, nil
	}

	if remainingUsable < numFlexible {
		return nil, 0, newTableError(ErrInvalidConfig,
			fmt.Sprintf("Not enough space for flexible columns: remaining=%d, count=%d",
				remainingUsable, numFlexible))
	}

	flexNaturalTotal := 0
	for i := range numCols {
		if !isFixed[i] {
			flexNaturalTotal += naturalWidths[i]
		}
	}

	if flexNaturalTotal <= remainingUsable {
		assigned := 0
		for i := range numCols {
			if !isFixed[i] {
				w := naturalWidths[i]
				w = clamp(w, resolvedMins[i], resolvedMaxs[i])
				if w < 1 {
					w = 1
				}
				resolvedWidths[i] = w
				assigned += w
			}
		}

		surplus := remainingUsable - assigned
		if surplus < 0 {
			deficit := -surplus
			for deficit > 0 {
				reduced := false
				for i := range numCols {
					if !isFixed[i] && resolvedWidths[i] > 1 {
						resolvedWidths[i]--
						deficit--
						reduced = true
						if deficit == 0 {
							break
						}
					}
				}
				if !reduced {
					break
				}
			}
		} else if surplus > 0 {
			share := surplus / numFlexible
			remainder := surplus % numFlexible

			for i := range numCols {
				if !isFixed[i] {
					add := share
					if remainder > 0 {
						add++
						remainder--
					}

					newWidth := resolvedWidths[i] + add
					surplus -= add
					if resolvedMaxs[i] > 0 && newWidth > resolvedMaxs[i] {
						diff := newWidth - resolvedMaxs[i]
						resolvedWidths[i] = resolvedMaxs[i]
						surplus += diff
					} else {
						resolvedWidths[i] = newWidth
					}
				}
			}

			for surplus > 0 {
				distributed := false
				for i := range numCols {
					if !isFixed[i] && (resolvedMaxs[i] == 0 || resolvedWidths[i] < resolvedMaxs[i]) {
						resolvedWidths[i]++
						surplus--
						distributed = true
						if surplus == 0 {
							break
						}
					}
				}
				if !distributed {
					break
				}
			}
		}
	} else {
		// Phase 1: give each flexible column its natural width (clamped to max)
		// if it fits. Columns that need more than their fair share are "oversized"
		// and will share the remaining space proportionally.
		fairShare := remainingUsable / numFlexible

		fitsNatural := make([]bool, numCols)
		fittedTotal := 0
		numOversized := 0
		oversizedNaturalTotal := 0

		for i := range numCols {
			if !isFixed[i] {
				w := naturalWidths[i]
				if resolvedMaxs[i] > 0 && w > resolvedMaxs[i] {
					w = resolvedMaxs[i]
				}
				if w <= fairShare {
					fitsNatural[i] = true
					w = clamp(w, resolvedMins[i], resolvedMaxs[i])
					if w < 1 {
						w = 1
					}
					resolvedWidths[i] = w
					fittedTotal += w
				} else {
					numOversized++
					oversizedNaturalTotal += naturalWidths[i]
				}
			}
		}

		// Phase 2: distribute remaining space among oversized columns
		oversizedBudget := remainingUsable - fittedTotal

		if numOversized == 0 {
			// All columns fit — distribute surplus to fitted columns
			surplus := remainingUsable - fittedTotal
			for surplus > 0 {
				distributed := false
				for i := range numCols {
					if !isFixed[i] && (resolvedMaxs[i] == 0 || resolvedWidths[i] < resolvedMaxs[i]) {
						resolvedWidths[i]++
						surplus--
						distributed = true
						if surplus == 0 {
							break
						}
					}
				}
				if !distributed {
					break
				}
			}
		} else if oversizedNaturalTotal == 0 {
			share := oversizedBudget / numOversized
			remainder := oversizedBudget % numOversized
			for i := range numCols {
				if !isFixed[i] && !fitsNatural[i] {
					w := share
					if remainder > 0 {
						w++
						remainder--
					}
					w = clamp(w, resolvedMins[i], resolvedMaxs[i])
					if w < 1 {
						w = 1
					}
					resolvedWidths[i] = w
				}
			}
		} else {
			assigned := 0
			for i := range numCols {
				if !isFixed[i] && !fitsNatural[i] {
					proportion := float64(naturalWidths[i]) / float64(oversizedNaturalTotal)
					w := int(proportion * float64(oversizedBudget))
					w = clamp(w, resolvedMins[i], resolvedMaxs[i])
					if w < 1 {
						w = 1
					}
					resolvedWidths[i] = w
					assigned += w
				}
			}

			deficit := oversizedBudget - assigned
			for deficit != 0 {
				moved := false
				for i := range numCols {
					if !isFixed[i] && !fitsNatural[i] {
						if deficit > 0 {
							if resolvedMaxs[i] == 0 || resolvedWidths[i] < resolvedMaxs[i] {
								resolvedWidths[i]++
								deficit--
								moved = true
							}
						} else if deficit < 0 {
							if resolvedWidths[i] > resolvedMins[i] {
								resolvedWidths[i]--
								deficit++
								moved = true
							}
						}
						if deficit == 0 {
							break
						}
					}
				}
				if !moved {
					break
				}
			}
		}
	}

	for i := range numCols {
		if resolvedWidths[i] < 1 {
			resolvedWidths[i] = 1
		}
	}

	return resolvedWidths, effectiveWidth, nil
}
