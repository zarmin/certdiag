package tui

import (
	"fmt"
	"slices"
	"strings"
)

type columnEditorModel struct {
	cursor  int
	pending []string  // ordered active column IDs, synced live to tree.activeCols on each toggle
	specs   []colSpec // columns offered in the active view
}

func newColumnEditorModel(activeCols []string, storeView bool) columnEditorModel {
	pending := make([]string, len(activeCols))
	copy(pending, activeCols)
	return columnEditorModel{pending: pending, specs: visibleColSpecs(storeView)}
}

func (ce *columnEditorModel) isActive(id string) bool {
	return slices.Contains(ce.pending, id)
}

func (ce *columnEditorModel) toggle() {
	if ce.cursor >= len(ce.specs) {
		return
	}
	id := ce.specs[ce.cursor].id
	if ce.isActive(id) {
		var next []string
		for _, c := range ce.pending {
			if c != id {
				next = append(next, c)
			}
		}
		ce.pending = next
	} else {
		// Re-add maintaining canonical order
		var next []string
		for _, spec := range ce.specs {
			if spec.id == id || ce.isActive(spec.id) {
				next = append(next, spec.id)
			}
		}
		ce.pending = next
	}
}

func (ce *columnEditorModel) view(width int) string {
	var sb strings.Builder

	sb.WriteString(styleModalTitle.Render(" Column Visibility"))
	sb.WriteString("\n")

	sepW := max(width-2, 4)
	sb.WriteString(styleSeparator.Render(" " + strings.Repeat("─", sepW)))
	sb.WriteString("\n")

	for i, spec := range ce.specs {
		checked := "[ ]"
		if ce.isActive(spec.id) {
			checked = "[x]"
		}
		line := fmt.Sprintf("  %s  %-12s", checked, spec.header)
		if i == ce.cursor {
			sb.WriteString(styleCursorRow.Render(padRight(line, width)))
		} else {
			sb.WriteString(styleNormalRow.Render(line))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
