package tableformat

import (
	"strings"

	"github.com/jedib0t/go-pretty/v6/text"
)

// newlineCollapser turns any embedded line break into a single space so NoWrap
// cells stay on one physical line.
var newlineCollapser = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

func processCellContent(content string, col *ColumnConfig, width int, tableOpts *TableOptions) []string {
	if col.TruncateAfter > 0 {
		content = text.Snip(content, col.TruncateAfter, Ellipsis)
	}

	if col.NoWrap || !tableOpts.AllowLinebreaks {
		// Collapse embedded newlines to spaces first: a NoWrap cell must render on
		// a single physical line, otherwise a literal \n survives text.Snip and
		// splits the row across lines, corrupting the table borders.
		oneLine := newlineCollapser.Replace(content)
		snipped := text.Snip(oneLine, width, Ellipsis)
		return []string{snipped}
	}

	if tableOpts.AllowLinebreaks {
		// Split on explicit newlines first, then wrap each segment
		// individually so intentional line breaks are preserved.
		segments := strings.Split(content, "\n")
		var lines []string
		for _, seg := range segments {
			var wrapped string
			if tableOpts.WhitespaceWrap {
				wrapped = text.WrapSoft(seg, width)
			} else {
				wrapped = text.WrapHard(seg, width)
			}
			for _, line := range strings.Split(wrapped, "\n") {
				if text.StringWidthWithoutEscSequences(line) > width {
					line = text.Snip(line, width, Ellipsis)
				}
				lines = append(lines, line)
			}
		}

		return lines
	}

	return []string{content}
}

func applyCellStyle(content string, style CellStyle) string {
	hasColor := style.FgColor != 0 || style.BgColor != 0
	if !hasColor && !style.Bold && !style.Italic {
		return content
	}

	colors := text.Colors{}

	if style.Bold {
		colors = append(colors, text.Bold)
	}
	if style.Italic {
		colors = append(colors, text.Italic)
	}
	if style.FgColor != 0 {
		colors = append(colors, style.FgColor)
	}
	if style.BgColor != 0 {
		colors = append(colors, style.BgColor)
	}

	return colors.Sprint(content)
}

func applyAlignment(content string, width int, align TextAlign) string {
	contentWidth := text.StringWidthWithoutEscSequences(content)
	if contentWidth >= width {
		return content
	}

	switch align {
	case AlignLeft:
		return text.AlignLeft.Apply(content, width)
	case AlignCenter:
		return text.AlignCenter.Apply(content, width)
	case AlignRight:
		return text.AlignRight.Apply(content, width)
	default:
		return text.AlignLeft.Apply(content, width)
	}
}

func padLine(width int) string {
	return strings.Repeat(" ", width)
}
