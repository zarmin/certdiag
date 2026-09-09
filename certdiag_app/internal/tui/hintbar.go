package tui

import (
	"strings"
)

type Hint struct {
	Key   string
	Label string
}

type StatusHint struct {
	Text string
}

// RenderHintBar renders the footer on one row. Hints are listed in priority
// order: when the row is too narrow the body is trimmed from the end, while the
// closing hints (?, q, Esc) and the status texts are kept, so the way out and
// the way to the full key list (? opens it) are always visible. Only when even
// those do not fit does the bar wrap.
func RenderHintBar(width int, hints []Hint, status ...StatusHint) (string, int) {
	parts := formatParts(fitHints(width, hints, status), status)
	wrapped := wrapHints(parts, width)
	rendered := styleInfoBar.Render(wrapped)
	height := strings.Count(rendered, "\n") + 1
	return rendered, height
}

func FormatHints(hints ...Hint) string {
	var parts []string
	for _, h := range hints {
		parts = append(parts, formatHint(h))
	}
	return strings.Join(parts, "  ")
}

func formatHint(h Hint) string {
	if h.Key == "" {
		return h.Label
	}
	return "[" + h.Key + "] " + h.Label
}

func formatParts(hints []Hint, status []StatusHint) []string {
	var parts []string
	for _, h := range hints {
		parts = append(parts, formatHint(h))
	}
	for _, s := range status {
		parts = append(parts, "| "+s.Text)
	}
	return parts
}

// isTailHint reports whether a hint belongs to the fixed tail of the bar.
func isTailHint(h Hint) bool {
	switch h.Key {
	case "?", "q", "Esc", "Esc/q":
		return true
	}
	return false
}

// fitHints drops body hints from the end until the row fits width, keeping the
// tail and the status texts. It returns the tail alone when nothing else fits.
func fitHints(width int, hints []Hint, status []StatusHint) []Hint {
	if width <= 0 {
		return hints
	}
	tailStart := len(hints)
	for tailStart > 0 && isTailHint(hints[tailStart-1]) {
		tailStart--
	}
	body, tail := hints[:tailStart], hints[tailStart:]
	for len(body) > 0 {
		candidate := append(append([]Hint{}, body...), tail...)
		if hintsFit(width, candidate, status) {
			return candidate
		}
		body = body[:len(body)-1]
	}
	return tail
}

func hintsFit(width int, hints []Hint, status []StatusHint) bool {
	return runeWidth(" "+strings.Join(formatParts(hints, status), "  ")) <= width
}

func wrapHints(hints []string, width int) string {
	sep := "  "
	single := " " + strings.Join(hints, sep)
	if width <= 0 || runeWidth(single) <= width {
		return single
	}

	var lines []string
	cur := " " + hints[0]
	for _, h := range hints[1:] {
		candidate := cur + sep + h
		if runeWidth(candidate) > width {
			lines = append(lines, cur)
			cur = " " + h
		} else {
			cur = candidate
		}
	}
	lines = append(lines, cur)
	return strings.Join(lines, "\n")
}
