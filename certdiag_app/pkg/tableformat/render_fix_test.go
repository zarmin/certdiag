package tableformat

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jedib0t/go-pretty/v6/text"
)

func lineWidths(out string) map[int]bool {
	w := map[int]bool{}
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		w[text.StringWidthWithoutEscSequences(l)] = true
	}
	return w
}

// TestRender_OverlongHeaderSnipped verifies an overlong header no longer
// misaligns the table (all rendered lines share one width).
func TestRender_OverlongHeaderSnipped(t *testing.T) {
	tbl := New()
	tbl.SetHeaders("THIS_IS_A_VERY_LONG_HEADER_NAME", "B")
	tbl.AddColumn("a", ColFixWidth(5))
	tbl.AddColumn("b", ColFixWidth(5))
	tbl.AddRow("x", "y")

	var sb strings.Builder
	if err := tbl.Render(&sb); err != nil {
		t.Fatal(err)
	}
	if w := lineWidths(sb.String()); len(w) != 1 {
		t.Errorf("inconsistent line widths %v - header not snipped to column width\n%s", keysOf(w), sb.String())
	}
}

// TestRender_NoWrapEmbeddedNewline verifies an embedded newline in a NoWrap cell
// no longer splits the row.
func TestRender_NoWrapEmbeddedNewline(t *testing.T) {
	tbl := New()
	tbl.SetHeaders("col1", "col2")
	tbl.AddColumn("a", ColNoWrap(), ColFixWidth(20))
	tbl.AddColumn("b", ColFixWidth(10))
	tbl.AddRow("line1\nline2", "ok")

	var sb strings.Builder
	if err := tbl.Render(&sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if strings.Contains(out, "line1\nline2") {
		t.Errorf("embedded newline survived into NoWrap cell:\n%s", out)
	}
	if w := lineWidths(out); len(w) != 1 {
		t.Errorf("inconsistent line widths %v - NoWrap cell split the row\n%s", keysOf(w), out)
	}
}

// TestTruncateAfter_Multibyte verifies TruncateAfter on a multibyte string just
// over the limit actually shortens the content and fits the target width,
// instead of appending the ellipsis with nothing removed (byte vs rune guard).
func TestTruncateAfter_Multibyte(t *testing.T) {
	const limit = 4
	col := ColumnConfig{TruncateAfter: limit}
	opts := TableOptions{AllowLinebreaks: true, WhitespaceWrap: true}

	got := processCellContent("áéíóú", &col, 20, &opts)
	if len(got) != 1 {
		t.Fatalf("expected 1 line, got %d: %q", len(got), got)
	}
	line := got[0]
	if w := text.StringWidthWithoutEscSequences(line); w > limit {
		t.Errorf("truncated width %d exceeds limit %d: %q", w, limit, line)
	}
	if !strings.HasSuffix(line, Ellipsis) {
		t.Errorf("expected ellipsis suffix, got %q", line)
	}
	body := strings.TrimSuffix(line, Ellipsis)
	if text.StringWidthWithoutEscSequences(body) >= text.StringWidthWithoutEscSequences("áéíóú") {
		t.Errorf("ellipsis appended but nothing removed: %q", line)
	}
}

// TestNaturalWidth_NoRuneOrAnsiSplit verifies natural-width estimation over
// TruncateAfter uses a width-aware slice, never a raw byte slice that would
// split a multibyte rune or an ANSI escape.
func TestNaturalWidth_NoRuneOrAnsiSplit(t *testing.T) {
	t.Run("multibyte", func(t *testing.T) {
		tb := New(WithWidth(0))
		tb.AddColumn("A", ColTruncateAfter(5))
		tb.AddRow("αβγδεζηθ")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatal(err)
		}
		if widths[0] != 5 {
			t.Errorf("natural width = %d, want 5", widths[0])
		}
		out, err := tb.String()
		if err != nil {
			t.Fatal(err)
		}
		if !utf8.ValidString(out) {
			t.Errorf("rendered output is not valid UTF-8:\n%q", out)
		}
	})
	t.Run("ansi", func(t *testing.T) {
		tb := New(WithWidth(0))
		tb.AddColumn("A", ColTruncateAfter(4))
		tb.AddRow("\x1b[31mRED\x1b[0m")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatal(err)
		}
		if widths[0] != 3 {
			t.Errorf("natural width = %d, want 3 (display width of RED)", widths[0])
		}
	})
}

// TestPercent100_FitsExactly verifies a 100%-width column renders exactly to the
// requested table width (closing border accounted for), not one column too wide.
func TestPercent100_FitsExactly(t *testing.T) {
	const width = 40
	tb := New(WithWidth(width))
	tb.AddColumn("A", ColFixWidthPercent(100))
	tb.AddRow("hello")

	var sb strings.Builder
	if err := tb.Render(&sb); err != nil {
		t.Fatal(err)
	}
	w := lineWidths(sb.String())
	if len(w) != 1 {
		t.Fatalf("inconsistent line widths %v\n%s", keysOf(w), sb.String())
	}
	if !w[width] {
		t.Errorf("rendered width %v, want %d\n%s", keysOf(w), width, sb.String())
	}
}

// TestPercentOverflow_Rejected verifies percent columns summing past 100%% are
// rejected instead of silently overflowing the table width.
func TestPercentOverflow_Rejected(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidthPercent(60))
	tb.AddColumn("B", ColFixWidthPercent(60))
	tb.AddRow("x", "y")
	assertErrorCode(t, validate(tb), ErrFixedWidthExceedsTable)
}

// TestNoWrapOverflow_Rejected verifies a NoWrap column whose content cannot fit
// the table width is rejected instead of silently overflowing.
func TestNoWrapOverflow_Rejected(t *testing.T) {
	tb := New(WithWidth(20))
	tb.AddColumn("A", ColNoWrap())
	tb.AddRow(strings.Repeat("x", 50))
	_, _, err := calculateWidths(tb)
	assertErrorCode(t, err, ErrNoWrapContentDoesNotFit)
}

// TestMinWidth_DoesNotExceedRequested verifies a column MinWidth larger than its
// share cannot push the total rendered width beyond the requested table width.
func TestMinWidth_DoesNotExceedRequested(t *testing.T) {
	const width = 20
	tb := New(WithWidth(width))
	tb.AddColumn("A", ColMinWidth(30))
	tb.AddRow("x")

	var sb strings.Builder
	if err := tb.Render(&sb); err != nil {
		t.Fatal(err)
	}
	for w := range lineWidths(sb.String()) {
		if w > width {
			t.Errorf("rendered line width %d exceeds requested %d\n%s", w, width, sb.String())
		}
	}
}

func keysOf(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	return out
}
