package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func hscrollTestCols() colWidths {
	return colWidths{
		filename: 0,
		ctype:    4,
		opt:      map[string]int{"expiry": 10},
		active:   []string{"expiry"},
	}
}

func plainHeaderCol(_ string, w int) string {
	return padOrTrunc("EXPIRES", w)
}

func styledExpiryCol(_ string, w int) string {
	val := "30d"
	styled := "\x1b[31m" + val + "\x1b[0m"
	return styled + strings.Repeat(" ", w-runeWidth(val))
}

func TestHScrollAlignsHeaderAndStyledRow(t *testing.T) {
	cols := hscrollTestCols()
	offset := 6

	plainHeader := hscrollSliceWithType(cols, "TYPE", plainHeaderCol, 0)
	plainRow := ansi.Strip(hscrollSliceWithType(cols, "cert", styledExpiryCol, 0))

	scrolledHeader := hscrollSliceWithType(cols, "TYPE", plainHeaderCol, offset)
	scrolledRow := hscrollSliceWithType(cols, "cert", styledExpiryCol, offset)

	wantHeader := string([]rune(plainHeader)[offset:])
	wantRow := string([]rune(plainRow)[offset:])

	if scrolledHeader != wantHeader {
		t.Fatalf("header scroll: got %q want %q", scrolledHeader, wantHeader)
	}
	if got := ansi.Strip(scrolledRow); got != wantRow {
		t.Fatalf("row scroll visible text: got %q want %q", got, wantRow)
	}
	if hw, rw := runeWidth(scrolledHeader), runeWidth(ansi.Strip(scrolledRow)); hw != rw {
		t.Fatalf("header and row dropped different visible widths: header=%d row=%d", hw, rw)
	}

	if !strings.Contains(scrolledRow, "\x1b[31m30d\x1b[0m") {
		t.Fatalf("styled expiry span not preserved intact: %q", scrolledRow)
	}
	if opens, resets := strings.Count(scrolledRow, "\x1b[31m"), strings.Count(scrolledRow, "\x1b[0m"); opens != resets {
		t.Fatalf("unbalanced escapes: opens=%d resets=%d in %q", opens, resets, scrolledRow)
	}
}

func TestHScrollZeroOffsetUnchanged(t *testing.T) {
	cols := hscrollTestCols()

	full := hscrollSliceWithType(cols, "cert", styledExpiryCol, 0)
	if !strings.Contains(full, "\x1b[31m30d\x1b[0m") {
		t.Fatalf("zero offset dropped styling: %q", full)
	}
	plainFull := hscrollSliceWithType(cols, "cert", func(_ string, w int) string {
		return padOrTrunc("30d", w)
	}, 0)
	if ansi.Strip(full) != plainFull {
		t.Fatalf("zero offset changed visible content: got %q want %q", ansi.Strip(full), plainFull)
	}
}

func TestHScrollMidColumnDoesNotBreakEscapes(t *testing.T) {
	cols := hscrollTestCols()
	offset := 8

	plainRow := ansi.Strip(hscrollSliceWithType(cols, "cert", styledExpiryCol, 0))
	scrolledRow := hscrollSliceWithType(cols, "cert", styledExpiryCol, offset)

	wantRow := string([]rune(plainRow)[offset:])
	if got := ansi.Strip(scrolledRow); got != wantRow {
		t.Fatalf("mid-column scroll visible text: got %q want %q", got, wantRow)
	}
	assertNoTruncatedEscape(t, scrolledRow)
}

func assertNoTruncatedEscape(t *testing.T, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b {
			continue
		}
		j := i
		for j < len(s) && s[j] != 'm' {
			j++
		}
		if j >= len(s) {
			t.Fatalf("truncated escape sequence at %d in %q", i, s)
		}
		i = j
	}
}
