package filepicker

import (
	"strings"
	"testing"
)

func TestPadToWidth(t *testing.T) {
	// Shorter than width - should be padded
	got := padToWidth("abc", 6)
	if len(got) != 6 {
		t.Errorf("padToWidth short: got len %d, want 6", len(got))
	}
	if !strings.HasPrefix(got, "abc") {
		t.Errorf("padToWidth short: got %q, should start with 'abc'", got)
	}

	// Exact width
	got = padToWidth("abc", 3)
	if got != "abc" {
		t.Errorf("padToWidth exact: got %q, want %q", got, "abc")
	}

	// Longer than width - should be truncated
	got = padToWidth("abcdefghij", 5)
	if len(got) > 5+len("…") {
		t.Errorf("padToWidth long: visible width should be <= 5, got %q", got)
	}

	// Empty string
	got = padToWidth("", 5)
	if len(got) != 5 {
		t.Errorf("padToWidth empty: got len %d, want 5", len(got))
	}
}

func TestTruncateToWidth(t *testing.T) {
	// Short (unchanged)
	got := truncateToWidth("abc", 10)
	if got != "abc" {
		t.Errorf("short: got %q, want %q", got, "abc")
	}

	// Exact width
	got = truncateToWidth("abcde", 5)
	if got != "abcde" {
		t.Errorf("exact: got %q, want %q", got, "abcde")
	}

	// Over width (truncated with ellipsis)
	got = truncateToWidth("abcdefghij", 5)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("over: got %q, should end with ellipsis", got)
	}

	// w=0 returns empty
	got = truncateToWidth("abc", 0)
	if got != "" {
		t.Errorf("w=0: got %q, want empty", got)
	}

	// w=1 returns just ellipsis
	got = truncateToWidth("abcdefg", 1)
	if got != "…" {
		t.Errorf("w=1: got %q, want %q", got, "…")
	}
}

func TestWrapText(t *testing.T) {
	// Short fits in one line
	lines := wrapText("hello world", 40)
	if len(lines) != 1 || lines[0] != "hello world" {
		t.Errorf("short: got %v", lines)
	}

	// Wraps at word boundary
	lines = wrapText("one two three four five", 10)
	if len(lines) < 2 {
		t.Errorf("wrap: expected multiple lines, got %v", lines)
	}
	for _, l := range lines {
		if len(l) > 10 && !strings.Contains(l, " ") {
			// Single words longer than maxW are OK
			continue
		}
	}

	// Single long word (doesn't break mid-word)
	lines = wrapText("superlongword", 5)
	if len(lines) != 1 || lines[0] != "superlongword" {
		t.Errorf("long word: got %v", lines)
	}

	// Empty string
	lines = wrapText("", 40)
	if len(lines) != 1 || lines[0] != "" {
		t.Errorf("empty: got %v, want [\"\"]", lines)
	}

	// Exactly at boundary
	lines = wrapText("abc def", 7)
	if len(lines) != 1 {
		t.Errorf("boundary: got %v, want single line", lines)
	}
}

func TestBoxDrawing(t *testing.T) {
	w := 20

	top := boxTop(w)
	if !strings.HasPrefix(top, "╭") || !strings.HasSuffix(top, "╮") {
		t.Errorf("boxTop: got %q", top)
	}
	if !strings.Contains(top, strings.Repeat("─", w-2)) {
		t.Errorf("boxTop: wrong width")
	}

	bottom := boxBottom(w)
	if !strings.HasPrefix(bottom, "╰") || !strings.HasSuffix(bottom, "╯") {
		t.Errorf("boxBottom: got %q", bottom)
	}

	sep := boxSep(w)
	if !strings.HasPrefix(sep, "├") || !strings.HasSuffix(sep, "┤") {
		t.Errorf("boxSep: got %q", sep)
	}
}

func TestRenderCheckbox(t *testing.T) {
	// Unchecked, unfocused
	got := renderCheckbox(false, false)
	if got != "[ ]" {
		t.Errorf("unchecked unfocused: got %q, want %q", got, "[ ]")
	}

	// Checked, unfocused
	got = renderCheckbox(true, false)
	if got != "[x]" {
		t.Errorf("checked unfocused: got %q, want %q", got, "[x]")
	}
}
