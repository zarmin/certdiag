package tui

import (
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
)

func TestTruncStrASCII(t *testing.T) {
	if got := truncStr("abc", 10); got != "abc" {
		t.Fatalf("in-bounds ASCII: got %q, want %q", got, "abc")
	}
	if got := truncStr("abcdefg", 4); got != "abc~" {
		t.Fatalf("truncated ASCII: got %q, want %q", got, "abc~")
	}
	if got := truncStr("abcd", 4); got != "abcd" {
		t.Fatalf("exact-fit ASCII: got %q, want %q", got, "abcd")
	}
}

func TestTruncStrMultibyteNoMidRuneCut(t *testing.T) {
	s := "日本語のテキストです"
	got := truncStr(s, 6)
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if w := ansi.StringWidth(got); w > 6 {
		t.Fatalf("display width %d exceeds max 6: %q", w, got)
	}
}
