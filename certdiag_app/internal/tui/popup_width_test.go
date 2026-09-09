package tui

import (
	"unicode/utf8"

	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestPopupPadToWidthPadsMultibyte(t *testing.T) {
	s := "café"
	out := popupPadToWidth(s, 10)
	if lipgloss.Width(out) != 10 {
		t.Fatalf("expected display width 10, got %d (%q)", lipgloss.Width(out), out)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("output is not valid UTF-8: %q", out)
	}
}

func TestPopupPadToWidthTruncatesMultibyte(t *testing.T) {
	s := "日本語テスト"
	out := popupPadToWidth(s, 6)
	if lipgloss.Width(out) != 6 {
		t.Fatalf("expected display width 6, got %d (%q)", lipgloss.Width(out), out)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("truncation cut mid-rune, invalid UTF-8: %q", out)
	}
}

func TestPopupPadToWidthKeepsAnsiIntact(t *testing.T) {
	s := "\x1b[31mredtext\x1b[0m"
	out := popupPadToWidth(s, 4)
	if lipgloss.Width(out) != 4 {
		t.Fatalf("expected display width 4, got %d (%q)", lipgloss.Width(out), out)
	}
	if !utf8.ValidString(out) {
		t.Fatalf("output is not valid UTF-8: %q", out)
	}
	if lipgloss.Width(out+"x") != 5 {
		t.Fatalf("ANSI escape appears broken: %q", out)
	}
}

func TestWrapWordsMultibyteByDisplayWidth(t *testing.T) {
	lines := wrapWords("日本 語 テスト ネット", 6)
	for _, l := range lines {
		if lipgloss.Width(l) > 6 {
			t.Fatalf("line exceeds display width 6: %q (%d)", l, lipgloss.Width(l))
		}
		if !utf8.ValidString(l) {
			t.Fatalf("wrap split a rune, invalid UTF-8: %q", l)
		}
	}
}

func TestPopupWidthASCIIRegression(t *testing.T) {
	if got := popupPadToWidth("hi", 5); got != "hi   " {
		t.Fatalf("ASCII pad regression: %q", got)
	}
	if got := popupPadToWidth("hello world", 5); got != "hello" {
		t.Fatalf("ASCII truncate regression: %q", got)
	}
	lines := wrapWords("the quick brown fox", 9)
	want := []string{"the quick", "brown fox"}
	if len(lines) != len(want) {
		t.Fatalf("ASCII wrap regression: %v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("ASCII wrap regression at %d: got %q want %q", i, lines[i], want[i])
		}
	}
}
