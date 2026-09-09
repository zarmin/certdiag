package output

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestHighlightMatches_NoColor(t *testing.T) {
	disableColors(t)

	t.Run("empty query", func(t *testing.T) {
		got := HighlightMatches("hello world", "")
		if got != "hello world" {
			t.Errorf("got %q, want unchanged", got)
		}
	})

	t.Run("non-empty query returns unchanged", func(t *testing.T) {
		got := HighlightMatches("hello world", "hello")
		if got != "hello world" {
			t.Errorf("got %q, want unchanged when colors disabled", got)
		}
	})

	t.Run("no match returns unchanged", func(t *testing.T) {
		got := HighlightMatches("hello world", "xyz")
		if got != "hello world" {
			t.Errorf("got %q, want unchanged", got)
		}
	})
}

func TestHighlightMatches_WithColor(t *testing.T) {
	oldEnabled := ColorsEnabled
	oldNoColor := color.NoColor
	ColorsEnabled = true
	color.NoColor = false
	t.Cleanup(func() {
		ColorsEnabled = oldEnabled
		color.NoColor = oldNoColor
	})

	t.Run("empty query unchanged", func(t *testing.T) {
		got := HighlightMatches("hello world", "")
		if got != "hello world" {
			t.Errorf("got %q, want unchanged", got)
		}
	})

	t.Run("single match adds ANSI", func(t *testing.T) {
		input := "hello world"
		got := HighlightMatches(input, "hello")
		if len(got) <= len(input) {
			t.Error("highlighted output should be longer than input (ANSI added)")
		}
		if !strings.Contains(got, "\x1b[") {
			t.Error("highlighted output should contain ANSI codes")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		got := HighlightMatches("Hello World", "hello")
		if !strings.Contains(got, "\x1b[") {
			t.Error("should match case-insensitively")
		}
	})

	t.Run("multiple matches", func(t *testing.T) {
		got := HighlightMatches("test test test", "test")
		count := strings.Count(got, "\x1b[")
		if count < 3 {
			t.Errorf("expected at least 3 ANSI sequences for 3 matches, got %d", count)
		}
	})

	t.Run("no match unchanged", func(t *testing.T) {
		got := HighlightMatches("hello world", "xyz")
		if got != "hello world" {
			t.Errorf("got %q, want unchanged when no match", got)
		}
	})
}

func TestHighlightMatches_Unicode(t *testing.T) {
	oldEnabled := ColorsEnabled
	oldNoColor := color.NoColor
	ColorsEnabled = true
	color.NoColor = false
	t.Cleanup(func() {
		ColorsEnabled = oldEnabled
		color.NoColor = oldNoColor
	})

	cases := []struct {
		name  string
		text  string
		query string
	}{
		{"lowercase longer than original", "Ⱥ", "ⱥ"},
		{"lowercase shorter than original", "İ", "i"},
		{"multibyte prefix around match", "héllo", "LLO"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HighlightMatches(tc.text, tc.query)
			if !strings.Contains(got, "\x1b[") {
				t.Errorf("expected highlight ANSI codes, got %q", got)
			}
			stripped := ansiEscapePattern.ReplaceAllString(got, "")
			if stripped != tc.text {
				t.Errorf("original text corrupted: got %q, want %q", stripped, tc.text)
			}
		})
	}
}

func TestSplitByANSI(t *testing.T) {
	t.Run("no ANSI", func(t *testing.T) {
		segs := splitByANSI("plain text")
		if len(segs) != 1 {
			t.Fatalf("expected 1 segment, got %d", len(segs))
		}
		if segs[0].isANSI || segs[0].text != "plain text" {
			t.Errorf("expected text segment 'plain text', got %+v", segs[0])
		}
	})

	t.Run("ANSI only", func(t *testing.T) {
		segs := splitByANSI("\x1b[31m")
		if len(segs) != 1 {
			t.Fatalf("expected 1 segment, got %d", len(segs))
		}
		if !segs[0].isANSI {
			t.Error("expected ANSI segment")
		}
	})

	t.Run("mixed", func(t *testing.T) {
		segs := splitByANSI("hello\x1b[31mworld\x1b[0m")
		if len(segs) != 4 {
			t.Fatalf("expected 4 segments, got %d", len(segs))
		}
		if segs[0].isANSI || segs[0].text != "hello" {
			t.Errorf("seg[0]: %+v", segs[0])
		}
		if !segs[1].isANSI {
			t.Errorf("seg[1]: expected ANSI")
		}
		if segs[2].isANSI || segs[2].text != "world" {
			t.Errorf("seg[2]: %+v", segs[2])
		}
		if !segs[3].isANSI {
			t.Errorf("seg[3]: expected ANSI")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		segs := splitByANSI("")
		if len(segs) != 0 {
			t.Errorf("expected 0 segments, got %d", len(segs))
		}
	})
}
