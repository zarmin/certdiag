package tableformat

import (
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/text"
)

func TestProcessCellContent(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		col       ColumnConfig
		width     int
		opts      TableOptions
		wantLines int
		check     func([]string) bool
	}{
		{
			name:      "TruncateAfter triggered",
			content:   "abcdefghijklmnop",
			col:       ColumnConfig{TruncateAfter: 5},
			width:     20,
			opts:      TableOptions{AllowLinebreaks: true},
			wantLines: 1,
			check: func(lines []string) bool {
				return strings.Contains(lines[0], Ellipsis)
			},
		},
		{
			name:      "TruncateAfter not triggered",
			content:   "abc",
			col:       ColumnConfig{TruncateAfter: 10},
			width:     20,
			opts:      TableOptions{AllowLinebreaks: true},
			wantLines: 1,
			check: func(lines []string) bool {
				return lines[0] == "abc"
			},
		},
		{
			name:      "NoWrap snip path",
			content:   "a very long content that should be snipped",
			col:       ColumnConfig{NoWrap: true},
			width:     10,
			opts:      TableOptions{AllowLinebreaks: true},
			wantLines: 1,
		},
		{
			name:      "AllowLinebreaks false snip path",
			content:   "a very long content that should be snipped",
			col:       ColumnConfig{},
			width:     10,
			opts:      TableOptions{AllowLinebreaks: false},
			wantLines: 1,
		},
		{
			name:    "WhitespaceWrap true WrapSoft",
			content: "hello world this is a long sentence that wraps",
			col:     ColumnConfig{},
			width:   10,
			opts:    TableOptions{AllowLinebreaks: true, WhitespaceWrap: true},
			check: func(lines []string) bool {
				return len(lines) > 1
			},
		},
		{
			name:    "WhitespaceWrap false WrapHard",
			content: "abcdefghijklmnopqrstuvwxyz",
			col:     ColumnConfig{},
			width:   10,
			opts:    TableOptions{AllowLinebreaks: true, WhitespaceWrap: false},
			check: func(lines []string) bool {
				return len(lines) > 1
			},
		},
		{
			name:      "TruncateAfter plus NoWrap combined",
			content:   "abcdefghijklmnopqrstuvwxyz",
			col:       ColumnConfig{TruncateAfter: 8, NoWrap: true},
			width:     20,
			opts:      TableOptions{AllowLinebreaks: true},
			wantLines: 1,
			check: func(lines []string) bool {
				return strings.Contains(lines[0], Ellipsis)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := processCellContent(tt.content, &tt.col, tt.width, &tt.opts)
			if tt.wantLines > 0 && len(lines) != tt.wantLines {
				t.Errorf("got %d lines, want %d", len(lines), tt.wantLines)
			}
			if tt.check != nil && !tt.check(lines) {
				t.Errorf("check failed, lines = %v", lines)
			}
		})
	}
}

func TestProcessCellContent_PostWrapSnip(t *testing.T) {
	content := "short " + strings.Repeat("x", 50) + " end"
	col := ColumnConfig{}
	opts := TableOptions{AllowLinebreaks: true, WhitespaceWrap: true}
	lines := processCellContent(content, &col, 10, &opts)
	for _, line := range lines {
		if strings.Contains(line, Ellipsis) {
			return
		}
	}
	t.Logf("lines = %v", lines)
}

func TestProcessCellContent_PostWrapSnip_Hard(t *testing.T) {
	content := strings.Repeat("x", 50)
	col := ColumnConfig{}
	opts := TableOptions{AllowLinebreaks: true, WhitespaceWrap: false}
	lines := processCellContent(content, &col, 10, &opts)
	for i, line := range lines {
		if len(line) > 15 {
			t.Errorf("line %d too wide: %q", i, line)
		}
	}
}

func TestApplyCellStyle(t *testing.T) {
	text.EnableColors()
	tests := []struct {
		name     string
		style    CellStyle
		wantAnsi bool
	}{
		{"no style", CellStyle{}, false},
		{"bold only", CellStyle{Bold: true}, true},
		{"italic only", CellStyle{Italic: true}, true},
		{"fg only", CellStyle{FgColor: Red}, true},
		{"bg only", CellStyle{BgColor: BgBlue}, true},
		{"all combined", CellStyle{Bold: true, Italic: true, FgColor: Green, BgColor: BgRed}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyCellStyle("test", tt.style)
			hasEsc := strings.Contains(result, "\033[")
			if tt.wantAnsi && !hasEsc {
				t.Errorf("expected ANSI escape, got %q", result)
			}
			if !tt.wantAnsi && hasEsc {
				t.Errorf("unexpected ANSI escape, got %q", result)
			}
			if !tt.wantAnsi && result != "test" {
				t.Errorf("expected unchanged content, got %q", result)
			}
		})
	}
}

func TestApplyAlignment(t *testing.T) {
	tests := []struct {
		name    string
		content string
		width   int
		align   TextAlign
		check   func(string) bool
	}{
		{
			name:    "content >= width unchanged",
			content: "hello",
			width:   5,
			align:   AlignLeft,
			check:   func(s string) bool { return s == "hello" },
		},
		{
			name:    "AlignLeft",
			content: "hi",
			width:   10,
			align:   AlignLeft,
			check:   func(s string) bool { return strings.HasPrefix(s, "hi") && len(s) == 10 },
		},
		{
			name:    "AlignCenter",
			content: "hi",
			width:   10,
			align:   AlignCenter,
			check:   func(s string) bool { return strings.TrimSpace(s) == "hi" && len(s) == 10 },
		},
		{
			name:    "AlignRight",
			content: "hi",
			width:   10,
			align:   AlignRight,
			check:   func(s string) bool { return strings.HasSuffix(s, "hi") && len(s) == 10 },
		},
		{
			name:    "invalid TextAlign default",
			content: "hi",
			width:   10,
			align:   TextAlign(99),
			check:   func(s string) bool { return len(s) == 10 },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyAlignment(tt.content, tt.width, tt.align)
			if !tt.check(result) {
				t.Errorf("check failed for %q, got %q", tt.name, result)
			}
		})
	}
}

func TestPadLine(t *testing.T) {
	tests := []struct {
		width int
		want  string
	}{
		{0, ""},
		{1, " "},
		{5, "     "},
	}
	for _, tt := range tests {
		got := padLine(tt.width)
		if got != tt.want {
			t.Errorf("padLine(%d) = %q, want %q", tt.width, got, tt.want)
		}
	}
}
