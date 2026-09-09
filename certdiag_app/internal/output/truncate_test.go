package output

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateRuneSafe(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"ascii short", "hello", 10, "hello"},
		{"ascii truncated", "hello world", 8, "hello..."},
		{"ascii exact", "hello", 5, "hello"},
		{"max0", "héllo", 0, ""},
		{"max1", "héllo", 1, "h"},
		{"max2", "héllo", 2, "hé"},
		{"max3", "héllo", 3, "hél"},
		{"multibyte boundary", "áéíóúñ", 5, "áé..."},
	}

	for _, tt := range tests {
		got := truncate(tt.in, tt.max)
		if got != tt.want {
			t.Errorf("%s: truncate(%q, %d) = %q, want %q", tt.name, tt.in, tt.max, got, tt.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: truncate(%q, %d) = %q is not valid UTF-8", tt.name, tt.in, tt.max, got)
		}
		if utf8.RuneCountInString(got) > tt.max && tt.max > 0 {
			t.Errorf("%s: truncate(%q, %d) = %q exceeds max %d runes", tt.name, tt.in, tt.max, got, tt.max)
		}
	}
}
