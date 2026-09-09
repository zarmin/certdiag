package tableformat

import "testing"

func TestDefaultBoxChars(t *testing.T) {
	fields := []struct {
		name  string
		value string
	}{
		{"TopLeft", DefaultBoxChars.TopLeft},
		{"TopRight", DefaultBoxChars.TopRight},
		{"BottomLeft", DefaultBoxChars.BottomLeft},
		{"BottomRight", DefaultBoxChars.BottomRight},
		{"LeftEdge", DefaultBoxChars.LeftEdge},
		{"RightEdge", DefaultBoxChars.RightEdge},
		{"TopEdge", DefaultBoxChars.TopEdge},
		{"BottomEdge", DefaultBoxChars.BottomEdge},
		{"Cross", DefaultBoxChars.Cross},
		{"Horizontal", DefaultBoxChars.Horizontal},
		{"Vertical", DefaultBoxChars.Vertical},
	}
	for _, f := range fields {
		if f.value == "" {
			t.Errorf("DefaultBoxChars.%s is empty", f.name)
		}
	}
}

func TestColorAliases(t *testing.T) {
	colors := []struct {
		name  string
		value interface{}
	}{
		{"Bold", Bold},
		{"Italic", Italic},
		{"Red", Red},
		{"Green", Green},
		{"Yellow", Yellow},
		{"Blue", Blue},
		{"Magenta", Magenta},
		{"Cyan", Cyan},
		{"White", White},
		{"BgRed", BgRed},
		{"BgGreen", BgGreen},
		{"BgYellow", BgYellow},
		{"BgBlue", BgBlue},
		{"BgMagenta", BgMagenta},
		{"BgCyan", BgCyan},
		{"BgWhite", BgWhite},
	}
	for _, c := range colors {
		if c.value == 0 {
			t.Errorf("%s is zero", c.name)
		}
	}
}

func TestEllipsis(t *testing.T) {
	if Ellipsis != "\u2026" {
		t.Errorf("Ellipsis = %q, want %q", Ellipsis, "\u2026")
	}
}
