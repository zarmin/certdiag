package tableformat

import (
	"testing"

	"github.com/jedib0t/go-pretty/v6/text"
)

func TestCell(t *testing.T) {
	tests := []struct {
		name        string
		args        []interface{}
		wantContent string
	}{
		{"no args", nil, ""},
		{"single string", []interface{}{"hello"}, "hello"},
		{"single int", []interface{}{42}, "42"},
		{"multiple args", []interface{}{"a", "b", 1}, "ab1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Cell(tt.args...)
			if c.Content != tt.wantContent {
				t.Errorf("Content = %q, want %q", c.Content, tt.wantContent)
			}
			if c.Style != (CellStyle{}) {
				t.Errorf("Style should be zero value, got %+v", c.Style)
			}
		})
	}
}

func TestCellBold(t *testing.T) {
	c := CellBold(Cell("test"))
	if !c.Style.Bold {
		t.Error("Bold should be true")
	}
	if c.Content != "test" {
		t.Errorf("Content = %q, want %q", c.Content, "test")
	}
}

func TestCellItalic(t *testing.T) {
	c := CellItalic(Cell("test"))
	if !c.Style.Italic {
		t.Error("Italic should be true")
	}
}

func TestCellFg(t *testing.T) {
	fn := CellFg(text.FgRed)
	c := fn(Cell("test"))
	if c.Style.FgColor != text.FgRed {
		t.Errorf("FgColor = %v, want %v", c.Style.FgColor, text.FgRed)
	}
}

func TestCellBg(t *testing.T) {
	fn := CellBg(text.BgBlue)
	c := fn(Cell("test"))
	if c.Style.BgColor != text.BgBlue {
		t.Errorf("BgColor = %v, want %v", c.Style.BgColor, text.BgBlue)
	}
}

func TestCellAlign(t *testing.T) {
	fn := CellAlign(AlignRight)
	c := fn(Cell("test"))
	if c.Style.Alignment != AlignRight {
		t.Errorf("Alignment = %v, want %v", c.Style.Alignment, AlignRight)
	}
	if !c.Style.HasAlign {
		t.Error("HasAlign should be true")
	}
}

func TestCellComposition(t *testing.T) {
	c := CellFg(Green)(CellBold(CellItalic(Cell("x"))))
	if c.Content != "x" {
		t.Errorf("Content = %q, want %q", c.Content, "x")
	}
	if !c.Style.Bold {
		t.Error("Bold should be true")
	}
	if !c.Style.Italic {
		t.Error("Italic should be true")
	}
	if c.Style.FgColor != Green {
		t.Errorf("FgColor = %v, want %v", c.Style.FgColor, Green)
	}
}
