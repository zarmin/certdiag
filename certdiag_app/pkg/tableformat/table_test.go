package tableformat

import (
	"bytes"
	"testing"
)

func TestNew_Defaults(t *testing.T) {
	tb := New()
	if tb.Options.FixWidth != 160 {
		t.Errorf("FixWidth = %d, want 160", tb.Options.FixWidth)
	}
	if !tb.Options.AllowLinebreaks {
		t.Error("AllowLinebreaks should be true")
	}
	if !tb.Options.DisplayHeaders {
		t.Error("DisplayHeaders should be true")
	}
	if !tb.Options.WhitespaceWrap {
		t.Error("WhitespaceWrap should be true")
	}
	if tb.Options.DefaultAlignment != AlignLeft {
		t.Errorf("DefaultAlignment = %d, want AlignLeft", tb.Options.DefaultAlignment)
	}
	if tb.Options.AutoDetect {
		t.Error("AutoDetect should be false")
	}
	if tb.Options.Compact {
		t.Error("Compact should be false")
	}
	if tb.Options.RowSeparators {
		t.Error("RowSeparators should be false")
	}
	if len(tb.Headers) != 0 {
		t.Errorf("Headers should be empty, got %v", tb.Headers)
	}
	if len(tb.Columns) != 0 {
		t.Errorf("Columns should be empty, got %v", tb.Columns)
	}
}

func TestNew_WithOptions(t *testing.T) {
	tb := New(WithWidth(80), WithCompact(true), WithRowSeparators(true))
	if tb.Options.FixWidth != 80 {
		t.Errorf("FixWidth = %d, want 80", tb.Options.FixWidth)
	}
	if !tb.Options.Compact {
		t.Error("Compact should be true")
	}
	if !tb.Options.RowSeparators {
		t.Error("RowSeparators should be true")
	}
}

func TestNew_OptionOverride(t *testing.T) {
	tb := New(WithWidth(80), WithWidth(120))
	if tb.Options.FixWidth != 120 {
		t.Errorf("FixWidth = %d, want 120 (last wins)", tb.Options.FixWidth)
	}
}

func TestSetHeaders(t *testing.T) {
	tb := New()
	ret := tb.SetHeaders("A", "B", "C")
	if ret != tb {
		t.Error("SetHeaders should return *Table for chaining")
	}
	if len(tb.Headers) != 3 {
		t.Errorf("len(Headers) = %d, want 3", len(tb.Headers))
	}
	if tb.Headers[0] != "A" || tb.Headers[1] != "B" || tb.Headers[2] != "C" {
		t.Errorf("Headers = %v, want [A B C]", tb.Headers)
	}
}

func TestSetHeaders_Empty(t *testing.T) {
	tb := New()
	tb.SetHeaders()
	if len(tb.Headers) != 0 {
		t.Errorf("len(Headers) = %d, want 0", len(tb.Headers))
	}
}

func TestAddColumn(t *testing.T) {
	tb := New()
	ret := tb.AddColumn("Name")
	if ret != tb {
		t.Error("AddColumn should return *Table for chaining")
	}
	if len(tb.Columns) != 1 {
		t.Fatalf("len(Columns) = %d, want 1", len(tb.Columns))
	}
	if tb.Columns[0].Name != "Name" {
		t.Errorf("Name = %q, want %q", tb.Columns[0].Name, "Name")
	}
	if tb.Columns[0].Alignment != AlignLeft {
		t.Errorf("Alignment = %d, want AlignLeft", tb.Columns[0].Alignment)
	}
}

func TestAddColumn_WithOptions(t *testing.T) {
	tb := New()
	tb.AddColumn("Age", ColFixWidth(10), ColAlign(AlignRight))
	if tb.Columns[0].FixWidth != 10 {
		t.Errorf("FixWidth = %d, want 10", tb.Columns[0].FixWidth)
	}
	if tb.Columns[0].Alignment != AlignRight {
		t.Errorf("Alignment = %d, want AlignRight", tb.Columns[0].Alignment)
	}
	if !tb.Columns[0].HasAlignment {
		t.Error("HasAlignment should be true")
	}
}

func TestAddRow(t *testing.T) {
	tb := New()
	tb.AddColumn("A")
	ret := tb.AddRow("hello", 42, 3.14, true)
	if ret != tb {
		t.Error("AddRow should return *Table for chaining")
	}
}

func TestAddRow_WithTableCell(t *testing.T) {
	tb := New()
	tb.AddColumn("A")
	tb.AddRow(CellBold(Cell("styled")))
}

func TestRender(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("Name")
	tb.AddColumn("Age")
	tb.SetHeaders("Name", "Age")
	tb.AddRow("Alice", 30)

	var buf bytes.Buffer
	err := tb.Render(&buf)
	if err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Render produced empty output")
	}
}

func TestString_Success(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("A")
	tb.AddRow("hello")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("String() error: %v", err)
	}
	if s == "" {
		t.Error("String() returned empty")
	}
}

func TestString_Error(t *testing.T) {
	tb := New()
	s, err := tb.String()
	if err == nil {
		t.Error("expected error for no columns")
	}
	if s != "" {
		t.Errorf("expected empty string on error, got %q", s)
	}
}

func TestDisplay(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("A")
	tb.AddRow("hello")
	err := tb.Display()
	if err != nil {
		t.Fatalf("Display() error: %v", err)
	}
}

func TestChaining(t *testing.T) {
	tb := New(WithWidth(80)).
		SetHeaders("Name", "Value").
		AddColumn("Name").
		AddColumn("Value").
		AddRow("a", "b").
		AddRow("c", "d")

	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if s == "" {
		t.Error("empty output")
	}
}
