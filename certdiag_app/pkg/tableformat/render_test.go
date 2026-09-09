package tableformat

import (
	"strings"
	"testing"
)

func TestRender_NoColumns(t *testing.T) {
	tb := New()
	_, err := tb.String()
	if err == nil {
		t.Error("expected error for no columns")
	}
}

func TestRender_CalculateWidthsError(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidth(10), ColFixWidthPercent(50))
	_, err := tb.String()
	if err == nil {
		t.Error("expected error from calculateWidths")
	}
}

func TestRender_HeadersDisplayed(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("Name")
	tb.SetHeaders("Name")
	tb.AddRow("Alice")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(s, "Name") {
		t.Errorf("output should contain header 'Name', got:\n%s", s)
	}
}

func TestRender_HeadersNotDisplayed(t *testing.T) {
	tb := New(WithWidth(60), WithDisplayHeaders(false))
	tb.AddColumn("Name")
	tb.SetHeaders("Name")
	tb.AddRow("Alice")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.Contains(s, DefaultBoxChars.LeftEdge) {
		t.Errorf("output should not contain header separator, got:\n%s", s)
	}
}

func TestRender_HeadersFewerThanColumns(t *testing.T) {
	tb := New(WithWidth(80))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.SetHeaders("OnlyOne")
	tb.AddRow("a", "b", "c")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if s == "" {
		t.Error("empty output")
	}
}

func TestRender_HeadersMoreThanColumns(t *testing.T) {
	tb := New(WithWidth(80))
	tb.AddColumn("A")
	tb.SetHeaders("One", "Two", "Three")
	tb.AddRow("a")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if s == "" {
		t.Error("empty output")
	}
}

func TestRender_RowWithTableCell(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("A")
	tb.AddRow(CellBold(CellFg(Green)(Cell("styled"))))
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(s, "styled") {
		t.Errorf("output should contain 'styled', got:\n%s", s)
	}
}

func TestRender_RowWithDefaultValues(t *testing.T) {
	tb := New(WithWidth(60))
	tb.AddColumn("A")
	tb.AddRow(42)
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(s, "42") {
		t.Errorf("output should contain '42', got:\n%s", s)
	}
}

func TestRender_RowShorterThanColumns(t *testing.T) {
	tb := New(WithWidth(80))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddRow("only one")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if s == "" {
		t.Error("empty output")
	}
}

func TestRender_AlignmentPriority(t *testing.T) {
	tb := New(WithWidth(80), WithDefaultAlignment(AlignLeft))
	tb.AddColumn("A", ColAlign(AlignCenter))
	tb.AddRow(CellAlign(AlignRight)(Cell("test")))
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(s, "test") {
		t.Error("output should contain 'test'")
	}
}

func TestRender_MultilinePadding(t *testing.T) {
	tb := New(WithWidth(30), WithAllowLinebreaks(true), WithWhitespaceWrap(false), WithDisplayHeaders(false))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddRow(strings.Repeat("x", 40), "short")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	lines := strings.Split(s, "\n")
	if len(lines) < 5 {
		t.Errorf("expected multiline output, got %d lines:\n%s", len(lines), s)
	}
}

func TestRender_RowSeparators(t *testing.T) {
	tb := New(WithWidth(60), WithRowSeparators(true), WithDisplayHeaders(false))
	tb.AddColumn("A")
	tb.AddRow("row1")
	tb.AddRow("row2")
	tb.AddRow("row3")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	sepCount := strings.Count(s, DefaultBoxChars.LeftEdge)
	if sepCount < 2 {
		t.Errorf("expected at least 2 row separators, got %d in:\n%s", sepCount, s)
	}
}

func TestRender_NoRowSeparators(t *testing.T) {
	tb := New(WithWidth(60), WithRowSeparators(false), WithDisplayHeaders(false))
	tb.AddColumn("A")
	tb.AddRow("row1")
	tb.AddRow("row2")
	s, err := tb.String()
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.Contains(s, DefaultBoxChars.LeftEdge) {
		t.Errorf("should not contain row separators, got:\n%s", s)
	}
}

func TestBuildTopBorder(t *testing.T) {
	t.Run("non-compact single col", func(t *testing.T) {
		s := buildTopBorder([]int{10}, false)
		if !strings.Contains(s, DefaultBoxChars.TopLeft) {
			t.Error("missing TopLeft")
		}
		if !strings.Contains(s, DefaultBoxChars.TopRight) {
			t.Error("missing TopRight")
		}
		if strings.Contains(s, DefaultBoxChars.TopEdge) {
			t.Error("single col should not have TopEdge")
		}
	})
	t.Run("non-compact multi col", func(t *testing.T) {
		s := buildTopBorder([]int{5, 5, 5}, false)
		if !strings.Contains(s, DefaultBoxChars.TopEdge) {
			t.Error("missing TopEdge for multi col")
		}
	})
	t.Run("compact", func(t *testing.T) {
		s := buildTopBorder([]int{5}, true)
		if !strings.Contains(s, DefaultBoxChars.TopLeft) {
			t.Error("missing TopLeft in compact")
		}
	})
}

func TestBuildHeaderSeparator(t *testing.T) {
	s := buildHeaderSeparator([]int{10, 10}, false)
	if !strings.Contains(s, DefaultBoxChars.LeftEdge) {
		t.Error("missing LeftEdge")
	}
	if !strings.Contains(s, DefaultBoxChars.Cross) {
		t.Error("missing Cross")
	}
	if !strings.Contains(s, DefaultBoxChars.RightEdge) {
		t.Error("missing RightEdge")
	}
}

func TestBuildRowSeparator(t *testing.T) {
	s1 := buildRowSeparator([]int{10, 10}, false)
	s2 := buildHeaderSeparator([]int{10, 10}, false)
	if s1 != s2 {
		t.Error("buildRowSeparator should equal buildHeaderSeparator")
	}
}

func TestBuildBottomBorder(t *testing.T) {
	s := buildBottomBorder([]int{10, 10}, false)
	if !strings.Contains(s, DefaultBoxChars.BottomLeft) {
		t.Error("missing BottomLeft")
	}
	if !strings.Contains(s, DefaultBoxChars.BottomEdge) {
		t.Error("missing BottomEdge")
	}
	if !strings.Contains(s, DefaultBoxChars.BottomRight) {
		t.Error("missing BottomRight")
	}
}

func TestBuildContentLine(t *testing.T) {
	t.Run("non-compact", func(t *testing.T) {
		s := buildContentLine([]string{"hello", "world"}, []int{10, 10}, false)
		if !strings.Contains(s, " hello ") {
			t.Errorf("non-compact should have padding, got %q", s)
		}
	})
	t.Run("compact", func(t *testing.T) {
		s := buildContentLine([]string{"hello", "world"}, []int{10, 10}, true)
		if strings.Contains(s, " hello ") {
			t.Errorf("compact should not have extra padding, got %q", s)
		}
		if !strings.Contains(s, "hello") {
			t.Errorf("compact should still contain content, got %q", s)
		}
	})
}
