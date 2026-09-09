package tableformat

import "testing"

func TestCalculateOverhead(t *testing.T) {
	tests := []struct {
		name    string
		numCols int
		compact bool
		want    int
	}{
		{"compact 0 cols", 0, true, 1},
		{"compact 1 col", 1, true, 2},
		{"compact 3 cols", 3, true, 4},
		{"non-compact 0 cols", 0, false, 1},
		{"non-compact 1 col", 1, false, 4},
		{"non-compact 3 cols", 3, false, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateOverhead(tt.numCols, tt.compact)
			if got != tt.want {
				t.Errorf("calculateOverhead(%d, %v) = %d, want %d", tt.numCols, tt.compact, got, tt.want)
			}
		})
	}
}

func TestPerColOverhead(t *testing.T) {
	if got := perColOverhead(true); got != 1 {
		t.Errorf("perColOverhead(true) = %d, want 1", got)
	}
	if got := perColOverhead(false); got != 3 {
		t.Errorf("perColOverhead(false) = %d, want 3", got)
	}
}

func TestUsableFromPercent(t *testing.T) {
	tests := []struct {
		name    string
		percent float64
		width   int
		compact bool
		want    int
	}{
		{"tableWidth=0", 50, 0, false, 0},
		{"normal", 50, 100, false, 46},
		{"compact", 50, 100, true, 48},
		{"usable<1 clamped", 1, 10, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := usableFromPercent(tt.percent, tt.width, tt.compact)
			if got != tt.want {
				t.Errorf("usableFromPercent(%.1f, %d, %v) = %d, want %d", tt.percent, tt.width, tt.compact, got, tt.want)
			}
		})
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		name          string
		val, min, max int
		want          int
	}{
		{"val<min", 3, 5, 10, 5},
		{"val>max", 15, 5, 10, 10},
		{"pass-through", 7, 5, 10, 7},
		{"min=0 ignored", 3, 0, 10, 3},
		{"max=0 ignored", 15, 5, 0, 15},
		{"all zeros", 0, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clamp(tt.val, tt.min, tt.max)
			if got != tt.want {
				t.Errorf("clamp(%d, %d, %d) = %d, want %d", tt.val, tt.min, tt.max, got, tt.want)
			}
		})
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(3, 5) != 5 {
		t.Error("maxInt(3,5) should be 5")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
	if maxInt(4, 4) != 4 {
		t.Error("maxInt(4,4) should be 4")
	}
}

func TestMinInt(t *testing.T) {
	if minInt(3, 5) != 3 {
		t.Error("minInt(3,5) should be 3")
	}
	if minInt(5, 3) != 3 {
		t.Error("minInt(5,3) should be 3")
	}
	if minInt(4, 4) != 4 {
		t.Error("minInt(4,4) should be 4")
	}
}

func TestCalculateWidths_NoColumns(t *testing.T) {
	tb := New(WithWidth(100))
	_, _, err := calculateWidths(tb)
	assertErrorCode(t, err, ErrInvalidConfig)
}

func TestCalculateWidths_ValidateErrorPropagation(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidth(10), ColFixWidthPercent(50))
	_, _, err := calculateWidths(tb)
	assertErrorCode(t, err, ErrBothFixWidthAndPercent)
}

func TestCalculateWidths_UsableWidthTooSmall(t *testing.T) {
	tb := New(WithWidth(5))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddColumn("D")
	_, _, err := calculateWidths(tb)
	assertErrorCode(t, err, ErrInvalidConfig)
}

func TestCalculateWidths_RemainingUsableTooSmall(t *testing.T) {
	tb := New(WithWidth(30), WithCompact(true))
	tb.AddColumn("A", ColFixWidth(20))
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddColumn("D")
	tb.AddColumn("E")
	tb.AddColumn("F")
	_, _, err := calculateWidths(tb)
	assertErrorCode(t, err, ErrInvalidConfig)
}

func TestCalculateWidths_AutoDetect(t *testing.T) {
	t.Run("alone", func(t *testing.T) {
		tb := New(WithAutoDetect())
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		tb.AddRow("hello")
		widths, ew, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if ew <= 0 {
			t.Errorf("effectiveWidth = %d, want > 0", ew)
		}
		if len(widths) != 1 {
			t.Fatalf("len(widths) = %d, want 1", len(widths))
		}
	})
	t.Run("with MaxWidth", func(t *testing.T) {
		tb := New(WithAutoDetect(), WithMaxWidth(40))
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		tb.AddRow("hello")
		_, ew, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if ew > 40 {
			t.Errorf("effectiveWidth = %d, want <= 40", ew)
		}
	})
	t.Run("with MinWidth", func(t *testing.T) {
		tb := New(WithAutoDetect(), WithMinWidth(200))
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		tb.AddRow("hello")
		_, ew, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if ew < 200 {
			t.Errorf("effectiveWidth = %d, want >= 200", ew)
		}
	})
}

func TestCalculateWidths_MinMaxClamping(t *testing.T) {
	t.Run("FixWidth < MinWidth on flexible", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColMinWidth(20))
		tb.AddRow("x")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] < 20 {
			t.Errorf("width = %d, want >= 20", widths[0])
		}
	})
}

func TestCalculateWidths_InfiniteMode(t *testing.T) {
	t.Run("fixed cols", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A", ColFixWidth(15))
		tb.AddRow("hello")
		widths, ew, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if ew != 0 {
			t.Errorf("effectiveWidth = %d, want 0", ew)
		}
		if widths[0] != 15 {
			t.Errorf("width = %d, want 15", widths[0])
		}
	})
	t.Run("flexible cols", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		tb.AddRow("hello")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] < 1 {
			t.Errorf("width = %d, want >= 1", widths[0])
		}
	})
	t.Run("clamp to min", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A", ColMinWidth(20))
		tb.AddRow("x")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] < 20 {
			t.Errorf("width = %d, want >= 20", widths[0])
		}
	})
	t.Run("clamp to max", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A", ColMaxWidth(3))
		tb.AddRow("hello world this is very long")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] > 3 {
			t.Errorf("width = %d, want <= 3", widths[0])
		}
	})
	t.Run("width<1 clamped", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] < 1 {
			t.Errorf("width = %d, want >= 1", widths[0])
		}
	})
}

func TestCalculateWidths_AllFixedColumns(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidth(20))
	tb.AddColumn("B", ColFixWidth(30))
	widths, ew, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ew != 100 {
		t.Errorf("effectiveWidth = %d, want 100", ew)
	}
	if widths[0] != 20 || widths[1] != 30 {
		t.Errorf("widths = %v, want [20 30]", widths)
	}
}

func TestCalculateWidths_FixWidthPercent(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidthPercent(50))
	tb.AddColumn("B")
	tb.AddRow("hello", "world")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] != 46 {
		t.Errorf("width[0] = %d, want 46", widths[0])
	}
}

func TestCalculateWidths_TruncateAfterNaturalWidth(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColTruncateAfter(5))
	tb.AddRow("abcdefghijklmnopqrstuvwxyz")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] > 96 {
		t.Errorf("width[0] = %d, expected reasonable size", widths[0])
	}
}

func TestCalculateWidths_HeadersWiderThanContent(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A")
	tb.SetHeaders("VeryLongHeaderName")
	tb.AddRow("x")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] < len("VeryLongHeaderName") {
		t.Logf("width = %d, header len = %d", widths[0], len("VeryLongHeaderName"))
	}
}

func TestCalculateWidths_RowShorterThanColumns(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddRow("only one")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(widths) != 3 {
		t.Errorf("len(widths) = %d, want 3", len(widths))
	}
	for _, w := range widths {
		if w < 1 {
			t.Errorf("width < 1: %d", w)
		}
	}
}

func TestCalculateWidths_SurplusEven(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddRow("a", "b")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(2, false)
	if total+overhead != 100 {
		t.Errorf("total+overhead = %d, want 100", total+overhead)
	}
}

func TestCalculateWidths_SurplusRemainder(t *testing.T) {
	tb := New(WithWidth(101))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddRow("a", "b")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(2, false)
	if total+overhead != 101 {
		t.Errorf("total+overhead = %d, want 101", total+overhead)
	}
}

func TestCalculateWidths_SurplusMaxCap(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColMaxWidth(10))
	tb.AddColumn("B")
	tb.AddRow("x", "y")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] > 10 {
		t.Errorf("width[0] = %d, want <= 10", widths[0])
	}
}

func TestCalculateWidths_SurplusResidualLoop(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColMaxWidth(5))
	tb.AddColumn("B", ColMaxWidth(5))
	tb.AddColumn("C")
	tb.AddRow("x", "y", "z")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] > 5 {
		t.Errorf("width[0] = %d, want <= 5", widths[0])
	}
	if widths[1] > 5 {
		t.Errorf("width[1] = %d, want <= 5", widths[1])
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(3, false)
	if total+overhead != 100 {
		t.Errorf("total+overhead = %d, want 100", total+overhead)
	}
}

func TestCalculateWidths_SurplusAllMaxed(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColMaxWidth(5))
	tb.AddColumn("B", ColMaxWidth(5))
	tb.AddRow("x", "y")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] > 5 || widths[1] > 5 {
		t.Errorf("widths = %v, want both <= 5", widths)
	}
}

func TestCalculateWidths_ShrinkProportional(t *testing.T) {
	tb := New(WithWidth(40))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddRow("abcdefghijklmnopqrstuvwxyz", "12345678901234567890")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] <= 0 || widths[1] <= 0 {
		t.Errorf("widths = %v, want both > 0", widths)
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(2, false)
	if total+overhead != 40 {
		t.Errorf("total+overhead = %d, want 40", total+overhead)
	}
}

func TestCalculateWidths_ShrinkDeficitPositive(t *testing.T) {
	tb := New(WithWidth(50))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddRow("abcdefghijklmnopqrstuvwxyz", "1234567890123456789", "abcdef")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(3, false)
	if total+overhead != 50 {
		t.Errorf("total+overhead = %d, want 50", total+overhead)
	}
}

func TestCalculateWidths_ShrinkDeficitNegative(t *testing.T) {
	tb := New(WithWidth(30))
	tb.AddColumn("A", ColMinWidth(10))
	tb.AddColumn("B", ColMinWidth(10))
	tb.AddRow("abcdefghijklmnopqrstuvwxyz", "12345678901234567890")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] < 10 || widths[1] < 10 {
		t.Errorf("widths = %v, want both >= 10", widths)
	}
}

func TestCalculateWidths_ShrinkDeficitZero(t *testing.T) {
	tb := New(WithWidth(40))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddRow("abcdefghijklmnop", "abcdefghijklmnop")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	overhead := calculateOverhead(2, false)
	if total+overhead > 40 {
		t.Errorf("total+overhead = %d, want <= 40", total+overhead)
	}
}

func TestCalculateWidths_ShrinkDeficitMaxPreventsIncrement(t *testing.T) {
	tb := New(WithWidth(50))
	tb.AddColumn("A", ColMaxWidth(5))
	tb.AddColumn("B")
	tb.AddRow("abcdefghijklmnopqrstuvwxyz", "12345678901234567890abcdef")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] > 5 {
		t.Errorf("width[0] = %d, want <= 5", widths[0])
	}
}

func TestCalculateWidths_ShrinkDeficitMinPreventsDecrement(t *testing.T) {
	tb := New(WithWidth(30))
	tb.AddColumn("A", ColMinWidth(15))
	tb.AddColumn("B")
	tb.AddRow("abcdefghijklmnopqrstuvwxyz", "12345678901234567890")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if widths[0] < 15 {
		t.Errorf("width[0] = %d, want >= 15", widths[0])
	}
}

func TestCalculateWidths_MultilineNaturalWidth(t *testing.T) {
	t.Run("multiline cell uses longest line not total", func(t *testing.T) {
		// A multi-line cell with short lines should not inflate the natural width.
		// Before the fix, "line1\nline2\nline3" measured as ~17 instead of 5.
		tb := New(WithWidth(80))
		tb.AddColumn("SHORT")
		tb.AddColumn("MULTI")
		tb.AddColumn("OTHER")
		tb.AddRow("hello world here", "line1\nline2\nline3", "some other text!")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// SHORT has natural width 16, MULTI should have natural width 5, OTHER 15.
		// With the bug, MULTI would be ~17 and steal space from SHORT and OTHER.
		if widths[1] >= widths[0] {
			t.Errorf("MULTI width (%d) >= SHORT width (%d); multiline natural width is inflated", widths[1], widths[0])
		}
	})

	t.Run("proportional squeeze not triggered by multiline", func(t *testing.T) {
		// Simulate the real bug: a relations column with many short lines.
		// Total string is long but each line is short.
		multiline := "Chain: Root -> Intermediate\n" +
			"  Signed by: Root CA\n" +
			"  Signs: Leaf cert"
		singleLine := "CN=My Very Long Certificate Filename That Should Not Be Wrapped.pem"

		tb := New(WithWidth(120))
		tb.AddColumn("FILENAME")
		tb.AddColumn("RELATIONS")
		tb.AddRow(singleLine, multiline)
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// FILENAME (68 chars) should get more space than RELATIONS (longest line ~28).
		// With the bug, RELATIONS total string (~67) would get roughly equal share.
		if widths[0] < widths[1] {
			t.Errorf("FILENAME width (%d) < RELATIONS width (%d); multiline inflated natural width", widths[0], widths[1])
		}
	})

	t.Run("single line cell unchanged", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A")
		tb.AddRow("hello world")
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if widths[0] < len("hello world") {
			t.Errorf("width = %d, want >= %d for single-line content", widths[0], len("hello world"))
		}
	})
}

func TestCalculateWidths_SmallColumnGetsNaturalWidth(t *testing.T) {
	t.Run("small column not squeezed below natural width", func(t *testing.T) {
		// When total natural widths exceed available space, columns whose
		// natural width fits within a fair share should still get their
		// full natural width. Only oversized columns should be squeezed.
		// This models the real scenario: RELATIONS column with "cert(#2 this file)"
		// (18 chars) alongside much wider FILENAME/SUBJECT/ISSUER columns.
		tb := New(WithWidth(120))
		tb.AddColumn("FILENAME")
		tb.AddColumn("SUBJECT")
		tb.AddColumn("ISSUER")
		tb.AddColumn("RELATIONS", ColMaxWidth(40))
		tb.AddRow(
			"very-long-certificate-filename-here.pem",                  // 39 chars
			"CN=Some Organization Certificate Authority Extended Name", // 56 chars
			"CN=Root CA Organization Trust Services Extended",          // 47 chars
			"cert(#2 this file)",                                       // 18 chars
		)
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// RELATIONS natural width is 18. It should not be squeezed below that.
		if widths[3] < 18 {
			t.Errorf("RELATIONS width (%d) < natural width 18; small column got squeezed", widths[3])
		}
	})

	t.Run("multiple small columns preserved", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("BIG")
		tb.AddColumn("SMALL1")
		tb.AddColumn("SMALL2")
		tb.SetHeaders("BIG", "SMALL1", "SMALL2")
		tb.AddRow(
			"this is a very long content string that clearly exceeds the available space by a lot", // 84 chars
			"short", // 5 chars
			"tiny",  // 4 chars
		)
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// Natural widths: BIG=84, SMALL1=max(6,5)=6, SMALL2=max(6,4)=6
		if widths[1] < 6 {
			t.Errorf("SMALL1 width (%d) < natural width 6; small column got squeezed", widths[1])
		}
		if widths[2] < 6 {
			t.Errorf("SMALL2 width (%d) < natural width 6; small column got squeezed", widths[2])
		}
	})

	t.Run("total still fills table width", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("BIG")
		tb.AddColumn("SMALL")
		tb.AddRow(
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", // 62 chars
			"hello", // 5 chars
		)
		widths, _, err := calculateWidths(tb)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		total := 0
		for _, w := range widths {
			total += w
		}
		overhead := calculateOverhead(2, false)
		if total+overhead != 100 {
			t.Errorf("total+overhead = %d, want 100", total+overhead)
		}
	})
}

func TestCalculateWidths_FinalMinEnforcement(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A")
	tb.AddColumn("B")
	tb.AddColumn("C")
	tb.AddRow("a", "b", "c")
	widths, _, err := calculateWidths(tb)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	for i, w := range widths {
		if w < 1 {
			t.Errorf("width[%d] = %d, want >= 1", i, w)
		}
	}
}
