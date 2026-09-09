package tableformat

import "testing"

func assertErrorCode(t *testing.T, err error, wantCode TableErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %d, got nil", wantCode)
	}
	te, ok := err.(*TableError)
	if !ok {
		t.Fatalf("expected *TableError, got %T", err)
	}
	if te.Code != wantCode {
		t.Errorf("error code = %d, want %d", te.Code, wantCode)
	}
}

func TestValidate_AutoDetectWithFixWidth(t *testing.T) {
	tb := New(WithAutoDetect(), WithWidth(100))
	tb.Options.AutoDetect = true
	tb.AddColumn("A")
	err := validate(tb)
	assertErrorCode(t, err, ErrAutoDetectWithFixWidth)
}

func TestValidate_MaxLessThanMin(t *testing.T) {
	t.Run("MaxWidth < MinWidth", func(t *testing.T) {
		tb := New(WithWidth(100), WithMinWidth(50), WithMaxWidth(30))
		tb.AddColumn("A")
		err := validate(tb)
		assertErrorCode(t, err, ErrMaxLessThanMin)
	})
	t.Run("MaxWidth=0 no error", func(t *testing.T) {
		tb := New(WithWidth(100), WithMinWidth(50))
		tb.AddColumn("A")
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("MinWidth=0 no error", func(t *testing.T) {
		tb := New(WithWidth(100), WithMaxWidth(200))
		tb.AddColumn("A")
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidate_BothFixWidthAndPercent(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidth(20), ColFixWidthPercent(30))
	err := validate(tb)
	assertErrorCode(t, err, ErrBothFixWidthAndPercent)
}

func TestValidate_BothFixWidthAndMinMax(t *testing.T) {
	t.Run("MinWidth only", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidth(20), ColMinWidth(5))
		assertErrorCode(t, validate(tb), ErrBothFixWidthAndMinMax)
	})
	t.Run("MaxWidth only", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidth(20), ColMaxWidth(50))
		assertErrorCode(t, validate(tb), ErrBothFixWidthAndMinMax)
	})
	t.Run("both", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidth(20), ColMinWidth(5), ColMaxWidth(50))
		assertErrorCode(t, validate(tb), ErrBothFixWidthAndMinMax)
	})
}

func TestValidate_EffectiveMaxLessThanMin(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A", ColFixWidthPercent(5), ColMinWidth(50), ColMaxWidth(3))
	err := validate(tb)
	assertErrorCode(t, err, ErrEffectiveMaxLessThanMin)
}

func TestValidate_FixedWidthExceedsTable(t *testing.T) {
	t.Run("exceeds", func(t *testing.T) {
		tb := New(WithWidth(20))
		tb.AddColumn("A", ColFixWidth(10))
		tb.AddColumn("B", ColFixWidth(10))
		err := validate(tb)
		assertErrorCode(t, err, ErrFixedWidthExceedsTable)
	})
	t.Run("effectiveWidth=0 no error", func(t *testing.T) {
		tb := New()
		tb.Options.FixWidth = 0
		tb.AddColumn("A", ColFixWidth(100))
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidate_ColumnWidthTooSmall(t *testing.T) {
	t.Run("FixWidth < MinWidth", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidth(2), ColMinWidth(5))
		assertErrorCode(t, validate(tb), ErrBothFixWidthAndMinMax)
	})
	t.Run("FixWidth < 1 implicit min", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.Columns = append(tb.Columns, ColumnConfig{Name: "A", FixWidth: 0})
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestValidate_ValidConfig(t *testing.T) {
	tb := New(WithWidth(100))
	tb.AddColumn("A")
	tb.AddColumn("B", ColMaxWidth(30))
	tb.AddRow("hello", "world")
	if err := validate(tb); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_PercentWithMinMax(t *testing.T) {
	t.Run("MinWidth only", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidthPercent(20), ColMinWidth(5))
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("MaxWidth only", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidthPercent(20), ColMaxWidth(50))
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	t.Run("both", func(t *testing.T) {
		tb := New(WithWidth(100))
		tb.AddColumn("A", ColFixWidthPercent(20), ColMinWidth(5), ColMaxWidth(50))
		if err := validate(tb); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
