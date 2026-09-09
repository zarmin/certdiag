package tableformat

import "testing"

func TestTableOptions(t *testing.T) {
	tests := []struct {
		name  string
		opt   TableOption
		check func(*Table) bool
	}{
		{"WithAutoDetect", WithAutoDetect(), func(tb *Table) bool { return tb.Options.AutoDetect }},
		{"WithWidth", WithWidth(120), func(tb *Table) bool { return tb.Options.FixWidth == 120 && !tb.Options.AutoDetect }},
		{"WithMinWidth", WithMinWidth(40), func(tb *Table) bool { return tb.Options.MinWidth == 40 }},
		{"WithMaxWidth", WithMaxWidth(200), func(tb *Table) bool { return tb.Options.MaxWidth == 200 }},
		{"WithAllowLinebreaks true", WithAllowLinebreaks(true), func(tb *Table) bool { return tb.Options.AllowLinebreaks }},
		{"WithAllowLinebreaks false", WithAllowLinebreaks(false), func(tb *Table) bool { return !tb.Options.AllowLinebreaks }},
		{"WithWhitespaceWrap", WithWhitespaceWrap(false), func(tb *Table) bool { return !tb.Options.WhitespaceWrap }},
		{"WithCompact", WithCompact(true), func(tb *Table) bool { return tb.Options.Compact }},
		{"WithDisplayHeaders", WithDisplayHeaders(false), func(tb *Table) bool { return !tb.Options.DisplayHeaders }},
		{"WithRowSeparators", WithRowSeparators(true), func(tb *Table) bool { return tb.Options.RowSeparators }},
		{"WithDefaultAlignment", WithDefaultAlignment(AlignCenter), func(tb *Table) bool { return tb.Options.DefaultAlignment == AlignCenter }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb := New(tt.opt)
			if !tt.check(tb) {
				t.Errorf("option %s did not set correctly", tt.name)
			}
		})
	}
}

func TestColOptions(t *testing.T) {
	tests := []struct {
		name  string
		opt   ColOption
		check func(*ColumnConfig) bool
	}{
		{"ColFixWidth", ColFixWidth(20), func(c *ColumnConfig) bool { return c.FixWidth == 20 }},
		{"ColFixWidthPercent", ColFixWidthPercent(25.5), func(c *ColumnConfig) bool { return c.FixWidthPercent == 25.5 }},
		{"ColMinWidth", ColMinWidth(5), func(c *ColumnConfig) bool { return c.MinWidth == 5 }},
		{"ColMaxWidth", ColMaxWidth(50), func(c *ColumnConfig) bool { return c.MaxWidth == 50 }},
		{"ColTruncateAfter", ColTruncateAfter(100), func(c *ColumnConfig) bool { return c.TruncateAfter == 100 }},
		{"ColNoWrap", ColNoWrap(), func(c *ColumnConfig) bool { return c.NoWrap }},
		{"ColAlign", ColAlign(AlignRight), func(c *ColumnConfig) bool { return c.Alignment == AlignRight && c.HasAlignment }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			col := &ColumnConfig{}
			tt.opt(col)
			if !tt.check(col) {
				t.Errorf("option %s did not set correctly", tt.name)
			}
		})
	}
}
